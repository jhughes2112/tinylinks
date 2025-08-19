using Logging;
using Shared;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Authentication
{
	// Allow logins for Discord users (OAuth2 only, no OIDC)
	public class AuthenticationDiscord : IAuthentication
	{
		private readonly string   _clientId;
		private readonly string   _clientSecret;
		private readonly ILogging _logger;

		private const string kAuthEndpoint  = "https://discord.com/api/oauth2/authorize";
		private const string kTokenEndpoint = "https://discord.com/api/oauth2/token";
		private const string kUserInfoUri   = "https://discord.com/api/users/@me";

		// OAuth state (short TTL)
		private const int    kStateTtlSeconds = 9;
		private const string kStateCookieName = "discord_state";

		private sealed class OAuthStateEntry
		{
			public string   CodeVerifier { get; }
			public DateTime CreatedUtc   { get; }
			public string?  LinkCode     { get; }
			public OAuthStateEntry(string codeVerifier, DateTime createdUtc, string? linkCode)
			{
				CodeVerifier = codeVerifier;
				CreatedUtc   = createdUtc;
				LinkCode     = linkCode;
			}
		}

		private readonly ThreadSafeDictionary<string, OAuthStateEntry> _states = new ThreadSafeDictionary<string, OAuthStateEntry>();

		public AuthenticationDiscord(string clientId, string clientSecret, ILogging logger)
		{
			_clientId     = clientId;
			_clientSecret = clientSecret;
			_logger       = logger;
			if (string.IsNullOrWhiteSpace(_clientId) || string.IsNullOrWhiteSpace(_clientSecret))
			{
				throw new ArgumentException("Discord auth missing client credentials");
			}
		}

		public string Provider => "discord";

		public void Tick()
		{
			// expire old auth states
			if (_states.Count > 0)
			{
				List<string> expired = new List<string>();
				DateTime now = DateTime.UtcNow;
				_states.Foreach((k, v) =>
				{
					if ((now - v.CreatedUtc).TotalSeconds > kStateTtlSeconds)
					{
						expired.Add(k);
					}
				});
				for (int i = 0; i < expired.Count; i++)
				{
					_states.Remove(expired[i]);
				}
			}
		}

		// Begin OAuth: set state cookie, stash verifier, return authorize URL as text/plain
		public Task<(int, string, byte[])> StartAuthenticate(Uri baseUri, HttpListenerContext httpContext)
		{
			try
			{
				string state = UrlHelper.GenerateRandomDataBase64url(32);
				httpContext.Response.Headers.Add("Set-Cookie", $"{kStateCookieName}={state}; Max-Age={kStateTtlSeconds}; Path=/; HttpOnly");

				string codeVerifier = UrlHelper.GenerateRandomDataBase64url(64);
				byte[] bytes = Encoding.ASCII.GetBytes(codeVerifier);
				byte[] hash = SHA256.HashData(bytes);
				string codeChallenge = UrlHelper.Base64UrlEncodeNoPadding(hash);

				string callbackUrl = new Uri(baseUri, "/api/oauth/callback").AbsoluteUri;
				string? linkCode = httpContext.Request.QueryString["linkcode"];
				_states.AddOrUpdate(state, new OAuthStateEntry(codeVerifier, DateTime.UtcNow, linkCode));

				// Discord scopes: identify email (space-separated)
				string scopes = "identify email";
				string url = string.Format(
					"{0}?response_type=code&client_id={1}&redirect_uri={2}&scope={3}&state={4}&code_challenge={5}&code_challenge_method=S256",
					kAuthEndpoint,
					Uri.EscapeDataString(_clientId),
					Uri.EscapeDataString(callbackUrl),
					Uri.EscapeDataString(scopes),
					Uri.EscapeDataString(state),
					Uri.EscapeDataString(codeChallenge)
				);

				return Task.FromResult((200, "text/plain", Encoding.UTF8.GetBytes(url)));
			}
			catch
			{
				return Task.FromResult((401, "text/plain", Encoding.UTF8.GetBytes("Cookie set failed")));
			}
		}

		// Check state cookie matches query
		public bool IsThisYours(HttpListenerContext httpContext)
		{
			bool isMine = false;
			string? state = httpContext.Request.QueryString["state"];
			string? cookieHeader = httpContext.Request.Headers["Cookie"];
			if (!string.IsNullOrWhiteSpace(state) && !string.IsNullOrWhiteSpace(cookieHeader))
			{
				string? stateCookie = UrlHelper.ExtractCookie(cookieHeader, kStateCookieName);
				isMine = !string.IsNullOrWhiteSpace(stateCookie) && string.Equals(stateCookie, state, StringComparison.Ordinal);
			}
			return isMine;
		}

		// Complete flow: exchange code for access_token, fetch /users/@me, return identity
		public async Task<(string?, string?, string?, string[]?, string?)> AuthenticateCallback(Uri baseUri, HttpListenerContext httpContext)
		{
			string? state = httpContext.Request.QueryString["state"];
			if (string.IsNullOrWhiteSpace(state))
			{
				return (null, null, null, null, null);
			}

			if (_states.TryRemove(state, out OAuthStateEntry entry) == false)
			{
				return (null, null, null, null, null);
			}

			try
			{
				// wipe cookie
				httpContext.Response.Headers.Add("Set-Cookie", $"{kStateCookieName}=; Max-Age=0; Path=/");

				string? code = httpContext.Request.QueryString["code"];
				if (string.IsNullOrWhiteSpace(code))
				{
					return (null, null, null, null, null);
				}

				string callbackUrl = new Uri(baseUri, "/api/oauth/callback").AbsoluteUri;
				// Exchange code for access token
				DiscordTokenResponse? token = await ExchangeCodeForAccessTokenAsync(code!, callbackUrl, entry.CodeVerifier).ConfigureAwait(false);
				if (token == null || string.IsNullOrWhiteSpace(token.access_token))
				{
					return (null, null, null, null, null);
				}

				// Fetch user info
				DiscordUserResponse? user = await GetUserAsync(token.access_token!).ConfigureAwait(false);
				if (user == null || string.IsNullOrWhiteSpace(user.id))
				{
					return (null, null, null, null, null);
				}

				string sub = user.id!;
				string? fullName = string.IsNullOrWhiteSpace(user.global_name) ? user.username : user.global_name;
				string? email = user.email; // only present with email scope and if verified
				string[] roles = Array.Empty<string>();
				return (sub, fullName, email, roles, entry.LinkCode);
			}
			catch (Exception ex)
			{
				_logger.Log(EVerbosity.Error, $"Discord auth failed: {ex}");
				return (null, null, null, null, null);
			}
		}

		private async Task<DiscordTokenResponse?> ExchangeCodeForAccessTokenAsync(string code, string redirectUri, string codeVerifier)
		{
			using (HttpClient httpClient = new HttpClient())
			{
				Dictionary<string, string> postData = new Dictionary<string, string>();
				postData["client_id"] = _clientId;
				postData["client_secret"] = _clientSecret;
				postData["grant_type"] = "authorization_code";
				postData["code"] = code;
				postData["redirect_uri"] = redirectUri;
				postData["code_verifier"] = codeVerifier;
				FormUrlEncodedContent content = new FormUrlEncodedContent(postData);
				HttpResponseMessage resp = await httpClient.PostAsync(kTokenEndpoint, content).ConfigureAwait(false);
				if (resp.IsSuccessStatusCode)
				{
					string body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
					try
					{
						DiscordTokenResponse? tr = JsonSerializer.Deserialize<DiscordTokenResponse>(body);
						return tr;
					}
					catch (Exception e)
					{
						_logger.Log(EVerbosity.Error, $"Discord token parse failed: {e}");
					}
				}
				else
				{
					_logger.Log(EVerbosity.Warning, $"Discord token exchange failed: {(int)resp.StatusCode} {resp.ReasonPhrase}");
				}
			}
			return null;
		}

		private async Task<DiscordUserResponse?> GetUserAsync(string accessToken)
		{
			using (HttpClient httpClient = new HttpClient())
			{
				httpClient.DefaultRequestHeaders.Add("Authorization", "Bearer " + accessToken);
				HttpResponseMessage resp = await httpClient.GetAsync(kUserInfoUri).ConfigureAwait(false);
				if (resp.IsSuccessStatusCode)
				{
					string body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
					try
					{
						DiscordUserResponse? ur = JsonSerializer.Deserialize<DiscordUserResponse>(body);
						return ur;
					}
					catch (Exception e)
					{
						_logger.Log(EVerbosity.Error, $"Discord user parse failed: {e}");
					}
				}
				else
				{
					_logger.Log(EVerbosity.Warning, $"Discord userinfo failed: {(int)resp.StatusCode} {resp.ReasonPhrase}");
				}
			}
			return null;
		}

		private sealed class DiscordTokenResponse
		{
			public string? access_token { get; set; }
			public string? token_type   { get; set; }
			public int     expires_in   { get; set; }
			public string? refresh_token{ get; set; }
			public string? scope        { get; set; }
		}

		private sealed class DiscordUserResponse
		{
			public string? id           { get; set; }
			public string? username     { get; set; }
			public string? global_name  { get; set; }
			public string? email        { get; set; }
			public bool     verified     { get; set; }
		}
	}
}
