using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Logging;
using System.Text.Json;
using Shared;
using System.Net.Http;
using System.Threading.Tasks;
using System.Net;

namespace Authentication
{
	// This handles the OAuth2 server-flow for standard JWT-based authentication servers.
	public class AuthenticationOAuth2 : IAuthentication
	{
		private readonly Dictionary<string, RSA> _publicKeys;
		private readonly ILogging                _logger;

		// OIDC / OAuth2 provider metadata
		public string Provider { get; private set; } = string.Empty;
		private readonly string _authorizationEndpoint;
		private readonly string _tokenEndpoint;
		private readonly string _clientId;
		private readonly string _clientSecret;

		// OAuth state (short TTL)
		private const    int    kOAuthStateTtlSeconds = 9; // 9 seconds to complete your login right now, will adjust it up in a bit
		private const    string kOAuthStateCookieName = "oauth_state";
		
		// When someone tries to authenticate, we stash some info in this object so it can be used when they finish the authentication flow and want to continue.
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

		private readonly ThreadSafeDictionary<string, OAuthStateEntry> _oauthStates = new ThreadSafeDictionary<string, OAuthStateEntry>();

		public AuthenticationOAuth2(string provider, string authorizationEndpoint, string tokenEndpoint, string clientId, string clientSecret, Dictionary<string, RSA> publicKeys, ILogging logger)
		{
			Provider = provider;
			_authorizationEndpoint = authorizationEndpoint;
			_tokenEndpoint = tokenEndpoint;
			_clientId = clientId;
			_clientSecret = clientSecret;
			_publicKeys = publicKeys;
			_logger = logger;

			if (string.IsNullOrEmpty(Provider) || string.IsNullOrEmpty(_authorizationEndpoint) || string.IsNullOrEmpty(_tokenEndpoint) || string.IsNullOrEmpty(_clientId) || string.IsNullOrEmpty(clientSecret) || publicKeys.Count==0)
				throw new InvalidOperationException("AuthenticationOAuth2 has nulls.");
		}

		public void Tick()
		{
			// expire old auth states
			if (_oauthStates.Count > 0)
			{
				List<string> expired = new List<string>();
				DateTime now = DateTime.UtcNow;
				_oauthStates.Foreach((k, v) =>
				{
					if ((now - v.CreatedUtc).TotalSeconds > kOAuthStateTtlSeconds)
					{
						expired.Add(k);
					}
				});
				foreach (string k in expired)
				{
					_oauthStates.Remove(k);
				}
			}
		}

		// This is an OpenID handshake, and we stash most of the info in a dictionary by a random state value so we can retrieve it later.
		public Task<(int, string, byte[])> StartAuthenticate(Uri baseUri, HttpListenerContext httpContext)
		{
			try
			{
				string state = UrlHelper.GenerateRandomDataBase64url(32);
				httpContext.Response.Headers.Add("Set-Cookie", $"{kOAuthStateCookieName}={state}; Max-Age={kOAuthStateTtlSeconds}; Path=/; HttpOnly");

				string codeVerifier = UrlHelper.GenerateRandomDataBase64url(64);
				byte[] bytes = Encoding.ASCII.GetBytes(codeVerifier);
				byte[] hash = SHA256.HashData(bytes);
				String codeChallenge = UrlHelper.Base64UrlEncodeNoPadding(hash);

				string callbackUrl = new Uri(baseUri, "/api/oauth/callback").AbsoluteUri;
				string? linkCode = httpContext.Request.QueryString["linkcode"];
				_oauthStates.AddOrUpdate(state, new OAuthStateEntry(codeVerifier, DateTime.UtcNow, linkCode));

				string url = $"{_authorizationEndpoint}?response_type=code&scope=openid+profile+email&redirect_uri={Uri.EscapeDataString(callbackUrl)}&client_id={Uri.EscapeDataString(_clientId)}&state={Uri.EscapeDataString(state)}&code_challenge={Uri.EscapeDataString(codeChallenge)}&code_challenge_method=S256";
				return Task.FromResult((200, "text/plain", Encoding.UTF8.GetBytes(url)));
			}
			catch
			{
				return Task.FromResult((401, "text/plain", Encoding.UTF8.GetBytes("Cookie set failed")));
			}
		}

		// Just inspects the query and cookie headers to see if they match.
		public bool IsThisYours(HttpListenerContext httpContext)
		{
			bool isMine = false;
			string? state = httpContext.Request.QueryString["state"];
			string? cookieHeader = httpContext.Request.Headers["Cookie"];
			if (!string.IsNullOrWhiteSpace(state) && !string.IsNullOrWhiteSpace(cookieHeader))
			{
				string? stateCookie = UrlHelper.ExtractCookie(cookieHeader, kOAuthStateCookieName);
				isMine = !string.IsNullOrWhiteSpace(stateCookie) && string.Equals(stateCookie, state, StringComparison.Ordinal);
			}
			return isMine;
		}

		public async Task<(string?, string?, string?, string[]?, string?)> AuthenticateCallback(Uri baseUri, HttpListenerContext httpContext)
		{
			// We already verified this is the correct state and it's ours.
			string state = httpContext.Request.QueryString["state"]!;
			if (_oauthStates.TryRemove(state, out OAuthStateEntry entry))
			{
				// wipe out that cookie
				try
				{
					httpContext.Response.Headers.Add("Set-Cookie", $"{kOAuthStateCookieName}=; Max-Age=0; Path=/");

					string? code = httpContext.Request.QueryString["code"];
					if (string.IsNullOrWhiteSpace(code)==false)
					{
						// fetch the JWT from the remote server
						string callbackUrl = new Uri(baseUri, "/api/oauth/callback").AbsoluteUri;
						string? id_token = await ExchangeCodeForJwtAsync(code!, callbackUrl, entry.CodeVerifier).ConfigureAwait(false);
						if (string.IsNullOrEmpty(id_token)==false)
						{
							// crack the JWT into the important parts
							(string? sub, string? fullName, string? email, string[]? roles) = Authenticate(id_token);
							return (sub, fullName, email, roles, entry.LinkCode);
						}
					}
				}
				catch {}
			}
			return (null, null, null, null, null);
		}

		// authstring is a JWT that is cracked into parts.  If it's invalid, accountId is returned null.  Otherwise you get a valid accountId and non-null roles.
		// Full name and email may or may not be set, so be prepared to fall back to accountId to display something, but always trust accountId is a unique string.
		private (string?, string?, string?, string[]?) Authenticate(string? jwt)
		{
			string?   accountId = null;
			string?   fullName  = null;
			string?   email     = null;
			string[]? roles     = null;
			try
			{
				if (string.IsNullOrEmpty(jwt)==false)
				{
					// Split the JWT into its parts
					string[] parts = jwt.Split('.');
					if (parts.Length == 3)
					{
						string header = parts[0];
						string payload = parts[1];
						string signature = parts[2];

						// Decode the header and payload
						string decodedHeader = UrlHelper.Base64UrlDecode(header);
						string decodedPayload = UrlHelper.Base64UrlDecode(payload);

						JwtHeader? jwtheader = JsonSerializer.Deserialize<JwtHeader>(decodedHeader);
						JwtPayload? jwtpayload = JsonSerializer.Deserialize<JwtPayload>(decodedPayload);

						// Extract the 'kid' from the JWT header
						if (jwtheader!=null && jwtpayload!=null && jwtheader.kid!=null)
						{
							// Find the corresponding key
							if (_publicKeys.TryGetValue(jwtheader.kid, out RSA? rsa))
							{
								// Verify the signature
								string signedData = header + "." + payload;
								byte[] signedBytes = Encoding.UTF8.GetBytes(signedData);
								byte[] signatureBytes = UrlHelper.Base64UrlDecodeBytes(signature);

								if (rsa.VerifyData(signedBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
								{
									long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
									if (jwtpayload.exp > now)
									{
										string allGroups = jwtpayload.groups==null ? string.Empty : string.Join(' ', jwtpayload.groups);
										_logger.Log(EVerbosity.Info, $"Successful authentication for {jwtpayload.sub} {jwtpayload.email ?? "NO-EMAIL"} {allGroups}");
										accountId = jwtpayload.sub;
										fullName  = jwtpayload.name;
										email     = jwtpayload.email;
										roles     = jwtpayload.groups==null ? Array.Empty<string>() : jwtpayload.groups;
									}
									else
									{
										_logger.Log(EVerbosity.Error, $"JWT has expired now {now} JWT: {jwt}");
									}
								}
								else
								{
									_logger.Log(EVerbosity.Error, $"Invalid signature for JWT: {jwt}");
								}
							}
							else
							{
								_logger.Log(EVerbosity.Error, $"Public key not found for the given kid {jwt}");
							}
						}
						else
						{
							_logger.Log(EVerbosity.Error, $"JWT header does not contain kid {jwt}");
						}
					}
					else
					{
						_logger.Log(EVerbosity.Error, "Invalid JWT format");
					}
				}
				else
				{
					_logger.Log(EVerbosity.Error, "JWT is null or empty");
				}
			}
			catch (Exception ex)
			{
				_logger.Log(EVerbosity.Error, $"JWT Validation threw an exception {ex}");
			}

			return (accountId, fullName, email, roles);
		}

		// Exchange an authorization code for a JWT using the given code_verifier, returns the id_token which has three parts and most of the important details (accountId, full name, email, roles[]).
		private async Task<string?> ExchangeCodeForJwtAsync(string code, string redirectUri, string codeVerifier)
		{
			using (HttpClient httpClient = new HttpClient())
			{
				var postData = new Dictionary<string, string>
				{
					{ "code", code },
					{ "redirect_uri", redirectUri },
					{ "client_id", _clientId! },
					{ "code_verifier", codeVerifier },
					{ "grant_type", "authorization_code" },
				};
				if (!string.IsNullOrEmpty(_clientSecret))
				{
					postData.Add("client_secret", _clientSecret!);
				}
				var requestContent = new FormUrlEncodedContent(postData);
				HttpResponseMessage tokenResponse = await httpClient.PostAsync(_tokenEndpoint, requestContent).ConfigureAwait(false);
				if (tokenResponse.IsSuccessStatusCode)
				{
					string responseBody = await tokenResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
					try
					{
						JwtResponse? jwtResponse = JsonSerializer.Deserialize<JwtResponse>(responseBody);
						if (string.IsNullOrEmpty(jwtResponse?.id_token)==false)
						{
							return jwtResponse.id_token;  // the whole response is the JWT, which includes the access_token and id_token
						}
					}
					catch (Exception e)
					{
						_logger.Log(EVerbosity.Error, $"Token exchange JSON parse failed: {e}");
					}
				}
				else
				{
					_logger.Log(EVerbosity.Error, $"Token response status failed {tokenResponse.StatusCode}");
				}
			}
			return null;
		}

		protected class JwtHeader
		{
			public string? kid { get; set; }   // this indicates what public key was used for signing
		}

		protected class JwtPayload
		{
			public string?   iss           { get; set; }  // this is supposed to always be our fusionauth/authentik server, but authentik doesn't let you configure what it returns so we can't really use it
			public string?   aud           { get; set; }  // authentik: returns the clientid that authenticated this user.  "thisisaclientid" is what we are using currently
			public long      exp           { get; set; }  // this is the expiration time for the JWT
			public long      iat           { get; set; }  // this is the time this JWT was issued at
			public string?   sub           { get; set; }  // this is the userid
			public string?   email         { get; set; }  // this should be something we receive
			public bool      emailVerified { get; set; }  // if true, the email link was clicked
			public string?   name          { get; set; }  // Full name
			public string[]? groups        { get; set; }  // authentik
		}

		protected class JwtResponse
		{
			public string? access_token { get; set; }
			public int     expires_in   { get; set; }
			public string? id_token     { get; set; }
			public string? scope        { get; set; }
			public string? token_type   { get; set; }
			public string? userId       { get; set; }
		}
	}
}
