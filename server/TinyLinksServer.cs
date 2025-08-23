using DataCollection;
using Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using HeyRed.Mime;
using Shared; // ThreadSafeDictionary
using Authentication; // IAuthentication
using System.Text.Json;
using Utilities;
using Storage;
using System.Net.Sockets;
using System.Security.Cryptography; // Added for PKCE verification

namespace TinyLinks
{
	// handles authenticating each and every request, then routes the request to the appropriate handler based on the HTTP method and URL structure.
	public class TinyLinksServer
	{
		private List<string>                   _advertiseUrls;
		private string                         _staticRootFolder;
		private IDataCollection                _dataCollection;
		private ILogging                       _logger;
		private StorageFiles                   _linksStorage;
		private Task                           _updateThread                = Task.CompletedTask;
		private CancellationTokenSource        _cancellationTokenSrc;
		private CancellationTokenSource?       _cancellationTokenSrcUpdate;
		private readonly JwtSigner             _jwt = new JwtSigner();      // Server JWT signer (RS256) for downstream cookies and JWKS

		private readonly List<IAuthentication> _authProviders;
		private int                            _sessionDurationSeconds      = 3600; // 1 hour session cookie
		private string                         _linkcreateSecret;           // secret used to create link codes
		private const int                      kLinkCodeTtlSeconds          = 3600;
		private const string                   kDownstreamSessionCookieName = "tinylinks_session";
		// Rule override: removed downstream handshake cookie in favor of provider state flow

		// Metrics counters (created at startup)
		private const string kCounterLoginCalls          = "tl_login_calls";
		private const string kCounterLoginSuccess        = "tl_login_success";
		private const string kCounterLinkCreateCalls     = "tl_linkcreate_calls";
		private const string kCounterLinkCreateSuccess   = "tl_linkcreate_success";
		private const string kCounterUnlinkCalls         = "tl_unlink_calls";
		private const string kCounterUnlinkSuccess       = "tl_unlink_success";

		private sealed class CodeRecord 
		{ 
			public string   Sub     { get; } 
			public DateTime Expires { get; } 
			public CodeRecord(string sub, DateTime expires) 
			{ 
				Sub     = sub; 
				Expires = expires; 
			} 
		}

		// Authorization code record for downstream token exchange
		private sealed class AuthCodeRecord
		{
			public string   Token               { get; }
			public string   ClientId            { get; }
			public string   RedirectUri         { get; }
			public string?  CodeChallenge       { get; }
			public string?  CodeChallengeMethod { get; }
			public DateTime Expires             { get; }
			public AuthCodeRecord(string token, string clientId, string redirectUri, string? codeChallenge, string? codeChallengeMethod, DateTime expires)
			{
				Token = token;
				ClientId = clientId;
				RedirectUri = redirectUri;
				CodeChallenge = codeChallenge;
				CodeChallengeMethod = codeChallengeMethod;
				Expires = expires;
			}
		}

		// In-memory, storage for link codes that expire quickly
		private readonly ThreadSafeDictionary<string, CodeRecord>      _codes = new ThreadSafeDictionary<string, CodeRecord>();
		// In-memory, storage for downstream authorization codes
		private readonly ThreadSafeDictionary<string, AuthCodeRecord>  _authCodes = new ThreadSafeDictionary<string, AuthCodeRecord>();

		public TinyLinksServer(List<string> advertiseUrls, string staticRootFolder, IDataCollection dataCollection, ILogging logger, CancellationTokenSource tokenSrc, IEnumerable<IAuthentication> authentications, int sessionDurationSeconds, string linkcreateSecret, StorageFiles linksStorage)
		{
			_advertiseUrls           = advertiseUrls;
			_staticRootFolder        = staticRootFolder;
			_dataCollection          = dataCollection;
			_logger                  = logger;
			_cancellationTokenSrc    = tokenSrc;
			_authProviders           = new List<IAuthentication>(authentications);
			_sessionDurationSeconds  = sessionDurationSeconds;
			_linkcreateSecret        = linkcreateSecret;
			_linksStorage            = linksStorage;

			if (string.IsNullOrWhiteSpace(staticRootFolder) || string.IsNullOrWhiteSpace(_linkcreateSecret) || _authProviders.Count==0)
				throw new ArgumentException("TinyLinksStorage has missing, empty, or null configuration fields");

			_logger.Log(EVerbosity.Info, $"Server initializing.");

			// Metrics initialization
			_dataCollection.CreateCounter(kCounterLoginCalls,        "Total OAuth callback attempts");
			_dataCollection.CreateCounter(kCounterLoginSuccess,      "Successful OAuth logins");
			_dataCollection.CreateCounter(kCounterLinkCreateCalls,   "Total link create calls");
			_dataCollection.CreateCounter(kCounterLinkCreateSuccess, "Successful link create responses");
			_dataCollection.CreateCounter(kCounterUnlinkCalls,       "Total unlink calls");
			_dataCollection.CreateCounter(kCounterUnlinkSuccess,     "Successful unlink responses");

			// Pre-create provider success counters for configured providers
			for (int i = 0; i < _authProviders.Count; i++)
			{
				string prov = SanitizeMetricNamePart(_authProviders[i].Provider);
				string counterName = GetProviderSuccessCounterName(prov);
				_dataCollection.CreateCounter(counterName, "Successful logins per provider");
			}

			// Start running the update threads
			_cancellationTokenSrcUpdate = new CancellationTokenSource();
			_updateThread = Task.Run(async () => await Update(_cancellationTokenSrcUpdate.Token).ConfigureAwait(false));
		}

		public async Task Shutdown()
		{
			_logger.Log(EVerbosity.Info, "Server shutting down.");
            if (_cancellationTokenSrc.IsCancellationRequested==false)
			{
				_cancellationTokenSrc.Cancel();
			}
			
			if (_cancellationTokenSrcUpdate?.IsCancellationRequested==false)
			{
				_cancellationTokenSrcUpdate.Cancel();
			}
			await _updateThread.ConfigureAwait(false);
			
			_logger.Log(EVerbosity.Info, "Server shutdown complete.");
		}

		private async Task Update(CancellationToken token)
		{
			while (token.IsCancellationRequested==false)
			{
				_logger.Log(EVerbosity.Extreme, $"Server.Update loop");

				try
				{
					await Task.Delay(1000, token).ConfigureAwait(false);  // Once a second, wake up and see if anything needs to be done

					// Let the auth providers clean themselves over time
					foreach (IAuthentication auth in _authProviders)
					{
						auth.Tick();
					}

					// expire old link codes
					if (_codes.Count > 0)
					{
						List<string> expiredCodes = new List<string>();
						DateTime now2 = DateTime.UtcNow;
						_codes.Foreach((string k, CodeRecord v) =>
						{
							if (now2 > v.Expires)
							{
								expiredCodes.Add(k);
							}
						});
						for (int i=0; i<expiredCodes.Count; i++)
						{
							_codes.Remove(expiredCodes[i]);
						}
					}

					// expire old auth codes
					if (_authCodes.Count > 0)
					{
						List<string> expired = new List<string>();
						DateTime now3 = DateTime.UtcNow;
						_authCodes.Foreach((string k, AuthCodeRecord v) =>
						{
							if (now3 > v.Expires)
							{
								expired.Add(k);
							}
						});
						for (int i=0; i<expired.Count; i++)
						{
							_authCodes.Remove(expired[i]);
						}
					}
				}
				catch (OperationCanceledException)
				{
					// flow control
				}
			}
			_logger.Log(EVerbosity.Info, $"Server.Update exiting.");
		}

		private Uri? GetAdvertiseBaseForRequest(Uri originalRequest)
		{
			// Try to match it against one of the advertised urls, so we can use that to construct redirects and tokens
			Uri? result = null;
			string requestPath = originalRequest.AbsoluteUri;
			for (int i = 0; i < _advertiseUrls.Count; i++)
			{
				if (Uri.TryCreate(_advertiseUrls[i], UriKind.Absolute, out Uri? baseUri))
				{
					if (requestPath.StartsWith(baseUri.AbsoluteUri, StringComparison.OrdinalIgnoreCase))
					{
						result = baseUri;
						break;
					}
				}
			}
			return result;
		}

		private bool TryReadValidSession(string token, out Utilities.JwtPayload? payload)
		{
			bool result = true;
			payload = null;
			if (_jwt.TryValidate(token, out payload) == false || payload == null)
			{
				result = false;
			}
			else if (payload.HasExpired())
			{
				result = false;
			}
			return result;
		}

		private static string AppendTokenToUrl(string baseUrl, string token)
		{
			string sep = baseUrl.Contains("?") ? "&" : "?";
			string result = baseUrl + sep + "token=" + Uri.EscapeDataString(token);
			return result;
		}

		private static string AppendKeyValueToUrl(string baseUrl, string key, string value)
		{
			string sep = baseUrl.Contains("?") ? "&" : "?";
			string result = baseUrl + sep + key + "=" + Uri.EscapeDataString(value);
			return result;
		}

		private async Task<string?> TryGetOverrideSub(string sub)
		{
			byte[]? data = await _linksStorage.Read(sub).ConfigureAwait(false);
			if (data == null || data.Length == 0)
			{
				return null;
			}
			string text = Encoding.UTF8.GetString(data).Trim();
			if (string.IsNullOrWhiteSpace(text))
			{
				return null;
			}
			return text;
		}

		private Task<bool> SaveOverrideSub(string fromSub, string toSub)
		{
			byte[] bytes = Encoding.UTF8.GetBytes(toSub);
			return _linksStorage.Write(fromSub, bytes);
		}

		private static string SanitizeMetricNamePart(string name)
		{
			string result = string.Empty;
			if (!string.IsNullOrEmpty(name))
			{
				StringBuilder sb = new StringBuilder(name.Length);
				for (int i = 0; i < name.Length; i++)
				{
					char c = name[i];
					if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
					{
						sb.Append(c);
					}
					else if (c >= 'A' && c <= 'Z')
					{
						sb.Append((char)(c + 32));
					}
					else
					{
						sb.Append('_');
					}
				}
				result = sb.ToString();
			}
			return result;
		}

		private static string GetProviderSuccessCounterName(string providerSanitized)
		{
			return "tl_login_success_provider_" + providerSanitized;
		}

		// Add CORS headers for cross-origin requests
		private static void AddCors(HttpListenerRequest request, HttpListenerResponse response, string allowedMethods)
		{
			string? origin = request.Headers["Origin"];
			if (!string.IsNullOrEmpty(origin))
			{
				response.Headers["Access-Control-Allow-Origin"] = origin;
				response.Headers["Vary"] = "Origin";
				response.Headers["Access-Control-Allow-Credentials"] = "true";
				response.Headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
				response.Headers["Access-Control-Allow-Methods"] = allowedMethods;
				response.Headers["Access-Control-Max-Age"] = "600";
			}
		}

		// ---------------- OAuth endpoints ----------------
		public Task<(int, string, byte[])> OAuthUrl(HttpListenerContext http)
		{
			AddCors(http.Request, http.Response, "GET, OPTIONS");
			if (string.Equals(http.Request.HttpMethod, "OPTIONS", StringComparison.OrdinalIgnoreCase))
			{
				return Task.FromResult((204, "text/plain", Array.Empty<byte>()));
			}

			int statusCode = 200;
			string contentType = "text/plain";
			byte[] content = Array.Empty<byte>();

			// Figure out where the request was sent to by the client
			Uri originalRequestUri = UrlHelper.GetPublicUrl(http.Request);

			Uri? baseUri = GetAdvertiseBaseForRequest(originalRequestUri);
			if (baseUri != null)
			{
				if (string.Equals(http.Request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
				{
					// Parse downstream request params
					DownstreamAuthRequest ds = new DownstreamAuthRequest();
					ds.ResponseType = http.Request.QueryString["response_type"] ?? "code";
					ds.Scope = http.Request.QueryString["scope"];
					ds.RedirectUri = http.Request.QueryString["redirect_uri"];
					ds.ClientId = http.Request.QueryString["client_id"];
					ds.State = http.Request.QueryString["state"];
					ds.CodeChallenge = http.Request.QueryString["code_challenge"];
					ds.CodeChallengeMethod = http.Request.QueryString["code_challenge_method"];

					// Require redirect_uri for this flow
					if (string.IsNullOrWhiteSpace(ds.RedirectUri)==false)
					{
						// If we already have a valid downstream session cookie, short-circuit and redirect back to client
						string? cookieHeader = http.Request.Headers["Cookie"];
						string? jwt = UrlHelper.ExtractCookie(cookieHeader, kDownstreamSessionCookieName);
						Utilities.JwtPayload? payload;
						if (!string.IsNullOrWhiteSpace(jwt) && TryReadValidSession(jwt, out payload) && payload != null)
						{
							if (string.Equals(ds.ResponseType ?? "code", "code", StringComparison.OrdinalIgnoreCase))
							{
								string authCode = Guid.NewGuid().ToString().Split('-')[0];
								DateTime expires = DateTime.UtcNow.AddSeconds(300);
								_authCodes.AddOrUpdate(authCode, new AuthCodeRecord(
									jwt!,
									ds.ClientId ?? string.Empty,
									ds.RedirectUri!,
									ds.CodeChallenge,
									ds.CodeChallengeMethod,
									expires));

								string redirectUrl = AppendKeyValueToUrl(ds.RedirectUri!, "code", authCode);
								if (!string.IsNullOrWhiteSpace(ds.State))
								{
									redirectUrl = AppendKeyValueToUrl(redirectUrl, "state", ds.State!);
								}
								http.Response.RedirectLocation = redirectUrl;
								statusCode = 307;
								contentType = "text/plain";
								content = Encoding.UTF8.GetBytes("Redirecting");
							}
							else
							{
								string redirectWithToken = AppendTokenToUrl(ds.RedirectUri!, jwt!);
								if (!string.IsNullOrWhiteSpace(ds.State))
								{
									redirectWithToken = AppendKeyValueToUrl(redirectWithToken, "state", ds.State!);
								}
								http.Response.RedirectLocation = redirectWithToken;
								statusCode = 307;
								contentType = "text/plain";
								content = Encoding.UTF8.GetBytes("Redirecting");
							}
						}
						else
						{
							// No session; redirect to root for interactive provider selection, preserving original query string
							string root = baseUri.AbsoluteUri.TrimEnd('/') + "/";
							string qs = http.Request.Url != null ? http.Request.Url.Query : string.Empty;
							string target = root + (string.IsNullOrEmpty(qs) ? string.Empty : qs);
							http.Response.RedirectLocation = target;
							statusCode = 307;
							contentType = "text/plain";
							content = Encoding.UTF8.GetBytes("Redirecting");
						}
					}
					else
					{
						statusCode = 500; // Rule override: enforce redirect_uri presence at authorize time
						contentType = "text/plain";
						content = Encoding.UTF8.GetBytes("redirect_uri required");
					}
				}
				else
				{
					_logger.Log(EVerbosity.Warning, "OAuthUrl Method Not Allowed");
					statusCode = 405;
					contentType = "text/plain";
					content = Encoding.UTF8.GetBytes("Method Not Allowed");
				}
			}
			else
			{
				_logger.Log(EVerbosity.Warning, $"OAuthUrl unexpected source: {originalRequestUri.AbsoluteUri}");
				statusCode = 401;
				contentType = "text/plain";
				content = Encoding.UTF8.GetBytes($"Request from unexpected source does not match any AdvertiseURL: {originalRequestUri.AbsoluteUri}");
			}

			return Task.FromResult((statusCode, contentType, content));
		}

		// Starts the upstream provider flow using provider and downstream params (used by index.html)
		public async Task<(int, string, byte[])> OAuthUpstream(HttpListenerContext http)
		{
			AddCors(http.Request, http.Response, "GET, OPTIONS");
			if (string.Equals(http.Request.HttpMethod, "OPTIONS", StringComparison.OrdinalIgnoreCase))
			{
				return (204, "text/plain", Array.Empty<byte>());
			}

			int statusCode = 200;
			string contentType = "text/plain";
			byte[] content = Array.Empty<byte>();

			Uri originalRequestUri = UrlHelper.GetPublicUrl(http.Request);
			Uri? baseUri = GetAdvertiseBaseForRequest(originalRequestUri);
			if (baseUri != null)
			{
				if (string.Equals(http.Request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
				{
					DownstreamAuthRequest ds = new DownstreamAuthRequest();
					ds.ResponseType = http.Request.QueryString["response_type"] ?? "code";
					ds.Scope = http.Request.QueryString["scope"];
					ds.RedirectUri = http.Request.QueryString["redirect_uri"];
					ds.ClientId = http.Request.QueryString["client_id"];
					ds.State = http.Request.QueryString["state"];
					ds.CodeChallenge = http.Request.QueryString["code_challenge"];
					ds.CodeChallengeMethod = http.Request.QueryString["code_challenge_method"];

					string? provider = http.Request.QueryString["provider"];
					if (!string.IsNullOrWhiteSpace(provider))
					{
						IAuthentication? auth = _authProviders.Find(p => string.Equals(p.Provider, provider, StringComparison.OrdinalIgnoreCase));
						if (auth != null)
						{
							(statusCode, contentType, content) = await auth.StartAuthenticate(baseUri, http, ds).ConfigureAwait(false);
						}
						else
						{
							_logger.Log(EVerbosity.Warning, "OAuthUpstream Unknown provider");
							statusCode = 400;
							contentType = "text/plain";
							content = Encoding.UTF8.GetBytes("Unknown provider");
						}
					}
					else
					{
						_logger.Log(EVerbosity.Warning, "OAuthUpstream Missing provider");
						statusCode = 400;
						contentType = "text/plain";
						content = Encoding.UTF8.GetBytes("Missing provider");
					}
				}
				else
				{
					_logger.Log(EVerbosity.Warning, "OAuthUpstream Method Not Allowed");
					statusCode = 405;
					contentType = "text/plain";
					content = Encoding.UTF8.GetBytes("Method Not Allowed");
				}
			}
			else
			{
				_logger.Log(EVerbosity.Warning, $"OAuthUpstream unexpected source: {originalRequestUri.AbsoluteUri}");
				statusCode = 401;
				contentType = "text/plain";
				content = Encoding.UTF8.GetBytes($"Request from unexpected source does not match any AdvertiseURL: {originalRequestUri.AbsoluteUri}");
			}

			return (statusCode, contentType, content);
		}

		// On the callback, we ask grab the cookie and see what provider the state variable is associated with.  Then we dispatch to it.
		public async Task<(int, string, byte[])> OAuthCallback(HttpListenerContext http)
		{
			AddCors(http.Request, http.Response, "GET, OPTIONS");
			if (string.Equals(http.Request.HttpMethod, "OPTIONS", StringComparison.OrdinalIgnoreCase))
			{
				return (204, "text/plain", Array.Empty<byte>());
			}

			int statusCode = 200;
			string contentType = "text/plain";
			byte[] content = Array.Empty<byte>();

			// Figure out where the request was sent to by the client
			Uri originalRequestUri = UrlHelper.GetPublicUrl(http.Request);

			Uri? baseUri = GetAdvertiseBaseForRequest(originalRequestUri);
			if (baseUri != null)
			{
				if (string.Equals(http.Request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
				{
					// Count total login attempts hitting callback
					_dataCollection.IncrementCounter(kCounterLoginCalls, 1);

					bool found = false;
					foreach (IAuthentication auth in _authProviders)
					{
						if (auth.IsThisYours(http))
						{
							found = true;
							(string? upstreamSub, string? fullName, string? email, string[]? roles, string? linkcode, DownstreamAuthRequest? ds) = await auth.AuthenticateCallback(baseUri, http).ConfigureAwait(false);
							if (!string.IsNullOrEmpty(upstreamSub) && ds!=null)
							{
								long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
								long exp = now + _sessionDurationSeconds;

								string downstreamSub = auth.Provider + "_" + upstreamSub!;

								// If there is a link code, see if it's valid, and if so, write a masquerade file for this login so this login will appear to be the other account.
								if (!string.IsNullOrWhiteSpace(linkcode))
								{
									if (_codes.TryRemove(linkcode, out CodeRecord rec) && DateTime.UtcNow <= rec.Expires)
									{
										await SaveOverrideSub(downstreamSub, rec.Sub).ConfigureAwait(false);
										_logger.Log(EVerbosity.Info, $"Linked override set {downstreamSub} -> {rec.Sub}");
									}
								}

								// See if this login has an override sub, and if so, be that account instead.  If not, use the downstreamSub as is.
								string finalSub = await TryGetOverrideSub(downstreamSub).ConfigureAwait(false) ?? downstreamSub;
								string downstreamJwt = _jwt.CreateServerJWT(baseUri, finalSub, email, roles, exp);

								// Log success and masquerade status
								if (string.Equals(finalSub, downstreamSub, StringComparison.Ordinal))
								{
									_logger.Log(EVerbosity.Info, $"Login success provider={auth.Provider} sub={finalSub} email={(email ?? string.Empty)} masquerade=false");
								}
								else
								{
									_logger.Log(EVerbosity.Info, $"Login success provider={auth.Provider} sub={finalSub} email={(email ?? string.Empty)} masquerade=true as {finalSub} from {downstreamSub}");
								}

								// Metrics: success + provider counter
								_dataCollection.IncrementCounter(kCounterLoginSuccess, 1);
								string provSan = SanitizeMetricNamePart(auth.Provider);
								string provCounter = GetProviderSuccessCounterName(provSan);
								_dataCollection.IncrementCounter(provCounter, 1);

								// Use downstream OIDC params to decide redirect target and code/token behavior
								// Try to set a cookie with the downstream JWT so we can skip this up until the session timeout
								try
								{
									http.Response.Headers.Add("Set-Cookie", $"{kDownstreamSessionCookieName}={downstreamJwt}; Max-Age={_sessionDurationSeconds}; Path=/; HttpOnly");
								}
								catch
								{
									_logger.Log(EVerbosity.Warning, "OAuthCallback cookie failed to set");
								}

								string responseType = ds.ResponseType ?? "code";
								if (string.Equals(responseType, "code", StringComparison.OrdinalIgnoreCase))
								{
									// Issue short-lived authorization code for token exchange
									string authCode = Guid.NewGuid().ToString().Split('-')[0];
									DateTime expires = DateTime.UtcNow.AddSeconds(300);
									_authCodes.AddOrUpdate(authCode, new AuthCodeRecord(
										downstreamJwt,
										ds.ClientId ?? string.Empty,
										ds.RedirectUri!,
										ds.CodeChallenge,
										ds.CodeChallengeMethod,
										expires));

									string redirectUrl = AppendKeyValueToUrl(ds.RedirectUri!, "code", authCode);
									if (!string.IsNullOrWhiteSpace(ds.State))
									{
										redirectUrl = AppendKeyValueToUrl(redirectUrl, "state", ds.State!);
									}
									http.Response.RedirectLocation = redirectUrl;
									statusCode = 307;
									contentType = "text/plain";
									content = Encoding.UTF8.GetBytes("Redirecting");
								}
								else
								{
									// Fallback: implicit-like, return token to redirect_uri
									string redirectWithToken = AppendTokenToUrl(ds.RedirectUri!, downstreamJwt);
									if (!string.IsNullOrWhiteSpace(ds.State))
									{
										redirectWithToken = AppendKeyValueToUrl(redirectWithToken, "state", ds.State!);
									}
									http.Response.RedirectLocation = redirectWithToken;
									statusCode = 307;
									contentType = "text/plain";
									content = Encoding.UTF8.GetBytes("Redirecting");
								}
							}
							else
							{
								_logger.Log(EVerbosity.Warning, "OAuthCallback authentication failed for provider");
								statusCode = 401;
								contentType = "text/plain";
								content = Encoding.UTF8.GetBytes("Invalid token");
							}
							break;
						}
					}
					if (found==false)
					{
						_logger.Log(EVerbosity.Warning, "OAuthCallback no provider claimed connection");
						statusCode = 400;
						contentType = "text/plain";
						content = Encoding.UTF8.GetBytes("Invalid state");
					}
				}
				else
				{
					_logger.Log(EVerbosity.Warning, "OAuthCallback Method Not Allowed");
					statusCode = 405;
					contentType = "text/plain";
					content = Encoding.UTF8.GetBytes("Method Not Allowed");
				}
			}
			else
			{
				_logger.Log(EVerbosity.Warning, $"OAuthCallback unexpected source: {originalRequestUri.AbsoluteUri}");
				statusCode = 401;
				contentType = "text/plain";
				content = Encoding.UTF8.GetBytes($"Request from unexpected source does not match any AdvertiseURL: {originalRequestUri.AbsoluteUri}");
			}

			return (statusCode, contentType, content);
		}

		//-------------------
		// Well-known endpoints for openid_configuration and jwks.json
		public Task<(int, string, byte[])> OpenIdConfiguration(HttpListenerContext http)
		{
			AddCors(http.Request, http.Response, "GET, OPTIONS");
			if (string.Equals(http.Request.HttpMethod, "OPTIONS", StringComparison.OrdinalIgnoreCase))
			{
				return Task.FromResult<(int, string, byte[])>((204, "text/plain", Array.Empty<byte>()));
			}

			int statusCode = 200;
			string contentType = "application/json";
			byte[] content = Array.Empty<byte>();

			// Figure out where the request was sent to by the client
			Uri originalRequestUri = UrlHelper.GetPublicUrl(http.Request);

			Uri? baseUri = GetAdvertiseBaseForRequest(originalRequestUri);
			if (baseUri != null)
			{
				if (string.Equals(http.Request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
				{
					Dictionary<string, object?> doc = new Dictionary<string, object?>();
					doc["issuer"] = baseUri.AbsoluteUri.TrimEnd('/');
					doc["authorization_endpoint"] = new Uri(baseUri, "/api/oauth/url").AbsoluteUri; // Rule override: advertise our authorize entrypoint
					doc["token_endpoint"] = new Uri(baseUri, "/api/oidc/token").AbsoluteUri;
					doc["jwks_uri"] = new Uri(baseUri, "/.well-known/jwks.json").AbsoluteUri;
					doc["response_types_supported"] = new[] { "code" };
					doc["subject_types_supported"] = new[] { "public" };
					doc["id_token_signing_alg_values_supported"] = new[] { "RS256" };
					doc["scopes_supported"] = new[] { "openid", "profile", "email" };
					doc["token_endpoint_auth_methods_supported"] = new[] { "none" };
					doc["claims_supported"] = new[] { "iss", "sub", "aud", "exp", "iat", "email", "name", "roles" };
					doc["code_challenge_methods_supported"] = new[] { "S256" };
					doc["grant_types_supported"] = new[] { "authorization_code" };
					string json = JsonSerializer.Serialize(doc);
					statusCode = 200;
					contentType = "application/json";
					content = Encoding.UTF8.GetBytes(json);
				}
				else
				{
					statusCode = 405;
					contentType = "text/plain";
					content = Encoding.UTF8.GetBytes("Method Not Allowed");
				}
			}
			else
			{
				_logger.Log(EVerbosity.Warning, $"OpenIdConfiguration unexpected source: {originalRequestUri.AbsoluteUri}");
				statusCode = 401;
				contentType = "text/plain";
				content = Encoding.UTF8.GetBytes($"Request from unexpected source does not match any AdvertiseURL: {originalRequestUri.AbsoluteUri}");
			}

			return Task.FromResult((statusCode, contentType, content));
		}

		public Task<(int, string, byte[])> Jwks(HttpListenerContext http)
		{
			AddCors(http.Request, http.Response, "GET, OPTIONS");
			if (string.Equals(http.Request.HttpMethod, "OPTIONS", StringComparison.OrdinalIgnoreCase))
			{
				return Task.FromResult<(int, string, byte[])>((204, "text/plain", Array.Empty<byte>()));
			}

			int statusCode = 200;
			string contentType = "application/json";
			byte[] content = Array.Empty<byte>();

			// Figure out where the request was sent to by the client
			Uri originalRequestUri = UrlHelper.GetPublicUrl(http.Request);

			Uri? baseUri = GetAdvertiseBaseForRequest(originalRequestUri);
			if (baseUri != null)
			{
				if (string.Equals(http.Request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
				{
					(string n, string e) = _jwt.GetPublicKeyComponents();
					Dictionary<string, object?> key = new Dictionary<string, object?>();
					key["kty"] = "RSA";
					key["use"] = "sig";
					key["alg"] = "RS256";
					key["kid"] = _jwt.Kid;
					key["n"] = n;
					key["e"] = e;
					Dictionary<string, object?> body = new Dictionary<string, object?>();
					body["keys"] = new[] { key };
					statusCode = 200;
					contentType = "application/json";
					content = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(body));
				}
				else
				{
					statusCode = 405;
				 contentType = "text/plain";
					content = Encoding.UTF8.GetBytes("Method Not Allowed");
				}
			}
			else
			{
				_logger.Log(EVerbosity.Warning, $"Jwks unexpected source: {originalRequestUri.AbsoluteUri}");
				statusCode = 401;
				contentType = "text/plain";
				content = Encoding.UTF8.GetBytes($"Request from unexpected source does not match any AdvertiseURL: {originalRequestUri.AbsoluteUri}");
			}

			return Task.FromResult((statusCode, contentType, content));
		}

		//-------------------
		// Static_root file server with auto-redirect on valid session at base
		public async Task<(int, string, byte[])> GetClient(HttpListenerContext http)
		{
			AddCors(http.Request, http.Response, "GET, OPTIONS");
			if (string.Equals(http.Request.HttpMethod, "OPTIONS", StringComparison.OrdinalIgnoreCase))
			{
				return (204, "text/plain", Array.Empty<byte>());
			}

			int statusCode = 200;
			string contentType = "text/plain";
			byte[] content = Array.Empty<byte>();

			// Figure out where the request was sent to by the client
			Uri originalRequestUri = UrlHelper.GetPublicUrl(http.Request);

			Uri? baseUri = GetAdvertiseBaseForRequest(originalRequestUri);
			if (baseUri != null)
			{
				Uri relativeUri = baseUri.MakeRelativeUri(originalRequestUri);
				string relative = relativeUri.ToString();   // may be "path/to/thing?x=1" or just "?x=1"
				int qIndex = relative.IndexOf('?');
				string relativePath = qIndex >= 0 ? relative.Substring(0, qIndex) : relative;

				(int statusCode2, string contentType2, byte[] content2) = await ServeStaticFile(_staticRootFolder, relativePath).ConfigureAwait(false);
				statusCode = statusCode2;
				contentType = contentType2;
				content = content2;
			}
			else
			{
				statusCode = 401;
				contentType = "text/plain";
				content = Encoding.UTF8.GetBytes($"Request from unexpected source does not match any AdvertiseURL: {originalRequestUri.AbsoluteUri}");
			}

			return (statusCode, contentType, content);
		}

		//-------------------
		// Static file server
		static private async Task<(int statusCode, string contentType, byte[] content)> ServeStaticFile(string staticRoot, string urlPath)
		{
			int statusCode = 200;
			string contentType = "text/plain";
			byte[] content = Array.Empty<byte>();

			string relativePath = urlPath.TrimStart('/');
			if (string.IsNullOrWhiteSpace(relativePath))
			{
				relativePath = "index.html"; // default file
			}

			string fullPath = Path.Combine(staticRoot, relativePath);
			string fullPathNormalized = Path.GetFullPath(fullPath);
			string staticRootNormalized = Path.GetFullPath(staticRoot);

			if (!fullPathNormalized.StartsWith(staticRootNormalized))
			{
				statusCode = 403;
				contentType = "text/plain";
				content = Encoding.UTF8.GetBytes("Forbidden");
			}
			else
			{
				if (!File.Exists(fullPathNormalized))
				{
					statusCode = 404;
					contentType = "text/plain";
					content = Encoding.UTF8.GetBytes("Not Found");
				}
				else
				{
					string fileName = Path.GetFileName(fullPathNormalized).ToLowerInvariant();
					string detectedContentType = MimeTypesMap.GetMimeType(fileName);
					byte[] bytes = await File.ReadAllBytesAsync(fullPathNormalized).ConfigureAwait(false);
					statusCode = 200;
					contentType = detectedContentType;
					content = bytes;
				}
			}

			return (statusCode, contentType, content);
		}

		// ---------------- Short link endpoints ----------------
		public Task<(int, string, byte[])> LinkCreate(HttpListenerContext http)
		{
			AddCors(http.Request, http.Response, "GET, OPTIONS");
			if (string.Equals(http.Request.HttpMethod, "OPTIONS", StringComparison.OrdinalIgnoreCase))
			{
				return Task.FromResult<(int, string, byte[])>((204, "text/plain", Array.Empty<byte>()));
			}

			int statusCode = 200;
			string contentType = "text/plain";
			byte[] content = Array.Empty<byte>();

			// Figure out where the request was sent to by the client
			Uri originalRequestUri = UrlHelper.GetPublicUrl(http.Request);

			Uri? baseUri = GetAdvertiseBaseForRequest(originalRequestUri);
			if (baseUri != null)
			{
				if (string.Equals(http.Request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
				{
					// Count total link create calls
					_dataCollection.IncrementCounter(kCounterLinkCreateCalls, 1);

					// Require secret on query line
					string? providedSecret = http.Request.QueryString["secret"];
					if (string.IsNullOrWhiteSpace(providedSecret) || string.Equals(providedSecret, _linkcreateSecret, StringComparison.Ordinal) == false)
					{
						_logger.Log(EVerbosity.Warning, "LinkCreate Unauthorized (missing or invalid secret)");
						statusCode = 401;
						contentType = "text/plain";
						content = Encoding.UTF8.GetBytes("Unauthorized");
					}
					else
					{
						string? cookieHeader = http.Request.Headers["Cookie"];
						string? jwt = UrlHelper.ExtractCookie(cookieHeader, kDownstreamSessionCookieName);
						Utilities.JwtPayload? payload;
						if (!string.IsNullOrWhiteSpace(jwt) && TryReadValidSession(jwt, out payload) && payload != null && !string.IsNullOrWhiteSpace(payload.sub))
						{
							string code = Guid.NewGuid().ToString().Split('-')[0];
							DateTime expires = DateTime.UtcNow.AddSeconds(kLinkCodeTtlSeconds);
							_codes.AddOrUpdate(code, new CodeRecord(payload.sub!, expires));
							_logger.Log(EVerbosity.Info, $"LinkCreate sub={payload.sub} code={code}");
							// success metric
							_dataCollection.IncrementCounter(kCounterLinkCreateSuccess, 1);
							statusCode = 200;
							contentType = "text/plain";
							content = Encoding.UTF8.GetBytes(code);
						}
						else
						{
							_logger.Log(EVerbosity.Warning, "LinkCreate Unauthorized (no or invalid session)");
							statusCode = 401;
							contentType = "text/plain";
							content = Encoding.UTF8.GetBytes("Unauthorized");
						}
					}
				}
				else
				{
					_logger.Log(EVerbosity.Warning, "LinkCreate Method Not Allowed");
					statusCode = 405;
					contentType = "text/plain";
					content = Encoding.UTF8.GetBytes("Method Not Allowed");
				}
			}
			else
			{
				_logger.Log(EVerbosity.Warning, $"LinkCreate unexpected source: {originalRequestUri.AbsoluteUri}");
				statusCode = 401;
				contentType = "text/plain";
				content = Encoding.UTF8.GetBytes($"Request from unexpected source does not match any AdvertiseURL: {originalRequestUri.AbsoluteUri}");
			}

			return Task.FromResult((statusCode, contentType, content));
		}

		public async Task<(int, string, byte[])> UnlinkAccount(HttpListenerContext http)
		{
			AddCors(http.Request, http.Response, "POST, OPTIONS");
			if (string.Equals(http.Request.HttpMethod, "OPTIONS", StringComparison.OrdinalIgnoreCase))
			{
				return (204, "text/plain", Array.Empty<byte>());
			}

			int statusCode = 200;
			string contentType = "text/plain";
			byte[] content = Array.Empty<byte>();

			// Figure out where the request was sent to by the client
			Uri originalRequestUri = UrlHelper.GetPublicUrl(http.Request);

			Uri? baseUri = GetAdvertiseBaseForRequest(originalRequestUri);
			if (baseUri != null)
			{
				if (string.Equals(http.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
				{
					// Count total unlink calls
					_dataCollection.IncrementCounter(kCounterUnlinkCalls, 1);

					string? cookieHeader = http.Request.Headers["Cookie"];
					string? jwt = UrlHelper.ExtractCookie(cookieHeader, kDownstreamSessionCookieName);
					Utilities.JwtPayload? payload;
					if (!string.IsNullOrWhiteSpace(jwt) && TryReadValidSession(jwt, out payload) && payload != null && !string.IsNullOrWhiteSpace(payload.sub))
					{
						string currentSub = payload.sub!;
						await _linksStorage.Delete(currentSub).ConfigureAwait(false);
						_logger.Log(EVerbosity.Info, $"Unlink removed override for {currentSub}");
						// success metric
						_dataCollection.IncrementCounter(kCounterUnlinkSuccess, 1);
						statusCode = 200;
						contentType = "text/plain";
						content = Encoding.UTF8.GetBytes("Unlinked");
					}
					else
					{
						_logger.Log(EVerbosity.Warning, "Unlink Unauthorized (no or valid session)");
						statusCode = 401;
						contentType = "text/plain";
						content = Encoding.UTF8.GetBytes("Unauthorized");
					}
				}
				else
				{
					_logger.Log(EVerbosity.Warning, "Unlink Method Not Allowed");
					statusCode = 405;
					contentType = "text/plain";
					content = Encoding.UTF8.GetBytes("Method Not Allowed");
				}
			}
			else
			{
				_logger.Log(EVerbosity.Warning, $"Unlink unexpected source: {originalRequestUri.AbsoluteUri}");
				statusCode = 401;
				contentType = "text/plain";
				content = Encoding.UTF8.GetBytes($"Request from unexpected source does not match any AdvertiseURL: {originalRequestUri.AbsoluteUri}");
			}

			return (statusCode, contentType, content);
		}

		// ---------------- OIDC Token endpoint ----------------
		public async Task<(int, string, byte[])> Token(HttpListenerContext http)
		{
			AddCors(http.Request, http.Response, "POST, OPTIONS");
			if (string.Equals(http.Request.HttpMethod, "OPTIONS", StringComparison.OrdinalIgnoreCase))
			{
				return (204, "text/plain", Array.Empty<byte>());
			}

			int statusCode = 200;
			string contentType = "application/json";
			byte[] content = Array.Empty<byte>();

			Uri originalRequestUri = UrlHelper.GetPublicUrl(http.Request);
			Uri? baseUri = GetAdvertiseBaseForRequest(originalRequestUri);
			if (baseUri != null)
			{
				if (string.Equals(http.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
				{
					// Read form body
					string body = string.Empty;
					try
					{
						using (StreamReader sr = new StreamReader(http.Request.InputStream, http.Request.ContentEncoding))
						{
							body = await sr.ReadToEndAsync().ConfigureAwait(false);
						}
					}
					catch {}

					Dictionary<string, string> form = ParseFormUrlEncoded(body);
					string grantType = form.ContainsKey("grant_type") ? form["grant_type"] : string.Empty;
					string code = form.ContainsKey("code") ? form["code"] : string.Empty;
					string redirectUri = form.ContainsKey("redirect_uri") ? form["redirect_uri"] : string.Empty;
					string clientId = form.ContainsKey("client_id") ? form["client_id"] : string.Empty;
					string codeVerifier = form.ContainsKey("code_verifier") ? form["code_verifier"] : string.Empty;

					if (string.Equals(grantType, "authorization_code", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(code))
					{
						if (_authCodes.TryRemove(code, out AuthCodeRecord record) && DateTime.UtcNow <= record.Expires)
						{
							bool ok = true;
							if (!string.IsNullOrWhiteSpace(record.ClientId) && !string.IsNullOrWhiteSpace(clientId))
							{
								ok = string.Equals(record.ClientId, clientId, StringComparison.Ordinal);
							}
							if (ok && !string.IsNullOrWhiteSpace(record.RedirectUri) && !string.IsNullOrWhiteSpace(redirectUri))
							{
								ok = string.Equals(record.RedirectUri, redirectUri, StringComparison.Ordinal);
							}
							if (ok && !string.IsNullOrWhiteSpace(record.CodeChallenge))
							{
								// Verify PKCE S256
								if (string.Equals(record.CodeChallengeMethod ?? string.Empty, "S256", StringComparison.OrdinalIgnoreCase))
								{
									if (string.IsNullOrWhiteSpace(codeVerifier)==false)
									{
										byte[] bytes = Encoding.ASCII.GetBytes(codeVerifier);
										byte[] hash = SHA256.HashData(bytes);
										string expected = UrlHelper.Base64UrlEncodeNoPadding(hash);
										ok = string.Equals(expected, record.CodeChallenge, StringComparison.Ordinal);
									}
									else
									{
										ok = false;
									}
								}
								else
								{
									ok = false;
								}
							}

							if (ok)
							{
								// Build minimal token response
								Dictionary<string, object?> resp = new Dictionary<string, object?>();
								resp["token_type"] = "Bearer";
								resp["expires_in"] = _sessionDurationSeconds;
								resp["access_token"] = record.Token;
								resp["id_token"] = record.Token;
								string json = JsonSerializer.Serialize(resp);
								statusCode = 200;
								contentType = "application/json";
								content = Encoding.UTF8.GetBytes(json);
							}
							else
							{
								statusCode = 400;
								contentType = "application/json";
								content = Encoding.UTF8.GetBytes("{\"error\":\"invalid_grant\"}");
							}
						}
						else
						{
							statusCode = 400;
							contentType = "application/json";
							content = Encoding.UTF8.GetBytes("{\"error\":\"invalid_grant\"}");
						}
					}
					else
					{
						statusCode = 400;
						contentType = "application/json";
						content = Encoding.UTF8.GetBytes("{\"error\":\"unsupported_grant_type\"}");
					}
				}
				else
				{
					statusCode = 405;
					contentType = "text/plain";
					content = Encoding.UTF8.GetBytes("Method Not Allowed");
				}
			}
			else
			{
				statusCode = 401;
				contentType = "text/plain";
				content = Encoding.UTF8.GetBytes($"Request from unexpected source does not match any AdvertiseURL: {originalRequestUri.AbsoluteUri}");
			}

			return (statusCode, contentType, content);
		}

		private static Dictionary<string, string> ParseFormUrlEncoded(string form)
		{
			Dictionary<string, string> dict = new Dictionary<string, string>(StringComparer.Ordinal);
			if (string.IsNullOrEmpty(form))
			{
				return dict;
			}
			string[] pairs = form.Split('&');
			for (int i = 0; i < pairs.Length; i++)
			{
				string p = pairs[i];
				if (string.IsNullOrEmpty(p)) continue;
				int eq = p.IndexOf('=');
				if (eq <= 0)
				{
					string k = WebUtility.UrlDecode(p);
					if (!dict.ContainsKey(k)) dict[k] = string.Empty;
				}
				else
				{
					string k = WebUtility.UrlDecode(p.Substring(0, eq));
					string v = WebUtility.UrlDecode(p.Substring(eq + 1));
					if (!dict.ContainsKey(k)) dict[k] = v;
				}
			}
			return dict;
		}
	}
}
