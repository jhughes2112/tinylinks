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
using System.Security.Cryptography;
using System.Text.Json;
using Utilities;
using Storage;

namespace TinyLinks
{
	// handles authenticating each and every request, then routes the request to the appropriate handler based on the HTTP method and URL structure.
	public class TinyLinksServer
	{
		private List<string>                   _advertiseUrls;
		private string                         _staticRootFolder;
		private IDataCollection                _dataCollection;
		private ILogging                       _logger;
		private Task                           _updateThread                = Task.CompletedTask;
		private CancellationTokenSource        _cancellationTokenSrc;
		private CancellationTokenSource?       _cancellationTokenSrcUpdate;

		private readonly List<IAuthentication> _authProviders;
		private readonly string?               _postLoginRedirect;
		private int                            _sessionDurationSeconds      = 3600; // 1 hour session cookie
		private string                         _linkcreateSecret;           // secret used to create link codes
		private const string                   kDownstreamSessionCookieName = "tinylinks_session";
		private const string                   kOAuthStateCookieName        = "oauth_state";

		// Metrics counters (created at startup)
		private const string kCounterLoginCalls          = "tl_login_calls";
		private const string kCounterLoginSuccess        = "tl_login_success";
		private const string kCounterLinkCreateCalls     = "tl_linkcreate_calls";
		private const string kCounterLinkCreateSuccess   = "tl_linkcreate_success";
		private const string kCounterUnlinkCalls         = "tl_unlink_calls";
		private const string kCounterUnlinkSuccess       = "tl_unlink_success";

		// Link code TTL
		private const int                      kLinkCodeTtlSeconds          = 3600;

		// OAuth state (short TTL)
		private const int kOAuthStateTtlSeconds = 9; // 9 seconds to complete your login right now, will adjust it up in a bit
		private readonly ThreadSafeDictionary<string, OAuthStateEntry> _oauthStates = new ThreadSafeDictionary<string, OAuthStateEntry>();

		// Server JWT signer (RS256) for downstream cookies and JWKS
		private readonly JwtSigner _jwt = new JwtSigner();

		// In-memory, minimal storage for link codes and relationships (bad/simple implementation)
		private readonly ThreadSafeDictionary<string, CodeRecord>      _codes = new ThreadSafeDictionary<string, CodeRecord>();
		private readonly ThreadSafeDictionary<string, HashSet<string>> _links = new ThreadSafeDictionary<string, HashSet<string>>();

		// Persistent storage for link relationships
		private readonly StorageFiles _linksStorage;

		public TinyLinksServer(List<string> advertiseUrls, string staticRootFolder, IDataCollection dataCollection, ILogging logger, CancellationTokenSource tokenSrc, IEnumerable<IAuthentication> authentications, string postLoginRedirect, int sessionDurationSeconds, string linkcreateSecret, StorageFiles linksStorage)
		{
			_advertiseUrls           = advertiseUrls;
			_staticRootFolder        = staticRootFolder;
			_dataCollection          = dataCollection;
			_logger                  = logger;
			_cancellationTokenSrc    = tokenSrc;
			_authProviders           = new List<IAuthentication>(authentications);
			_postLoginRedirect       = postLoginRedirect;
			_sessionDurationSeconds  = sessionDurationSeconds;
			_linkcreateSecret        = linkcreateSecret;
			_linksStorage            = linksStorage;

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
						foreach (string k in expiredCodes)
						{
							_codes.Remove(k);
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

		private Uri? GetAdvertiseBaseForRequest(Uri requestUri)
		{
			Uri? result = null;
			string requestPath = requestUri.AbsoluteUri;
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

		private static string? ExtractCookie(string? cookieHeader, string cookieName)
		{
			string? result = null;
			if (!string.IsNullOrWhiteSpace(cookieHeader))
			{
				string search = cookieName + "=";
				string[] parts = cookieHeader.Split(';');
				for (int i = 0; i < parts.Length; i++)
				{
					string p = parts[i].Trim();
					if (p.StartsWith(search, StringComparison.Ordinal))
					{
						result = p.Substring(search.Length);
						break;
					}
				}
			}
			else
			{
				result = null;
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

		// ---------------- OAuth endpoints ----------------
		public Task<(int, string, byte[])> OAuthUrl(HttpListenerContext http)
		{
			int statusCode = 200;
			string contentType = "text/plain";
			byte[] content = Array.Empty<byte>();

			Uri? baseUri = http.Request.Url != null ? GetAdvertiseBaseForRequest(http.Request.Url) : null;
			if (baseUri != null)
			{
				if (string.Equals(http.Request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
				{
					string? provider = http.Request.QueryString["provider"];
					if (!string.IsNullOrWhiteSpace(provider))
					{
						IAuthentication? auth = _authProviders.Find(p => string.Equals(p.Provider, provider, StringComparison.OrdinalIgnoreCase));
						if (auth != null)
						{
							string state = UrlHelper.GenerateRandomDataBase64url(32);
							string codeVerifier = UrlHelper.GenerateRandomDataBase64url(64);
							byte[] bytes = Encoding.ASCII.GetBytes(codeVerifier);
							byte[] hash = SHA256.HashData(bytes);
							String codeChallenge = UrlHelper.Base64UrlEncodeNoPadding(hash);

							string callbackUrl = new Uri(baseUri, "/api/oauth/callback").AbsoluteUri;
							string? linkCode = http.Request.QueryString["linkcode"];
							_oauthStates.AddOrUpdate(state, new OAuthStateEntry(provider, codeVerifier, callbackUrl, DateTime.UtcNow, linkCode));

							try
							{
								http.Response.Headers.Add("Set-Cookie", $"{kOAuthStateCookieName}={state}; Max-Age={kOAuthStateTtlSeconds}; Path=/; HttpOnly");
							}
							catch
							{
								// ignore cookie add failure
							}

							string url = auth.BuildAuthorizeUrl(callbackUrl, state, codeChallenge);
							statusCode = 200;
							contentType = "text/plain";
							content = Encoding.UTF8.GetBytes(url);
						}
						else
						{
							_logger.Log(EVerbosity.Warning, "OAuthUrl Unknown provider");
							statusCode = 400;
							contentType = "text/plain";
							content = Encoding.UTF8.GetBytes("Unknown provider");
						}
					}
					else
					{
						_logger.Log(EVerbosity.Warning, "OAuthUrl Missing provider");
						statusCode = 400;
						contentType = "text/plain";
						content = Encoding.UTF8.GetBytes("Missing provider");
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
				_logger.Log(EVerbosity.Warning, $"OAuthUrl unexpected source: {http.Request.Url}");
				statusCode = 401;
				contentType = "text/plain";
				content = Encoding.UTF8.GetBytes($"Request from unexpected source does not match any AdvertiseURL: {http.Request.Url}");
			}

			return Task.FromResult((statusCode, contentType, content));
		}

		public async Task<(int, string, byte[])> OAuthCallback(HttpListenerContext http)
		{
			int statusCode = 200;
			string contentType = "text/plain";
			byte[] content = Array.Empty<byte>();

			Uri? baseUri = http.Request.Url != null ? GetAdvertiseBaseForRequest(http.Request.Url) : null;
			if (baseUri != null)
			{
				if (string.Equals(http.Request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
				{
					// Count total login attempts hitting callback
					_dataCollection.IncrementCounter(kCounterLoginCalls, 1);

					string? code = http.Request.QueryString["code"];
					string? state = http.Request.QueryString["state"];
					if (!string.IsNullOrWhiteSpace(code) && !string.IsNullOrWhiteSpace(state))
					{
						string? cookieHeader = http.Request.Headers["Cookie"];
						string? stateCookie = ExtractCookie(cookieHeader, kOAuthStateCookieName);
						if (!string.IsNullOrWhiteSpace(stateCookie) && string.Equals(stateCookie, state, StringComparison.Ordinal))
						{
							if (_oauthStates.TryRemove(state, out OAuthStateEntry entry))
							{
								IAuthentication? auth = _authProviders.Find(p => string.Equals(p.Provider, entry.Provider, StringComparison.OrdinalIgnoreCase));
								if (auth != null)
								{
									string? id_token = await auth.ExchangeCodeForJwtAsync(code!, entry.CallbackUrl, entry.CodeVerifier).ConfigureAwait(false);
									if (!string.IsNullOrEmpty(id_token))
									{
										(string? upstreamSub, string? fullName, string? email, string[]? roles) = auth.Authenticate(id_token);
										if (!string.IsNullOrEmpty(upstreamSub))
										{
											long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
											long exp = now + _sessionDurationSeconds;

											string downstreamSub = entry.Provider + "_" + upstreamSub!;

											// If there is a link code, see if it's valid, and if so, write a masquerade file for this login so this login will appear to be the other account.
											if (!string.IsNullOrWhiteSpace(entry.LinkCode))
											{
												if (_codes.TryRemove(entry.LinkCode!, out CodeRecord rec) && DateTime.UtcNow <= rec.Expires)
												{
													await SaveOverrideSub(downstreamSub, rec.Sub).ConfigureAwait(false);
													_logger.Log(EVerbosity.Info, $"Linked override set {downstreamSub} -> {rec.Sub}");
												}
											}

											// See if this login has an override sub, and if so, be that account instead.  If not, use the downstreamSub as is.
											string finalSub = await TryGetOverrideSub(downstreamSub).ConfigureAwait(false) ?? downstreamSub;
											string downstreamJwt = _jwt.CreateServerJWTWithSub(baseUri, finalSub, email, roles, exp);

											// Log success and masquerade status
											if (string.Equals(finalSub, downstreamSub, StringComparison.Ordinal))
											{
												_logger.Log(EVerbosity.Info, $"Login success provider={entry.Provider} sub={finalSub} email={(email ?? string.Empty)} masquerade=false");
											}
											else
											{
												_logger.Log(EVerbosity.Info, $"Login success provider={entry.Provider} sub={finalSub} email={(email ?? string.Empty)} masquerade=true as {finalSub} from {downstreamSub}");
											}

											// Metrics: success + provider counter
											_dataCollection.IncrementCounter(kCounterLoginSuccess, 1);
											string provSan = SanitizeMetricNamePart(entry.Provider);
											string provCounter = GetProviderSuccessCounterName(provSan);
											_dataCollection.CreateCounter(provCounter, "Successful logins per provider"); // safe if already exists
											_dataCollection.IncrementCounter(provCounter, 1);

											try
											{
												http.Response.Headers.Add("Set-Cookie", $"{kDownstreamSessionCookieName}={downstreamJwt}; Max-Age={_sessionDurationSeconds}; Path=/; HttpOnly");
												http.Response.Headers.Add("Set-Cookie", $"{kOAuthStateCookieName}=; Max-Age=0; Path=/");
											}
											catch
											{
												// ignore cookie add failure
											}

											if (!string.IsNullOrWhiteSpace(_postLoginRedirect))
											{
												string redirectWithToken = AppendTokenToUrl(_postLoginRedirect!, downstreamJwt);
												http.Response.RedirectLocation = redirectWithToken;
												statusCode = 307;
												contentType = "text/plain";
												content = Encoding.UTF8.GetBytes("Redirecting");
											}
											else
											{
												_logger.Log(EVerbosity.Error, "post_login_redirect not configured");
												statusCode = 500;
												contentType = "text/plain";
												content = Encoding.UTF8.GetBytes("post_login_redirect not configured");
											}
										}
										else
										{
											_logger.Log(EVerbosity.Warning, "OAuthCallback invalid token from provider");
											statusCode = 401;
											contentType = "text/plain";
											content = Encoding.UTF8.GetBytes("Invalid token");
										}
									}
									else
									{
										_logger.Log(EVerbosity.Warning, "OAuthCallback token exchange failed");
										statusCode = 401;
										contentType = "text/plain";
										content = Encoding.UTF8.GetBytes("Token exchange failed");
									}
								}
								else
								{
									_logger.Log(EVerbosity.Warning, "OAuthCallback Unknown provider");
									statusCode = 400;
									contentType = "text/plain";
									content = Encoding.UTF8.GetBytes("Unknown provider");
								}
							}
							else 
							{
								_logger.Log(EVerbosity.Warning, "OAuthCallback Unknown or expired state");
								statusCode = 400;
								contentType = "text/plain";
								content = Encoding.UTF8.GetBytes("Unknown or expired state");
							}
						}
						else
						{
							_logger.Log(EVerbosity.Warning, "OAuthCallback Invalid state (cookie mismatch)");
							statusCode = 400;
							contentType = "text/plain";
							content = Encoding.UTF8.GetBytes("Invalid state");
						}
					}
					else
					{
						_logger.Log(EVerbosity.Warning, "OAuthCallback Missing code or state");
						statusCode = 400;
						contentType = "text/plain";
						content = Encoding.UTF8.GetBytes("Missing code or state");
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
				_logger.Log(EVerbosity.Warning, $"OAuthCallback unexpected source: {http.Request.Url}");
				statusCode = 401;
				contentType = "text/plain";
				content = Encoding.UTF8.GetBytes($"Request from unexpected source does not match any AdvertiseURL: {http.Request.Url}");
			}

			return (statusCode, contentType, content);
		}

		//-------------------
		// Well-known endpoints for openid_configuration and jwks.json
		public Task<(int, string, byte[])> OpenIdConfiguration(HttpListenerContext http)
		{
			int statusCode = 200;
			string contentType = "application/json";
			byte[] content = Array.Empty<byte>();

			Uri? baseUri = http.Request.Url != null ? GetAdvertiseBaseForRequest(http.Request.Url) : null;
			if (baseUri != null)
			{
				if (string.Equals(http.Request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
				{
					Dictionary<string, object?> doc = new Dictionary<string, object?>();
					doc["issuer"] = baseUri.AbsoluteUri.TrimEnd('/');
					doc["jwks_uri"] = new Uri(baseUri, "/.well-known/jwks.json").AbsoluteUri;
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
				statusCode = 401;
				contentType = "text/plain";
				content = Encoding.UTF8.GetBytes($"Request from unexpected source does not match any AdvertiseURL: {http.Request.Url}");
			}

			return Task.FromResult((statusCode, contentType, content));
		}

		public Task<(int, string, byte[])> Jwks(HttpListenerContext http)
		{
			int statusCode = 200;
			string contentType = "application/json";
			byte[] content = Array.Empty<byte>();

			Uri? baseUri = http.Request.Url != null ? GetAdvertiseBaseForRequest(http.Request.Url) : null;
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
				statusCode = 401;
				contentType = "text/plain";
				content = Encoding.UTF8.GetBytes($"Request from unexpected source does not match any AdvertiseURL: {http.Request.Url}");
			}

			return Task.FromResult((statusCode, contentType, content));
		}

		//-------------------
		// Static_root file server with auto-redirect on valid session at base
		public async Task<(int, string, byte[])> GetClient(HttpListenerContext httpListenerContext)
		{
			int statusCode = 200;
			string contentType = "text/plain";
			byte[] content = Array.Empty<byte>();

			Uri? requestUri = httpListenerContext.Request.Url;
			if (requestUri != null)
			{
				Uri? baseUri = GetAdvertiseBaseForRequest(requestUri);
				if (baseUri != null)
				{
					string relative = requestUri.AbsoluteUri.Substring(baseUri.AbsoluteUri.Length).TrimStart('/');
					if (string.IsNullOrEmpty(relative) || string.Equals(relative, "index.html", StringComparison.OrdinalIgnoreCase))
					{
						string? cookieHeader = httpListenerContext.Request.Headers["Cookie"];
						string? jwt = ExtractCookie(cookieHeader, kDownstreamSessionCookieName);
						Utilities.JwtPayload? payload;
						if (!string.IsNullOrWhiteSpace(jwt) && TryReadValidSession(jwt, out payload))
						{
							_logger.Log(EVerbosity.Info, $"Auto-redirecting authenticated user {payload!.sub}");
							if (!string.IsNullOrWhiteSpace(_postLoginRedirect))
							{
								string redirectWithToken = AppendTokenToUrl(_postLoginRedirect!, jwt!);
								httpListenerContext.Response.RedirectLocation = redirectWithToken;
								statusCode = 307;
								contentType = "text/plain";
								content = Encoding.UTF8.GetBytes("Redirecting");
							}
							else
							{
								_logger.Log(EVerbosity.Error, "post_login_redirect not configured");
								statusCode = 500;
								contentType = "text/plain";
								content = Encoding.UTF8.GetBytes("post_login_redirect not configured");
							}
						}
					}

					if (content.Length == 0)
					{
						(int statusCode2, string contentType2, byte[] content2) = await ServeStaticFile(_staticRootFolder, relative).ConfigureAwait(false);
						statusCode = statusCode2;
						contentType = contentType2;
						content = content2;
					}
				}
				else
				{
					statusCode = 401;
					contentType = "text/plain";
					content = Encoding.UTF8.GetBytes($"Request from unexpected source does not match any AdvertiseURL: {requestUri}");
				}
			}
			else
			{
				statusCode = 400;
				contentType = "text/plain";
				content = Encoding.UTF8.GetBytes("Invalid request URL");
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
					string detectedContentType = HeyRed.Mime.MimeTypesMap.GetMimeType(fileName);
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
			int statusCode = 200;
			string contentType = "text/plain";
			byte[] content = Array.Empty<byte>();

			Uri? baseUri = http.Request.Url != null ? GetAdvertiseBaseForRequest(http.Request.Url) : null;
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
						string? jwt = ExtractCookie(cookieHeader, kDownstreamSessionCookieName);
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
				_logger.Log(EVerbosity.Warning, $"LinkCreate unexpected source: {http.Request.Url}");
				statusCode = 401;
				contentType = "text/plain";
				content = Encoding.UTF8.GetBytes($"Request from unexpected source does not match any AdvertiseURL: {http.Request.Url}");
			}

			return Task.FromResult((statusCode, contentType, content));
		}

		public async Task<(int, string, byte[])> UnlinkAccount(HttpListenerContext http)
		{
			int statusCode = 200;
			string contentType = "text/plain";
			byte[] content = Array.Empty<byte>();

			Uri? baseUri = http.Request.Url != null ? GetAdvertiseBaseForRequest(http.Request.Url) : null;
			if (baseUri != null)
			{
				if (string.Equals(http.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
				{
					// Count total unlink calls
					_dataCollection.IncrementCounter(kCounterUnlinkCalls, 1);

					string? cookieHeader = http.Request.Headers["Cookie"];
					string? jwt = ExtractCookie(cookieHeader, kDownstreamSessionCookieName);
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
				_logger.Log(EVerbosity.Warning, $"Unlink unexpected source: {http.Request.Url}");
				statusCode = 401;
				contentType = "text/plain";
				content = Encoding.UTF8.GetBytes($"Request from unexpected source does not match any AdvertiseURL: {http.Request.Url}");
			}

			return (statusCode, contentType, content);
		}

		// Request/Model DTOs
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
		private sealed class OAuthStateEntry 
		{ 
			public string   Provider     { get; } 
			public string   CodeVerifier { get; } 
			public string   CallbackUrl  { get; } 
			public DateTime CreatedUtc   { get; } 
			public string?  LinkCode     { get; } 
			public OAuthStateEntry(string provider, string codeVerifier, string callbackUrl, DateTime createdUtc, string? linkCode) 
			{ 
				Provider     = provider; 
				CodeVerifier = codeVerifier; 
				CallbackUrl  = callbackUrl; 
				CreatedUtc   = createdUtc; 
				LinkCode     = linkCode; 
			} 
		}
	}
}
