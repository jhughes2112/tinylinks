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
		private readonly string?               _postLoginRedirect;
		private int                            _sessionDurationSeconds      = 3600; // 1 hour session cookie
		private string                         _linkcreateSecret;           // secret used to create link codes
		private const int                      kLinkCodeTtlSeconds          = 3600;
		private const string                   kDownstreamSessionCookieName = "tinylinks_session";

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

		// In-memory, storage for link codes that expire quickly
		private readonly ThreadSafeDictionary<string, CodeRecord>      _codes = new ThreadSafeDictionary<string, CodeRecord>();

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

			if (string.IsNullOrWhiteSpace(_postLoginRedirect) || string.IsNullOrWhiteSpace(staticRootFolder) || string.IsNullOrWhiteSpace(_linkcreateSecret) || _authProviders.Count==0)
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
		public async Task<(int, string, byte[])> OAuthUrl(HttpListenerContext http)
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
							// See how the auth system wants to handle this call.  State will be set in a cookie so the callback can retrieve it later.
							(statusCode, contentType, content) = await auth.StartAuthenticate(baseUri, http).ConfigureAwait(false);
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

			return (statusCode, contentType, content);
		}

		// On the callback, we ask grab the cookie and see what provider the state variable is associated with.  Then we dispatch to it.
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

					bool found = false;
					foreach (IAuthentication auth in _authProviders)
					{
						if (auth.IsThisYours(http))
						{
							found = true;
							(string? upstreamSub, string? fullName, string? email, string[]? roles, string? linkcode) = await auth.AuthenticateCallback(baseUri, http).ConfigureAwait(false);
							if (!string.IsNullOrEmpty(upstreamSub))
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

								try
								{
									// Try to set a cookie with the downstream JWT so we can skip this up until the session timeout
									http.Response.Headers.Add("Set-Cookie", $"{kDownstreamSessionCookieName}={downstreamJwt}; Max-Age={_sessionDurationSeconds}; Path=/; HttpOnly");

									string redirectWithToken = AppendTokenToUrl(_postLoginRedirect!, downstreamJwt);
									http.Response.RedirectLocation = redirectWithToken;
									statusCode = 307;
									contentType = "text/plain";
									content = Encoding.UTF8.GetBytes("Redirecting");
								}
								catch
								{
									// ignore cookie add failure
									_logger.Log(EVerbosity.Warning, "OAuthCallback cookie failed to set");
									statusCode = 401;
									contentType = "text/plain";
									content = Encoding.UTF8.GetBytes("Cookie failure");
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
						string? jwt = UrlHelper.ExtractCookie(cookieHeader, kDownstreamSessionCookieName);
						if (!string.IsNullOrWhiteSpace(jwt) && TryReadValidSession(jwt, out Utilities.JwtPayload? payload))
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
				_logger.Log(EVerbosity.Warning, $"Unlink unexpected source: {http.Request.Url}");
				statusCode = 401;
				contentType = "text/plain";
				content = Encoding.UTF8.GetBytes($"Request from unexpected source does not match any AdvertiseURL: {http.Request.Url}");
			}

			return (statusCode, contentType, content);
		}
	}
}
