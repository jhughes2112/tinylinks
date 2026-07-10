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
		private readonly string _scopes;  // these should be "openid+email+profile" unless one of the upstream providers doesn't support one, like SIWE-OIDC doesn't support email

		// OAuth state (short TTL)
		private const    int    kOAuthStateTtlSeconds = 300; // 5 minutes to complete your login
		private const    string kOAuthStateCookieName = "oauth_state";
		
		// When someone tries to authenticate, we stash some info in this object so it can be used when they finish the authentication flow and want to continue.
		private sealed class OAuthStateEntry 
		{ 
			public string                 CodeVerifier { get; } 
			public DateTime               CreatedUtc   { get; } 
			public string?                LinkCode     { get; } 
			public DownstreamAuthRequest  Downstream   { get; }
			public OAuthStateEntry(string codeVerifier, DateTime createdUtc, string? linkCode, DownstreamAuthRequest downstream) 
			{ 
				CodeVerifier = codeVerifier; 
				CreatedUtc   = createdUtc; 
				LinkCode     = linkCode; 
				Downstream   = downstream; 
			} 
		}

		private readonly ThreadSafeDictionary<string, OAuthStateEntry> _oauthStates = new ThreadSafeDictionary<string, OAuthStateEntry>();

		public AuthenticationOAuth2(string provider, string authorizationEndpoint, string tokenEndpoint, string clientId, string clientSecret, string scopes, Dictionary<string, RSA> publicKeys, ILogging logger)
		{
			Provider = provider;
			_authorizationEndpoint = authorizationEndpoint;
			_tokenEndpoint = tokenEndpoint;
			_clientId = clientId;
			_clientSecret = clientSecret;
			_publicKeys = publicKeys;
			_scopes = scopes;
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
		public Task<(int, string, byte[])> StartAuthenticate(Uri baseUri, HttpListenerContext httpContext, DownstreamAuthRequest downstream)
		{
			try
			{
				string state = UrlHelper.GenerateRandomDataBase64url(32);
				bool secure = string.Equals(baseUri.Scheme, "https", StringComparison.OrdinalIgnoreCase);
				httpContext.Response.Headers.Add("Set-Cookie", UrlHelper.BuildSetCookie(kOAuthStateCookieName, state, kOAuthStateTtlSeconds, "/", true, secure));

				string codeVerifier = UrlHelper.GenerateRandomDataBase64url(64);
				byte[] bytes = Encoding.ASCII.GetBytes(codeVerifier);
				byte[] hash = SHA256.HashData(bytes);
				String codeChallenge = UrlHelper.Base64UrlEncodeNoPadding(hash);

				string callbackUrl = new Uri(baseUri, "/api/oauth/callback").AbsoluteUri;
				string? linkCode = httpContext.Request.QueryString["linkcode"];
				_oauthStates.AddOrUpdate(state, new OAuthStateEntry(codeVerifier, DateTime.UtcNow, linkCode, downstream));

				_logger.Log(EVerbosity.Debug, $"OAuth2 Provider={Provider} Sending to url with scopes={_scopes} state={state} challenge={codeChallenge} verifier={codeVerifier}");

				string url = $"{_authorizationEndpoint}?response_type=code&scope={_scopes}&redirect_uri={Uri.EscapeDataString(callbackUrl)}&client_id={Uri.EscapeDataString(_clientId)}&state={Uri.EscapeDataString(state)}&code_challenge={Uri.EscapeDataString(codeChallenge)}&code_challenge_method=S256";
				httpContext.Response.RedirectLocation = url;
				return Task.FromResult((307, "text/plain", Encoding.UTF8.GetBytes("Redirecting")));
			}
			catch
			{
				return Task.FromResult<(int, string, byte[])>((401, "text/plain", Encoding.UTF8.GetBytes("Cookie set failed")));
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
				if (!string.IsNullOrWhiteSpace(stateCookie) && string.Equals(stateCookie, state, StringComparison.Ordinal))
				{
					// Only claim if we have an active state matching this provider
					isMine = _oauthStates.ContainsKey(state);
				}

				_logger.Log(EVerbosity.Debug, $"OAuth2 Provider={Provider} IsMine={isMine} state={state}");
			}
			return isMine;
		}

		public async Task<(string?, string?, string?, string[]?, string?, DownstreamAuthRequest?)> AuthenticateCallback(Uri baseUri, HttpListenerContext httpContext)
		{
			// We already verified this is the correct state and it's ours.
			string state = httpContext.Request.QueryString["state"]!;
			if (_oauthStates.TryRemove(state, out OAuthStateEntry? entry))
			{
				// wipe out that cookie
				try
				{
					bool secure = string.Equals(baseUri.Scheme, "https", StringComparison.OrdinalIgnoreCase);
					httpContext.Response.Headers.Add("Set-Cookie", UrlHelper.BuildSetCookie(kOAuthStateCookieName, string.Empty, 0, "/", true, secure));

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
							return (sub, fullName, email, roles, entry.LinkCode, entry.Downstream);
						}
						else
						{
							_logger.Log(EVerbosity.Debug, $"OAuth2 Provider={Provider} state={state} code={code} but id_token exchange failed");
						}
					}
					else
					{
						_logger.Log(EVerbosity.Debug, $"OAuth2 Provider={Provider} state={state} but no code was set in the query");
					}
				}
				catch {}
			}
			return (null, null, null, null, null, null);
		}

		// authstring is a JWT that is cracked into parts.  If it's invalid, accountId is returned null.  Otherwise you get a valid accountId and non-null roles.
		// Full name and email may or may not be set, so be prepared to fall back to accountId to display something, but always trust accountId is a unique string.
		private (string?, string?, string?, string[]?) Authenticate(string? jwt)
		{
			string?   accountId = null;
			string?   fullName  = null;
			string?   email     = null;
			string[]? roles     = null;

			// small clock skew allowance
			const int expLeewaySeconds = 300;

			try
			{
				if (string.IsNullOrEmpty(jwt))
				{
					_logger.Log(EVerbosity.Error, "JWT is null or empty");
					return (null, null, null, null);
				}

				// Normalize raw token -- strip Bearer and surrounding whitespace only
				string token = jwt.Trim();
				if (token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
					token = token.Substring("Bearer ".Length).Trim();

				// Locate the dots and slice exact compact segments
				int dot1 = token.IndexOf('.');
				int dot2 = (dot1 >= 0) ? token.IndexOf('.', dot1 + 1) : -1;

				if (dot1 <= 0 || dot2 <= dot1 + 1 || dot2 >= token.Length - 1)
				{
					_logger.Log(EVerbosity.Error, $"Invalid JWT format -- dot positions dot1={dot1}, dot2={dot2}, tokenLen={token.Length}");
					return (null, null, null, null);
				}

				string header = token.Substring(0, dot1);
				string payload = token.Substring(dot1 + 1, dot2 - dot1 - 1);
				string signature = token.Substring(dot2 + 1);

				// Quick inner-whitespace detection
				if (HasInnerWhitespace(header) || HasInnerWhitespace(payload) || HasInnerWhitespace(signature))
				{
					_logger.Log(EVerbosity.Error, "JWT contains whitespace characters inside one or more segments -- likely header folding or proxy wrapping");
					LogSegmentDiagnostics(header, payload, signature, token, dot1, dot2);
					return (null, null, null, null);
				}

				// Validate base64url alphabet
				if (!IsBase64Url(header) || !IsBase64Url(payload) || !IsBase64Url(signature))
				{
					_logger.Log(EVerbosity.Error, "One or more JWT segments contain non-base64url characters [-_A-Za-z0-9]");
					LogSegmentDiagnostics(header, payload, signature, token, dot1, dot2);
					return (null, null, null, null);
				}

				// Decode header/payload for claims and kid
				string decodedHeader, decodedPayload;
				try
				{
					decodedHeader = UrlHelper.Base64UrlDecode(header);
					decodedPayload = UrlHelper.Base64UrlDecode(payload);
				}
				catch (Exception ex)
				{
					_logger.Log(EVerbosity.Error, $"Failed to base64url-decode header/payload -- {ex.GetType().Name}: {ex.Message}");
					LogSegmentDiagnostics(header, payload, signature, token, dot1, dot2);
					return (null, null, null, null);
				}

				JwtHeader? jwtheader = null;
				JwtPayload? jwtpayload = null;
				try
				{
					jwtheader = JsonSerializer.Deserialize(decodedHeader, TinyLinks.TinyLinksJsonContext.Default.JwtHeader);
					jwtpayload = JsonSerializer.Deserialize(decodedPayload, TinyLinks.TinyLinksJsonContext.Default.UpstreamJwtPayload);
				}
				catch (Exception ex)
				{
					_logger.Log(EVerbosity.Error, $"Failed to JSON-deserialize header/payload -- {ex.GetType().Name}: {ex.Message}\nHeaderJsonPreview={Preview(decodedHeader)}\nPayloadJsonPreview={Preview(decodedPayload)}");
					return (null, null, null, null);
				}

				if (jwtheader == null || jwtpayload == null)
				{
					_logger.Log(EVerbosity.Error, "JWT header or payload deserialized to null");
					return (null, null, null, null);
				}

				// alg sanity
//				if (!string.Equals(jwtheader.alg, "RS256", StringComparison.Ordinal))
//				{
//					_logger.Log(EVerbosity.Error, $"Unsupported alg in JWT header -- alg={jwtheader.alg ?? "null"} expected=RS256");
//					return (null, null, null, null);
//				}

				if (jwtheader.kid == null)
				{
					_logger.Log(EVerbosity.Error, $"JWT header does not contain kid. HeaderJson={Preview(decodedHeader)}");
					return (null, null, null, null);
				}

				if (!_publicKeys.TryGetValue(jwtheader.kid, out RSA? rsa) || rsa == null)
				{
					_logger.Log(EVerbosity.Error, $"Public key not found for kid={jwtheader.kid}");
					return (null, null, null, null);
				}

				try
				{
					// Build the exact signing input from the original token bytes
					string signingInputStr = token.Substring(0, dot2);

					byte[] signingInputAscii = Encoding.ASCII.GetBytes(signingInputStr);
					byte[] signingInputUtf8  = Encoding.UTF8.GetBytes(signingInputStr); // diagnostic A/B

					byte[] signatureBytes;
					try
					{
						signatureBytes = UrlHelper.Base64UrlDecodeBytes(signature); // ensure this adds padding properly
					}
					catch (Exception ex)
					{
						_logger.Log(EVerbosity.Error, $"Failed to base64url-decode signature -- {ex.GetType().Name}: {ex.Message}");
						LogSegmentDiagnostics(header, payload, signature, token, dot1, dot2);
						return (null, null, null, null);
					}

					// Key diagnostics
					try
					{
						var rsaParams = rsa.ExportParameters(false);
						int keyBits = rsaParams.Modulus?.Length > 0 ? rsaParams.Modulus.Length * 8 : -1;
						_logger.Log(EVerbosity.Info, $"Using RSA key kid={jwtheader.kid} size={keyBits} bits");
					}
					catch
					{
						_logger.Log(EVerbosity.Info, $"Using RSA key kid={jwtheader.kid} (size unavailable)");
					}

					// Hash and length diagnostics
					string shaAscii = BytesToHex(SHA256.HashData(signingInputAscii));
					string shaUtf8  = BytesToHex(SHA256.HashData(signingInputUtf8));

					_logger.Log(EVerbosity.Info, $"JWT diagnostics -- dot1={dot1}, dot2={dot2}, tokenLen={token.Length}, headerLen={header.Length}, payloadLen={payload.Length}, sigB64UrlLen={signature.Length}, sigBytesLen={signatureBytes.Length}");
					_logger.Log(EVerbosity.Info, $"SigningInput SHA256 (ASCII)={shaAscii}");
					if (!shaAscii.Equals(shaUtf8, StringComparison.Ordinal))
						_logger.Log(EVerbosity.Info, $"SigningInput SHA256 (UTF8) differs={shaUtf8} -- this would be unexpected for base64url content");

					// Verify signature (ASCII should be canonical)
					bool okAscii = rsa.VerifyData(signingInputAscii, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

					if (!okAscii)
					{
						// Try UTF8 purely as a diagnostic
						bool okUtf8 = rsa.VerifyData(signingInputUtf8, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
						_logger.Log(EVerbosity.Error, $"Invalid signature -- okAscii={okAscii}, okUtf8={okUtf8}, sigFirst8={BytesToHex(signatureBytes.AsSpan(0, Math.Min(8, signatureBytes.Length)).ToArray())}");
						LogSegmentDiagnostics(header, payload, signature, token, dot1, dot2);
						return (null, null, null, null);
					}

					long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
					long exp = jwtpayload.exp;
					if (exp <= 0)
					{
						_logger.Log(EVerbosity.Error, $"JWT payload missing or invalid exp -- exp={exp}");
						return (null, null, null, null);
					}

					if (exp + expLeewaySeconds <= now)
					{
						_logger.Log(EVerbosity.Error, $"JWT has expired -- now={now}, exp={exp}, leeway={expLeewaySeconds}");
						return (null, null, null, null);
					}

					string allGroups = jwtpayload.groups == null ? string.Empty : string.Join(' ', jwtpayload.groups);
					_logger.Log(EVerbosity.Info, $"Successful authentication for {jwtpayload.sub} {jwtpayload.email ?? "NO-EMAIL"} {jwtpayload.name ?? "NO-NAME"} {allGroups}");

					accountId = jwtpayload.sub;
					fullName  = jwtpayload.name;
					email     = jwtpayload.email;
					roles     = jwtpayload.groups ?? Array.Empty<string>();
				}
				catch (CryptographicException cex)
				{
					_logger.Log(EVerbosity.Error, $"Cryptographic failure during signature verification -- {cex.GetType().Name}: {cex.Message}");
					return (null, null, null, null);
				}
			}
			catch (Exception ex)
			{
				_logger.Log(EVerbosity.Error, $"JWT Validation threw an exception {ex}");
			}

			return (accountId, fullName, email, roles);

			// local helpers
			static bool HasInnerWhitespace(string s) => s.IndexOfAny(new[] { ' ', '\t', '\r', '\n' }) >= 0;

			static bool IsBase64Url(string s)
			{
				foreach (char ch in s)
				{
					bool ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
					if (!ok) return false;
				}
				return true;
			}

			static string Preview(string s)
			{
				const int n = 200;
				string p = s.Length <= n ? s : s.Substring(0, n) + "...";
				return p.Replace("\r", "\\r").Replace("\n", "\\n");
			}

			static string BytesToHex(byte[] bytes)
			{
				var sb = new StringBuilder(bytes.Length * 2);
				foreach (var b in bytes) sb.Append(b.ToString("X2"));
				return sb.ToString();
			}
		}
		private void LogSegmentDiagnostics(string header, string payload, string signature, string token, int dot1, int dot2)
		{
			_logger.Log(EVerbosity.Info,
				$"[JWT Diagnostics]\n" +
				$"  tokenLen={token.Length}, dot1={dot1}, dot2={dot2}\n" +
				$"  headerLen={header.Length}, payloadLen={payload.Length}, signatureLen={signature.Length}\n" +
				$"  headerFirst20={(header.Length > 20 ? header.Substring(0, 20) + "..." : header)}\n" +
				$"  payloadFirst20={(payload.Length > 20 ? payload.Substring(0, 20) + "..." : payload)}\n" +
				$"  signatureFirst20={(signature.Length > 20 ? signature.Substring(0, 20) + "..." : signature)}");

			// Extra: show whether segments contain whitespace or non-base64url chars
			_logger.Log(EVerbosity.Info,
				$"  headerHasWS={ContainsWS(header)}, payloadHasWS={ContainsWS(payload)}, sigHasWS={ContainsWS(signature)}");

			static bool ContainsWS(string s) => s.IndexOfAny(new[] { ' ', '\t', '\r', '\n' }) >= 0;
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
						JwtResponse? jwtResponse = JsonSerializer.Deserialize(responseBody, TinyLinks.TinyLinksJsonContext.Default.JwtResponse);
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

		internal class JwtHeader
		{
			public string? kid { get; set; }   // this indicates what public key was used for signing
		}

		internal class JwtPayload
		{
			public string?   iss           { get; set; }  // this is supposed to always be our fusionauth/authentik server, but authentik doesn't let you configure what it returns so we can't really use it
//			public string?   aud           { get; set; }  // authentik: returns the clientid that authenticated this user.  "thisisaclientid" is what we are using currently  SIWE-OIDC returns this as an array, which breaks deserialization.
			public long      exp           { get; set; }  // this is the expiration time for the JWT
			public long      iat           { get; set; }  // this is the time this JWT was issued at
			public string?   sub           { get; set; }  // this is the userid
			public string?   email         { get; set; }  // this should be something we receive
			public bool      emailVerified { get; set; }  // if true, the email link was clicked
			public string?   name          { get; set; }  // Full name
			public string[]? groups        { get; set; }  // authentik
		}

		internal class JwtResponse
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
