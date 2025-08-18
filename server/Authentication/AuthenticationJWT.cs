using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Logging;
using System.Text.Json;
using Shared;
using System.Net.Http;
using System.Threading.Tasks;

namespace Authentication
{
	// This checks that the JWT was signed by the correct private key, and also supports building OIDC authorize URLs and code exchange.
	public class AuthenticationJWT : IAuthentication
	{
		private readonly Dictionary<string, RSA> _publicKeys;
		private readonly ILogging                _logger;

		// OIDC / OAuth2 provider metadata
		public string Provider { get; private set; } = string.Empty;
		private readonly string? _authorizationEndpoint;
		private readonly string? _tokenEndpoint;
		private readonly string? _clientId;
		private readonly string? _clientSecret;

		public AuthenticationJWT(Dictionary<string, RSA> publicKeys, ILogging logger)
		{
			_publicKeys = publicKeys;
			_logger     = logger;
		}

		public AuthenticationJWT(string provider, string authorizationEndpoint, string tokenEndpoint, string clientId, string? clientSecret, Dictionary<string, RSA> publicKeys, ILogging logger)
		{
			Provider = provider ?? string.Empty;
			_authorizationEndpoint = authorizationEndpoint;
			_tokenEndpoint = tokenEndpoint;
			_clientId = clientId;
			_clientSecret = clientSecret;
			_publicKeys = publicKeys;
			_logger = logger;
		}

		// Call this with httpListenerContext.Request.Headers.GetValues("Authorization");
		public (string?, string?, string?, string[]?) AuthenticateRequest(string[]? authorizationHeaders)
		{
			string? token = null;
			if (authorizationHeaders != null && authorizationHeaders.Length > 0)
			{
				token = authorizationHeaders[0];
				if (token!=null && token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
				{
					token = token.Substring("Bearer ".Length).Trim();
				}
			}
			return Authenticate(token);
		}

		// Actual functionality of the JWT validation uses the RSA key list
		// (accountId, full name, email, roles[])
		public (string?, string?, string?, string[]?) Authenticate(string? jwt)
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

		public string BuildAuthorizeUrl(string redirectUri, string state, string codeChallenge)
		{
			if (string.IsNullOrEmpty(_authorizationEndpoint) || string.IsNullOrEmpty(_clientId))
				throw new InvalidOperationException("Authorization endpoint or client id not configured for this provider.");

			string url = string.Format("{0}?response_type=code&scope=openid+profile+email&redirect_uri={1}&client_id={2}&state={3}&code_challenge={4}&code_challenge_method=S256",
				_authorizationEndpoint,
				Uri.EscapeDataString(redirectUri),
				Uri.EscapeDataString(_clientId),
				Uri.EscapeDataString(state),
				Uri.EscapeDataString(codeChallenge)
			);
			return url;
		}

		// Exchange an authorization code for a JWT using the given code_verifier, returns the id_token which has three parts and most of the important details (accountId, full name, email, roles[]).
		public async Task<string?> ExchangeCodeForJwtAsync(string code, string redirectUri, string codeVerifier)
		{
			if (string.IsNullOrEmpty(_tokenEndpoint) || string.IsNullOrEmpty(_clientId))
				throw new InvalidOperationException("Token endpoint or client id not configured for this provider.");

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
