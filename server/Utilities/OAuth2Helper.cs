using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Net.Http;
using System.Threading.Tasks;
using Logging;
using Shared;
using System.Text.Json;

namespace Authentication
{
	// utility class to handle fetching and caching data.  This is used on both client and server.
	public class OAuth2Helper
	{
		private Dictionary<string, OAuthConfiguration?>     _urlToConfig = new Dictionary<string, OAuthConfiguration?>();
		private Dictionary<string, Dictionary<string, RSA>> _publicKeys  = new Dictionary<string, Dictionary<string, RSA>>();
		private ILogging _logger;

		public OAuth2Helper(ILogging logger)
		{
			_logger     = logger;
		}

		// This grabs the current public key from an OAuth2 server from the well-known address.  If this fails, you get null
	    // Example: https://accounts.google.com/.well-known/openid-configuration
		public async Task<OAuthConfiguration?> Fetch(string url)
		{
			if (_urlToConfig.TryGetValue(url, out OAuthConfiguration? config)==false)
			{
				const int kRetries = 6;
				for (int i=0; i<kRetries; i++)
				{
					using (HttpClient client = new HttpClient())
					{
						client.Timeout = TimeSpan.FromSeconds(5);

						// Fetch the OpenID Connect discovery document
						try
						{
							string discoveryResponse = await client.GetStringAsync(url).ConfigureAwait(false);
							config = JsonSerializer.Deserialize<OAuthConfiguration>(discoveryResponse);
							break;
						}
						catch (Exception e)
						{
							_logger.Log(EVerbosity.Error, $"Oauth2Helper.Fetch trying to retrieve {url} attempt {i} caught exception: {e}");
							await Task.Delay(10000).ConfigureAwait(false);  // wait a while, then re-try
						}
					}
				}
				_urlToConfig.Add(url, config);  // This may be null.  Better to stop trying to fetch it if it's already failed though.
			}
			return config;
		}

		// Convenience method: returns the authorization and token endpoints from discovery.
		public async Task<(string? authorization_endpoint, string? token_endpoint)> GetEndpoints(string discoveryUrl)
		{
			OAuthConfiguration? config = await Fetch(discoveryUrl).ConfigureAwait(false);
			if (config == null)
			{
				_logger.Log(EVerbosity.Error, $"OAuth2Helper.GetEndpoints config is null for {discoveryUrl}");
				return (null, null);
			}
			if (string.IsNullOrWhiteSpace(config.authorization_endpoint) || string.IsNullOrWhiteSpace(config.token_endpoint))
			{
				_logger.Log(EVerbosity.Error, $"OAuth2Helper.GetEndpoints missing endpoints for {discoveryUrl} auth={config.authorization_endpoint ?? "<null>"} token={config.token_endpoint ?? "<null>"}");
			}
			return (config.authorization_endpoint, config.token_endpoint);
		}

		// Returns null if this fails for any reason.
		public async Task<Dictionary<string, RSA>?> GetPublicKeys(string discoveryUrl)
		{
			Dictionary<string, RSA>? keys = null;
			OAuthConfiguration? config = await Fetch(discoveryUrl).ConfigureAwait(false);
			if (config!=null)
			{
				if (string.IsNullOrEmpty(config.jwks_uri)==false)
				{
					if (_publicKeys.TryGetValue(config.jwks_uri, out keys)==false)
					{
						// Create the dictionary so we don't ever retrieve this url again, even if it's missing/empty.
						keys = new Dictionary<string, RSA>();

						// Actually fetch it then
						using (HttpClient client = new HttpClient())
						{
							try
							{
								client.Timeout = TimeSpan.FromSeconds(5);
								string jwksResponse = await client.GetStringAsync(config.jwks_uri).ConfigureAwait(false);
								KeySet? jwksData = JsonSerializer.Deserialize<KeySet>(jwksResponse);
								if (jwksData!=null && jwksData.keys!=null)
								{
									// Parse the keys
									foreach (Key k in jwksData.keys)
									{
										if (k.kid!=null && k.n!=null && k.e!=null)
										{
											RSAParameters rsa = new RSAParameters
											{
												Modulus = UrlHelper.Base64UrlDecodeBytes(k.n),
												Exponent = UrlHelper.Base64UrlDecodeBytes(k.e)
											};

											RSA rsaKey = RSA.Create();
											rsaKey.ImportParameters(rsa);
											keys.Add(k.kid, rsaKey);
										}
										else
										{
											_logger.Log(EVerbosity.Error, $"OAuth2Helper.GetPublicKeys key has at least one null in its data {jwksResponse}");
										}
									}
								}
								else
								{
									_logger.Log(EVerbosity.Error, $"OAuth2Helper.GetPublicKeys jwksData did not parse properly: {jwksResponse}");
								}
							}
							catch (Exception e)
							{
								_logger.Log(EVerbosity.Error, $"OAuth2Helper.GetPublicKeys caught exception getting public keys {config.jwks_uri} {e}");
							}
							finally
							{
								_publicKeys.Add(config.jwks_uri, keys);  // cache for future use
							}
						}
					}
					// the else case here is we fetched the cached version and quickly return keys
				}
				else
				{
					_logger.Log(EVerbosity.Error, $"OAuth2Helper.GetPublicKeys jwks_uri is null for {discoveryUrl}");
				}
			}
			else
			{
				_logger.Log(EVerbosity.Error, $"OAuth2Helper.GetPublicKeys config is null for {discoveryUrl}");
			}
			return keys;
		}

		// Used only for deserializing and fetching the JwksUri, for the most part.  We assume the rest is setup as expected.
		public class OAuthConfiguration
		{
			public string? issuer { get; set; }
			public string? authorization_endpoint { get; set; }
			public string? device_authorization_endpoint { get; set; }
			public string? token_endpoint { get; set; }
			public string? userinfo_endpoint { get; set; }
			public string? revocation_endpoint { get; set; }
			public string? jwks_uri { get; set; }
			public List<string>? response_types_supported { get; set; }
			public List<string>? subject_types_supported { get; set; }
			public List<string>? id_token_signing_alg_values_supported { get; set; }
			public List<string>? scopes_supported { get; set; }
			public List<string>? token_endpoint_auth_methods_supported { get; set; }
			public List<string>? claims_supported { get; set; }
			public List<string>? code_challenge_methods_supported { get; set; }
			public List<string>? grant_types_supported { get; set; }
		}

		// RSA Keys
		public class Key
		{
			public string? e { get; set; }
			public string? use { get; set; }
			public string? n { get; set; }
			public string? kty { get; set; }
			public string? kid { get; set; }
			public string? alg { get; set; }
		}

		// This is the contents of the jwks_uri
		public class KeySet
		{
			public List<Key>? keys { get; set; }
		}
	}
}
