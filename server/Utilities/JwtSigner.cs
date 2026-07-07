using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Logging;
using Shared;

namespace Utilities
{
	public sealed class JwtSigner
	{
		private readonly RSA _rsa;
		private readonly string _kid;

		// Loads the RSA signing key from keyFilePath if it exists, otherwise generates a fresh key and persists it (PKCS#8 PEM).
		// Persisting the key keeps sessions/JWKS stable across restarts, and lets multiple instances share one signing key.
		// If keyFilePath is null/empty, the key is ephemeral (regenerated every start) - fine for single-instance dev only.
		public JwtSigner(string? keyFilePath, ILogging logger)
		{
			RSA? loaded = null;
			if (!string.IsNullOrWhiteSpace(keyFilePath) && File.Exists(keyFilePath))
			{
				try
				{
					RSA rsa = RSA.Create();
					rsa.ImportFromPem(File.ReadAllText(keyFilePath));
					loaded = rsa;
					logger.Log(EVerbosity.Info, $"JwtSigner loaded signing key from {keyFilePath}");
				}
				catch (Exception e)
				{
					logger.Log(EVerbosity.Error, $"JwtSigner failed to load key from {keyFilePath}, generating a new one: {e.Message}");
				}
			}

			if (loaded == null)
			{
				loaded = RSA.Create(2048);
				if (!string.IsNullOrWhiteSpace(keyFilePath))
				{
					try
					{
						string? dir = Path.GetDirectoryName(Path.GetFullPath(keyFilePath));
						if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
						File.WriteAllText(keyFilePath, loaded.ExportPkcs8PrivateKeyPem());
						if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
						{
							try { File.SetUnixFileMode(keyFilePath, UnixFileMode.UserRead | UnixFileMode.UserWrite); } catch { }
						}
						logger.Log(EVerbosity.Info, $"JwtSigner generated and persisted a new signing key at {keyFilePath}");
					}
					catch (Exception e)
					{
						logger.Log(EVerbosity.Error, $"JwtSigner could not persist signing key to {keyFilePath}: {e.Message}");
					}
				}
				else
				{
					logger.Log(EVerbosity.Warning, "JwtSigner using an ephemeral signing key (no --jwt_key_file); sessions will not survive a restart.");
				}
			}

			_rsa = loaded;
			RSAParameters p = _rsa.ExportParameters(false);
			using var sha = SHA256.Create();
			byte[] hash = sha.ComputeHash(p.Modulus!);
			_kid = UrlHelper.Base64UrlEncodeNoPadding(hash.AsSpan(0, 8).ToArray());
		}

		public string Kid => _kid;

		// Create a general JWT given arbitrary claims
		private string CreateToken(Dictionary<string, object?> claims, string issuer)
		{
			var header = new Dictionary<string, object>
			{
				{"alg", "RS256"},
				{"typ", "JWT"},
				{"kid", _kid}
			};
			string headerJson = JsonSerializer.Serialize(header);
			string headerB64 = UrlHelper.Base64UrlEncodeNoPadding(Encoding.UTF8.GetBytes(headerJson));

			if (!claims.ContainsKey("iss")) claims["iss"] = issuer;
			string payloadJson = JsonSerializer.Serialize(claims);
			string payloadB64 = UrlHelper.Base64UrlEncodeNoPadding(Encoding.UTF8.GetBytes(payloadJson));

			string signingInput = headerB64 + "." + payloadB64;
			byte[] data = Encoding.UTF8.GetBytes(signingInput);
			byte[] sig = _rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
			string sigB64 = UrlHelper.Base64UrlEncodeNoPadding(sig);
			return signingInput + "." + sigB64;
		}

		// Helper to mint with an explicit full sub (used for link override)
		public string CreateServerJWT(Uri issuerBase, string sub, string? email, string[]? roles, long exp, string? aud, string? nonce)
		{
			long iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
			var claims = new Dictionary<string, object?>
			{
				{"iss", issuerBase.AbsoluteUri.TrimEnd('/')},
				{"sub", sub},
				{"exp", exp},
				{"iat", iat},
				{"email", email},
				{"roles", roles ?? Array.Empty<string>()}
			};
			if (!string.IsNullOrEmpty(aud))   claims["aud"]   = aud;
			if (!string.IsNullOrEmpty(nonce)) claims["nonce"] = nonce;
			return CreateToken(claims, issuerBase.AbsoluteUri.TrimEnd('/'));
		}

		// Validate and parse into a typed payload object
		public bool TryValidate(string token, out JwtPayload? payload)
		{
			try
			{
				string[] parts = token.Split('.');
				if (parts.Length == 3) 
				{
					byte[] data = Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]);
					byte[] sig  = UrlHelper.Base64UrlDecodeBytes(parts[2]);
					if (_rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
					{
						string payloadJson = Encoding.UTF8.GetString(UrlHelper.Base64UrlDecodeBytes(parts[1]));
						payload = JsonSerializer.Deserialize<JwtPayload>(payloadJson);
						return payload != null;
					}
				}
			}
			catch { }
			payload = null;
			return false;
		}

		public (string n, string e) GetPublicKeyComponents()
		{
			RSAParameters p = _rsa.ExportParameters(false);
			return (UrlHelper.Base64UrlEncodeNoPadding(p.Modulus!), UrlHelper.Base64UrlEncodeNoPadding(p.Exponent!));
		}
	}

	public sealed class JwtPayload
	{
		public string? iss { get; set; }
		public string? sub { get; set; }
		public long exp { get; set; }
		public long iat { get; set; }
		public string? email { get; set; }
		public string[] roles { get; set; } = Array.Empty<string>();

		public bool HasExpired()
		{
			long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
			return now >= exp;
		}
	}
}
