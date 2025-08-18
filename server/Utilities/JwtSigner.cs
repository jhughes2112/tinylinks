using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Shared;

namespace Utilities
{
	public sealed class JwtSigner
	{
		private readonly RSA _rsa;
		private readonly string _kid;

		public JwtSigner()
		{
			_rsa = RSA.Create(2048);
			RSAParameters p = _rsa.ExportParameters(false);
			using var sha = SHA256.Create();
			byte[] hash = sha.ComputeHash(p.Modulus!);
			_kid = UrlHelper.Base64UrlEncodeNoPadding(hash.AsSpan(0, 8).ToArray());
		}

		public string Kid => _kid;

		// Create a general JWT given arbitrary claims
		public string CreateToken(Dictionary<string, object?> claims, string issuer)
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

		// Helper to mint the TinyLinks downstream token with standard claims expected by downstream services
		public string CreateServerJWT(Uri issuerBase, string provider, string upstreamSub, string? email, string[]? roles, long exp)
		{
			string sub = provider + "_" + upstreamSub;
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
			return CreateToken(claims, issuerBase.AbsoluteUri.TrimEnd('/'));
		}

		// Helper to mint with an explicit full sub (used for link override)
		public string CreateServerJWTWithSub(Uri issuerBase, string sub, string? email, string[]? roles, long exp)
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
			return CreateToken(claims, issuerBase.AbsoluteUri.TrimEnd('/'));
		}

		// Validate signature and return payload JSON
		public bool TryValidate(string token, out string payloadJson)
		{
			payloadJson = string.Empty;
			try
			{
				string[] parts = token.Split('.');
				if (parts.Length != 3) return false;
				byte[] data = Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]);
				byte[] sig  = UrlHelper.Base64UrlDecodeBytes(parts[2]);
				bool ok = _rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
				if (!ok) return false;
				payloadJson = Encoding.UTF8.GetString(UrlHelper.Base64UrlDecodeBytes(parts[1]));
				return true;
			}
			catch { return false; }
		}

		// Validate and parse into a typed payload object
		public bool TryValidate(string token, out JwtPayload? payload)
		{
			payload = null;
			if (!TryValidate(token, out string payloadJson)) return false;
			try
			{
				payload = JsonSerializer.Deserialize<JwtPayload>(payloadJson);
				return payload != null;
			}
			catch { return false; }
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
