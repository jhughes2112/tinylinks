using System;
using System.Text;
using System.Security.Cryptography;

namespace Shared
{
	static public class UrlHelper
	{
		// This lets you decode a URL that is base64 encoded.  Typically this happens in a JWT, but maybe useful elsewhere?
		static public string Base64UrlDecode(string input)
		{
			string output = input.Replace('-', '+').Replace('_', '/');
			switch (output.Length % 4) // Pad with trailing '='s
			{
				case 0: break; // No pad chars in this case
				case 2: output += "=="; break; // Two pad chars
				case 3: output += "="; break; // One pad char
				default: throw new System.Exception("Illegal base64url string!");
			}
			byte[] converted = Convert.FromBase64String(output); // Standard base64 decoder
			return Encoding.UTF8.GetString(converted);
		}

		// Base64url no-padding encodes the given input buffer.
		static public string Base64UrlEncodeNoPadding(byte[] buffer)
		{
			string base64 = Convert.ToBase64String(buffer);

			// Converts base64 to base64url.
			base64 = base64.Replace("+", "-");
			base64 = base64.Replace("/", "_");
			// Strips padding.
			base64 = base64.Replace("=", "");

			return base64;
		}

		// Returns URI-safe data with a given input length.
		static public string GenerateRandomDataBase64url(uint length)
		{
			byte[] bytes = new byte[length];
			RandomNumberGenerator.Fill(new Span<byte>(bytes));
			return Base64UrlEncodeNoPadding(bytes);
		}

		static public byte[] Base64UrlDecodeBytes(string input)
		{
			string output = input.Replace('-', '+').Replace('_', '/');
			switch (output.Length % 4)
			{
				case 0: break;
				case 2: output += "=="; break;
				case 3: output += "="; break;
				default: throw new Exception($"Illegal base64url string! {input}");
			}
			return Convert.FromBase64String(output);
		}

	}
}
