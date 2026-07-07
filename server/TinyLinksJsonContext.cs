using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace TinyLinks
{
	// Source-generated System.Text.Json metadata so the app works under NativeAOT (no runtime reflection).
	// Every type that passes through JsonSerializer must be registered here, including the runtime types
	// of values stored in Dictionary<string, object?> payloads (string, long, int, string[], nested dicts).
	[JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Metadata)]
	[JsonSerializable(typeof(Dictionary<string, object?>))]
	[JsonSerializable(typeof(Dictionary<string, object?>[]))]
	[JsonSerializable(typeof(string))]
	[JsonSerializable(typeof(long))]
	[JsonSerializable(typeof(int))]
	[JsonSerializable(typeof(bool))]
	[JsonSerializable(typeof(string[]))]
	[JsonSerializable(typeof(Utilities.JwtPayload), TypeInfoPropertyName = "ServerJwtPayload")]
	[JsonSerializable(typeof(Authentication.OAuth2Helper.OAuthConfiguration))]
	[JsonSerializable(typeof(Authentication.OAuth2Helper.KeySet))]
	[JsonSerializable(typeof(Authentication.AuthenticationOAuth2.JwtHeader))]
	[JsonSerializable(typeof(Authentication.AuthenticationOAuth2.JwtPayload), TypeInfoPropertyName = "UpstreamJwtPayload")]
	[JsonSerializable(typeof(Authentication.AuthenticationOAuth2.JwtResponse))]
	[JsonSerializable(typeof(Authentication.AuthenticationDiscord.DiscordTokenResponse))]
	[JsonSerializable(typeof(Authentication.AuthenticationDiscord.DiscordUserResponse))]
	internal partial class TinyLinksJsonContext : JsonSerializerContext
	{
	}
}
