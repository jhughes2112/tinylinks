using System;
using System.Net.Http;

namespace Tinylinks.OAuth
{
    public class OAuthConfigItem
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string AuthURL { get; set; }
        public string TokenURL { get; set; }
        public string[] Scopes { get; set; }
    }

    public class OAuth
    {
        public OAuthConfigItem Config;
        public HttpClient Client;
        public string Token;
        public string Verifier;

        public OAuth(OAuthConfigItem config)
        {
            Config = config;
            Client = new HttpClient();
            Verifier = Guid.NewGuid().ToString("N");
        }

        public string GetAuthURL(string state)
        {
            var scope = Config.Scopes != null ? string.Join(" ", Config.Scopes) : string.Empty;
            return string.Format("{0}?client_id={1}&response_type=code&scope={2}&state={3}",
                Config.AuthURL,
                Uri.EscapeDataString(Config.ClientId),
                Uri.EscapeDataString(scope),
                Uri.EscapeDataString(state));
        }

        public string ExchangeToken(string code)
        {
            return string.Empty;
        }

        public HttpClient GetClient()
        {
            return Client;
        }

        public string GenerateState()
        {
            return Guid.NewGuid().ToString("N");
        }
    }
}
