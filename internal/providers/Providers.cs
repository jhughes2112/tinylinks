using System.Collections.Generic;
using Tinylinks.Constants;
using Tinylinks.OAuth;
using Tinylinks.Types;

namespace Tinylinks.Providers
{
    public class Providers
    {
        public OAuthConfig Config;
        public OAuth.OAuth Github;
        public OAuth.OAuth Google;
        public OAuth.OAuth Generic;

        public Providers(OAuthConfig config)
        {
            Config = config;
            if (!string.IsNullOrEmpty(config.GithubClientId))
            {
                Github = new OAuth.OAuth(new OAuth.OAuthConfigItem
                {
                    ClientId = config.GithubClientId,
                    ClientSecret = config.GithubClientSecret,
                    AuthURL = "https://github.com/login/oauth/authorize"
                });
            }
            if (!string.IsNullOrEmpty(config.GoogleClientId))
            {
                Google = new OAuth.OAuth(new OAuth.OAuthConfigItem
                {
                    ClientId = config.GoogleClientId,
                    ClientSecret = config.GoogleClientSecret,
                    AuthURL = "https://accounts.google.com/o/oauth2/v2/auth"
                });
            }
            if (!string.IsNullOrEmpty(config.GenericClientId))
            {
                Generic = new OAuth.OAuth(new OAuth.OAuthConfigItem
                {
                    ClientId = config.GenericClientId,
                    ClientSecret = config.GenericClientSecret,
                    AuthURL = config.GenericAuthURL,
                    TokenURL = config.GenericTokenURL,
                    Scopes = config.GenericScopes
                });
            }
        }

        public OAuth.OAuth GetProvider(string name)
        {
            switch (name)
            {
                case "github": return Github;
                case "google": return Google;
                case "generic": return Generic;
                default: return null;
            }
        }

        public Claims GetUser(string provider)
        {
            return new Claims();
        }

        public string[] GetConfiguredProviders()
        {
            var list = new List<string>();
            if (Github != null) list.Add("github");
            if (Google != null) list.Add("google");
            if (Generic != null) list.Add("generic");
            return list.ToArray();
        }
    }
}
