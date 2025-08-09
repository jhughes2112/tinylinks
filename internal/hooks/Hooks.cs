using System;
using Tinylinks.Auth;
using Tinylinks.Types;
using Tinylinks.Handlers; // using placeholder Providers

namespace Tinylinks.Hooks
{
    public class Hooks
    {
        public HooksConfig Config { get; set; }
        public Auth Auth { get; set; }
        public Providers Providers { get; set; }

        public Hooks(HooksConfig config, Auth auth, Providers providers)
        {
            Config = config;
            Auth = auth;
            Providers = providers;
        }

        public UserContext UseUserContext(Auth.Context ctx)
        {
            var cookie = Auth.GetSessionCookie(ctx);
            if (cookie == null || string.IsNullOrEmpty(cookie.Provider))
            {
                Console.Error.WriteLine("Session cookie missing or provider undefined");
                return new UserContext();
            }

            var provider = Providers.GetProvider(cookie.Provider);
            if (provider == null)
            {
                return new UserContext();
            }

            return new UserContext
            {
                Username = cookie.Username,
                Name = cookie.Name,
                Email = cookie.Email,
                IsLoggedIn = true,
                OAuth = true,
                Provider = cookie.Provider,
                OAuthGroups = cookie.OAuthGroups,
            };
        }
    }
}
