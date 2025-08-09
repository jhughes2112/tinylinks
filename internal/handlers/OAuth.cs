using System;
using Tinylinks.Auth;
using Tinylinks.Types;
using Tinylinks.Utils;

namespace Tinylinks.Handlers
{
    public partial class Handlers
    {
        public void OAuthURLHandler(Auth.Context ctx)
        {
            var request = new OAuthRequest { Provider = ctx.Query("provider") };
            var provider = Providers.GetProvider(request.Provider);
            if (provider == null)
            {
                ctx.JSON(404, new { status = 404, message = "not found" });
                return;
            }
            var state = provider.GenerateState();
            var authURL = provider.GetAuthURL(state);
            ctx.SetCookie(Config.CsrfCookieName, state, (int)TimeSpan.FromHours(1).TotalSeconds, "/", "", Config.CookieSecure, true);
            var redirectURI = ctx.Query("redirect_uri");
            if (!string.IsNullOrEmpty(redirectURI))
            {
                ctx.SetCookie(Config.RedirectCookieName, redirectURI, (int)TimeSpan.FromHours(1).TotalSeconds, "/", "", Config.CookieSecure, true);
            }
            ctx.JSON(200, new { status = 200, message = "OK", url = authURL });
        }

        public void OAuthCallbackHandler(Auth.Context ctx)
        {
            var providerName = new OAuthRequest { Provider = ctx.Query("provider") };
            var state = ctx.Query("state");
            var csrfCookie = ctx.GetCookie(Config.CsrfCookieName);
            if (csrfCookie == string.Empty || csrfCookie != state)
            {
                ctx.JSON(400, new { status = 400, message = "invalid csrf" });
                return;
            }
            ctx.SetCookie(Config.CsrfCookieName, string.Empty, -1, "/", "", Config.CookieSecure, true);
            var code = ctx.Query("code");
            var provider = Providers.GetProvider(providerName.Provider);
            if (provider == null)
            {
                ctx.JSON(404, new { status = 404, message = "not found" });
                return;
            }
            provider.ExchangeToken(code);
            var user = provider.GetUser();
            if (user == null || string.IsNullOrEmpty(user.Email))
            {
                ctx.JSON(400, new { status = 400, message = "invalid user" });
                return;
            }
            var username = !string.IsNullOrEmpty(user.PreferredUsername)
                ? user.PreferredUsername
                : string.Format("{0}_{1}", user.Email.Split('@')[0], user.Email.Split('@')[1]);
            var name = !string.IsNullOrEmpty(user.Name)
                ? user.Name
                : string.Format("{0} ({1})", Utils.Capitalize(user.Email.Split('@')[0]), user.Email.Split('@')[1]);
            Auth.CreateSessionCookie(ctx, new SessionCookie
            {
                Username = username,
                Name = name,
                Email = user.Email,
                Provider = providerName.Provider,
                OAuthGroups = Utils.CoalesceToString(user.Groups)
            });
            var redirectCookie = ctx.GetCookie(Config.RedirectCookieName);
            if (string.IsNullOrEmpty(redirectCookie))
            {
                ctx.JSON(200, new { status = 200, message = "OK" });
                return;
            }
            var continueUrl = string.Format("{0}/continue?redirect_uri={1}", Config.AppURL, Uri.EscapeDataString(redirectCookie));
            ctx.SetCookie(Config.RedirectCookieName, string.Empty, -1, "/", "", Config.CookieSecure, true);
            ctx.JSON(200, new { status = 200, message = "OK", url = continueUrl });
        }
    }
}
