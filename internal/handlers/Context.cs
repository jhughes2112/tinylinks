using Tinylinks.Auth;
using Tinylinks.Types;

namespace Tinylinks.Handlers
{
    public partial class Handlers
    {
        public void AppContextHandler(Auth.Context ctx)
        {
            var configuredProviders = Providers.GetConfiguredProviders();
            var appContext = new AppContext
            {
                Status = 200,
                Message = "OK",
                ConfiguredProviders = configuredProviders,
                DisableContinue = Config.DisableContinue,
                Title = Config.Title,
                GenericName = Config.GenericName,
                Domain = Config.Domain,
                BackgroundImage = Config.BackgroundImage,
                OAuthAutoRedirect = Config.OAuthAutoRedirect
            };
            ctx.JSON(200, appContext);
        }

        public void UserContextHandler(Auth.Context ctx)
        {
            var userContext = Hooks.UseUserContext(ctx);
            var response = new UserContextResponse
            {
                Status = 200,
                IsLoggedIn = userContext.IsLoggedIn,
                Username = userContext.Username,
                Name = userContext.Name,
                Email = userContext.Email,
                Provider = userContext.Provider,
                Oauth = userContext.OAuth
            };
            if (!userContext.IsLoggedIn)
            {
                response.Message = "Unauthorized";
            }
            else
            {
                response.Message = "Authenticated";
            }
            ctx.JSON(200, response);
        }
    }
}
