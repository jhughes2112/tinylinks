using Tinylinks.Auth;

namespace Tinylinks.Handlers
{
    public partial class Handlers
    {
        public void LogoutHandler(Auth.Context ctx)
        {
            Auth.DeleteSessionCookie(ctx);
            ctx.JSON(200, new { status = 200, message = "Logged out" });
        }
    }
}
