using Tinylinks.Auth;
using Tinylinks.Types;

namespace Tinylinks.Handlers
{
    public partial class Handlers
    {
        public void ProxyHandler(Auth.Context ctx)
        {
            ctx.JSON(501, new { status = 501, message = "proxy not implemented" });
        }
    }
}
