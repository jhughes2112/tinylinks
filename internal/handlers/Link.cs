using System;
using System.Collections.Generic;
using Tinylinks.Auth;

namespace Tinylinks.Handlers
{
    public partial class Handlers
    {
        private void CleanupCodes()
        {
            var now = DateTime.UtcNow;
            var remove = new List<string>();
            foreach (var pair in codes)
            {
                if (now > pair.Value.Expires)
                {
                    remove.Add(pair.Key);
                }
            }
            foreach (var key in remove)
            {
                codes.Remove(key);
            }
        }

        public void GetShortLinkHandler(Auth.Context ctx)
        {
            var user = Hooks.UseUserContext(ctx);
            if (!user.IsLoggedIn)
            {
                ctx.JSON(401, new { status = 401, message = "Unauthorized" });
                return;
            }
            string code;
            lock (codeMu)
            {
                CleanupCodes();
                code = Guid.NewGuid().ToString().Split('-')[0];
                codes[code] = new CodeEntry { Issuer = user.Username, Expires = DateTime.UtcNow.AddHours(1) };
            }
            ctx.JSON(200, new { code = code });
        }

        private class CodeRequest
        {
            public string Code { get; set; }
        }

        private class UnlinkRequest
        {
            public string A { get; set; }
            public string B { get; set; }
        }

        public void UseShortLinkHandler(Auth.Context ctx)
        {
            var user = Hooks.UseUserContext(ctx);
            if (!user.IsLoggedIn)
            {
                ctx.JSON(401, new { status = 401, message = "Unauthorized" });
                return;
            }
            CodeRequest req;
            if (!ctx.BindJSON<CodeRequest>(out req))
            {
                ctx.JSON(400, new { status = 400, message = "Bad Request" });
                return;
            }
            CodeEntry entry;
            lock (codeMu)
            {
                CleanupCodes();
                if (!codes.TryGetValue(req.Code, out entry))
                {
                    ctx.JSON(400, new { status = 400, message = "Invalid code" });
                    return;
                }
                codes.Remove(req.Code);
            }
            try
            {
                LinkDB.AddLink(entry.Issuer, user.Username);
            }
            catch (Exception)
            {
                ctx.JSON(500, new { status = 500, message = "Internal Server Error" });
                return;
            }
            ctx.JSON(200, new { status = 200, message = "Linked" });
        }

        public void GetLinkedAccountsHandler(Auth.Context ctx)
        {
            var user = Hooks.UseUserContext(ctx);
            if (!user.IsLoggedIn)
            {
                ctx.JSON(401, new { status = 401, message = "Unauthorized" });
                return;
            }
            string[] links;
            try
            {
                links = LinkDB.Get(user.Username);
            }
            catch (Exception)
            {
                ctx.JSON(500, new { status = 500, message = "Internal Server Error" });
                return;
            }
            ctx.JSON(200, new { accounts = links });
        }

        public void AdminShowLinkedAccountsHandler(Auth.Context ctx)
        {
            var user = Hooks.UseUserContext(ctx);
            if (!IsAdmin(user.Email))
            {
                ctx.JSON(403, new { status = 403, message = "Forbidden" });
                return;
            }
            var account = ctx.Query("account");
            string[] links;
            try
            {
                links = LinkDB.Get(account);
            }
            catch (Exception)
            {
                ctx.JSON(500, new { status = 500, message = "Internal Server Error" });
                return;
            }
            ctx.JSON(200, new { accounts = links });
        }

        public void AdminUnlinkAccountsHandler(Auth.Context ctx)
        {
            var user = Hooks.UseUserContext(ctx);
            if (!IsAdmin(user.Email))
            {
                ctx.JSON(403, new { status = 403, message = "Forbidden" });
                return;
            }
            UnlinkRequest req;
            if (!ctx.BindJSON<UnlinkRequest>(out req))
            {
                ctx.JSON(400, new { status = 400, message = "Bad Request" });
                return;
            }
            try
            {
                LinkDB.RemoveLink(req.A, req.B);
            }
            catch (Exception)
            {
                ctx.JSON(500, new { status = 500, message = "Internal Server Error" });
                return;
            }
            ctx.JSON(200, new { status = 200, message = "Unlinked" });
        }
    }
}
