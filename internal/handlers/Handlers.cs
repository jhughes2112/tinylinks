using System;
using System.Collections.Generic;
using Tinylinks.Auth;
using Tinylinks.Types;
using Tinylinks.Hooks;
using Tinylinks.Providers;
using Tinylinks.Docker;
using Tinylinks.Linkdb;

namespace Tinylinks.Handlers
{
    public partial class Handlers
    {
        public HandlersConfig Config;
        public Auth Auth;
        public Hooks Hooks;
        public Providers Providers;
        public Docker Docker;
        public LinkDB LinkDB;

        private readonly Dictionary<string, byte> admin;
        private readonly object codeMu = new object();
        private readonly Dictionary<string, CodeEntry> codes;

        public struct CodeEntry
        {
            public string Issuer;
            public DateTime Expires;
        }

        public Handlers(HandlersConfig config, Auth auth, Hooks hooks, Providers providers, Docker docker, LinkDB db, string[] admins)
        {
            Config = config;
            Auth = auth;
            Hooks = hooks;
            Providers = providers;
            Docker = docker;
            LinkDB = db;
            admin = new Dictionary<string, byte>();
            if (admins != null)
            {
                foreach (var e in admins)
                {
                    var lower = (e ?? string.Empty).Trim().ToLowerInvariant();
                    if (lower != string.Empty && !admin.ContainsKey(lower))
                    {
                        admin[lower] = 0;
                    }
                }
            }
            codes = new Dictionary<string, CodeEntry>();
        }

        public void HealthcheckHandler(Auth.Context ctx)
        {
            ctx.JSON(200, new { status = 200, message = "OK" });
        }

        public bool IsAdmin(string email)
        {
            if (email == null) return false;
            return admin.ContainsKey(email.ToLowerInvariant());
        }
}
