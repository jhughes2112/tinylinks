using System;
using System.IO;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Tinylinks.Types;
using Tinylinks.Auth;
using Tinylinks.Handlers;
using Tinylinks.Hooks;
using Tinylinks.Providers;
using Tinylinks.Docker;
using Tinylinks.Linkdb;

namespace Tinylinks.Server
{
    public class Server
    {
        public ServerConfig Config;

        public Server(ServerConfig config)
        {
            Config = config;
        }

        public void Start(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            var app = builder.Build();

            var auth = new Auth.Auth(new AuthConfig { SessionCookieName = "session", SessionExpiry = 3600 });
            var providers = new Providers.Providers(new OAuthConfig());
            var hooks = new Hooks.Hooks(new HooksConfig(), auth, providers);
            var docker = new Docker.Docker();
            var linkdb = new LinkDB("links");
            var handlers = new Handlers.Handlers(new HandlersConfig(), auth, hooks, providers, docker, linkdb, Array.Empty<string>());

            async System.Threading.Tasks.Task Run(HttpContext ctx, Action<Auth.Context> action)
            {
                var c = new Auth.Context { Request = ctx.Request, Writer = ctx.Response };
                foreach (var kv in ctx.Request.Query)
                {
                    c.QueryParameters[kv.Key] = kv.Value;
                }
                if (ctx.Request.ContentLength > 0)
                {
                    using var reader = new StreamReader(ctx.Request.Body);
                    c.Body = await reader.ReadToEndAsync();
                }
                action(c);
                ctx.Response.StatusCode = c.ResponseStatus;
                if (c.ResponseBody != null)
                {
                    await ctx.Response.WriteAsJsonAsync(c.ResponseBody);
                }
            }

            app.MapGet("/", () => "OK");
            app.MapGet("/health", ctx => Run(ctx, handlers.HealthcheckHandler));
            app.MapGet("/context/app", ctx => Run(ctx, handlers.AppContextHandler));
            app.MapGet("/context/user", ctx => Run(ctx, handlers.UserContextHandler));
            app.MapPost("/logout", ctx => Run(ctx, handlers.LogoutHandler));

            app.Run($"http://{Config.Address}:{Config.Port}");
        }
    }
}
