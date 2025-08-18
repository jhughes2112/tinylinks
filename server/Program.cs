using ReachableGames;
using CommandLine;
using DataCollection;
using Logging;
using Networking;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.Loader;
using System.Threading;
using System.Threading.Tasks;
using Utilities;
using Storage;
using Authentication;
using System.Net;

namespace TinyLinks
{
	public class Program
	{
		static public async Task Main(string[] args)
		{
			await Parser.Default.ParseArguments<TinyLinksOptions>(args).WithParsedAsync(Run).ConfigureAwait(false);
		}

		static private async Task Run(TinyLinksOptions o)
		{
			CancellationTokenSource tokenSrc = new CancellationTokenSource();

			// Set up a callback so a ^C will halt the server
			bool sigIntRecvd = false;
			Console.CancelKeyPress += new ConsoleCancelEventHandler((object? sender, ConsoleCancelEventArgs e) =>
				{
					Console.WriteLine("Caught SIGINT, tripping cancellation token.");   // Control-C
					e.Cancel = true;
					sigIntRecvd = true;
					tokenSrc.Cancel();
				});

			// Set up a callback to have SIGTERM also halt the server gracefully.  This is what "docker stop" uses.
			AssemblyLoadContext? ctx = AssemblyLoadContext.GetLoadContext(typeof(Program).GetTypeInfo().Assembly);
			if (ctx!=null)
			{
				ctx.Unloading += (AssemblyLoadContext context) =>
				{
					if (sigIntRecvd==false)  // don't process this if control-c happened 
					{
						Console.WriteLine("Caught SIGTERM, tripping cancellation token.");  // SIGTERM / kill
						tokenSrc.Cancel();
					}
				};
			}

			// Move resource definitions outside try/catch so they can be properly disposed in finally
			ILogging? logger = null;
			IDataCollection? dataCollection = null;
			List<IAuthentication>? authentications = null;
			StorageFiles? linksStorage = null;
			TinyLinksServer? server = null;
			ReachableGames.RGWebSocket.WebServer? webServer = null;
			
			try
			{
				logger = CommandLineHelpersServer.CreateLogger("TinyLinks", o.log_config!);
				dataCollection = CommandLineHelpersServer.CreateDataCollection("prometheus", new Dictionary<string, string>() { { "process", "TinyLinks" } }, logger);
				authentications = await CommandLineHelpersServer.CreateAuthentications(o.auth_config ?? new[] { "always" }, logger).ConfigureAwait(false);
				linksStorage = new StorageFiles(o.storage_config!, logger);  // data is stored where directed by the command line option
				List<string> advertiseUrls = GetAdvertiseUrls(o.advertise_urls!);

				// The reason this takes in a CancellationTokenSource is Docker/someone may hit ^C and want to shutdown the server.
				// The reason we explicitly call Shutdown is the server itself may exit for other reasons, and we need to make sure it shuts down in either case.
				server = new TinyLinksServer(advertiseUrls, o.static_root!, dataCollection, logger, tokenSrc, authentications, o.post_login_redirect!, o.session_duration, o.linkcreate_secret!, linksStorage!);

				// Set up a websocket handler that forwards connections, disconnections, and messages to the ClusterServer
				ConnectionManagerReject connectionMgr = new ConnectionManagerReject(logger);
				webServer = new ReachableGames.RGWebSocket.WebServer(o.conn_bindurl!, 20, 1000, 5, connectionMgr, logger);

				// (responseCode, responseContentType, responseContent)
				webServer.RegisterExactEndpoint("/metrics", async (HttpListenerContext context) => { return (200, "text/plain", await dataCollection.Generate()); });
				webServer.RegisterExactEndpoint("/health", (HttpListenerContext) => { return Task.FromResult((200, "text/plain", new byte[0])); } );

				// Explicit API handlers
				webServer.RegisterExactEndpoint("/.well-known/openid-configuration", server.OpenIdConfiguration);
				webServer.RegisterExactEndpoint("/.well-known/jwks.json", server.Jwks);
				webServer.RegisterExactEndpoint("/api/oauth/url", server.OAuthUrl);        // if the user wants to log in and masquerade as another account, they call this with ?linkcode=<code> and the server knows to start masquerading as the appropriate user
				webServer.RegisterExactEndpoint("/api/oauth/callback", server.OAuthCallback);
				webServer.RegisterExactEndpoint("/api/link/create", server.LinkCreate);    // game must call this with ?secret=<gamesecret>&userjwt=<jwt> to create a link to allow another account to masquerade as this one
				webServer.RegisterExactEndpoint("/api/link/unlink", server.UnlinkAccount); // user can call this with ?userjwt=<jwt> to disable masquerading as another account

				// Static content last
				webServer.RegisterPrefixEndpoint("/", server.GetClient);

				webServer.Start();  // this starts the webserver in a separate thread

				await tokenSrc.Token;  // block here until the cancellation token triggers.  Note, if the server decides to shut itself down, IT CANCELS THIS TOKEN.  So this is the perfect way to wait.
			}
			catch (OperationCanceledException)
			{
				// flow control
			}
			catch (Exception e)
			{
				Console.WriteLine(e);
			}
			finally
			{
				webServer?.UnregisterPrefixEndpoint("/");
				webServer?.UnregisterExactEndpoint("/.well-known/openid-configuration");
				webServer?.UnregisterExactEndpoint("/.well-known/jwks.json");
				webServer?.UnregisterExactEndpoint("/api/oauth/url");
				webServer?.UnregisterExactEndpoint("/api/oauth/callback");
				webServer?.UnregisterExactEndpoint("/api/link/create");
				webServer?.UnregisterExactEndpoint("/api/link/unlink");
				webServer?.UnregisterExactEndpoint("/metrics");
				webServer?.UnregisterExactEndpoint("/health");

				if (server != null)
				{
					await server.Shutdown().ConfigureAwait(false);
				}
				if (linksStorage != null)
				{
					await linksStorage.Shutdown().ConfigureAwait(false);
				}
				if (webServer!=null)
				{
					await webServer.Shutdown().ConfigureAwait(false);
				}
				
				// Dispose of resources that implement IDisposable
				linksStorage?.Dispose();
				dataCollection?.Dispose();
				logger?.Dispose();
				// authentication does not implement IDisposable, so no disposal needed
			}
		}

		// Parse the comma-separated advertise_urls string into a list of URLs. Handles whitespace trimming and empty entries.
		static private List<string> GetAdvertiseUrls(string advertise_urls)
		{
			if (string.IsNullOrWhiteSpace(advertise_urls))
				return new List<string> { "http://localhost:7777/" };

			var urls = new List<string>();
			string[] parts = advertise_urls.Split(',');
			foreach (string part in parts)
			{
				string trimmed = part.Trim();
				if (!string.IsNullOrWhiteSpace(trimmed))
					urls.Add(trimmed);
			}
			return urls;
		}
    }
}
