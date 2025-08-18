using CommandLine;
using System.Collections.Generic;

namespace TinyLinks
{
	public class TinyLinksOptions
	{
		//-------------------
		// Logging
		[Option("log_config", Required = false, Default = "console,2", HelpText = "Must be: console,# or file,#,/path/file.log where [0=Errors, 1=Warnings, 2=Info, 3=Debug, 4=Extreme]")]
		public string? log_config { get; set; }

		//-------------------
		// Connection
		[Option("conn_bindurl", Required = false, Default = "http://+:7777/", HelpText = "This is the URL we actually bind to. /health and /metrics for hosting and prometheus.")]
		public string? conn_bindurl { get; set; }

        //-------------------
        // Storage - primarily for metadata, and it's always stored in .json format to make life simple.
        [Option("storage_config", Required = true, HelpText = "Root of dynamic storage, ex: /data/")]
		public string? storage_config { get; set; }

		//-------------------
		// Authentication
		// Allow multiple --auth_config entries. Preferred syntax: "openid,<provider>,<well-known-openid-config-url>" or "always".
		[Option("auth_config", Required = true, HelpText = "Authentication entries. Repeat option to add more. Each: always or openid,<provider>,<well-known-openid-config-url>", Separator = '\n')]
		public IEnumerable<string>? auth_config { get; set; } = new[] { "always" };

		//-------------------
		// Post-login redirect
		[Option("post_login_redirect", Required = true, HelpText = "Absolute URL to redirect users to after successful login.")]
		public string? post_login_redirect { get; set; }

		[Option("session_duration", Required = false, Default = 3600, HelpText = "Duration of a logged in session in seconds, after which user will need to login again.")]
		public int session_duration { get; set; }

		//-------------------
		// Static content and hosting
		[Option("advertise_urls", Required = true, Default = "http://localhost:7777/", HelpText = "Comma-separated list of URLs that requests should look like to the server. Example: 'http://localhost:7777/,https://example.com:8080/wiki/'")]
		public string? advertise_urls { get; set; }

		[Option("static_root", Required = false, Default = "../static_root", HelpText = "Path to the static client files. Can be relative to the executable or an absolute path.")]
		public string? static_root { get; set; }
	}
}
