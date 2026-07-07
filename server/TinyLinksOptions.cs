using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace TinyLinks
{
	// Hand-rolled command line parsing (no reflection) so the app can be compiled with NativeAOT.
	// Semantics match the previous CommandLineParser usage: --name value [value...], where list
	// options collect every value up to the next --flag, and repeating a flag appends to the list.
	public class TinyLinksOptions
	{
		//-------------------
		// Logging
		// Must be: console,# or file,#,/path/file.log where [0=Errors, 1=Warnings, 2=Info, 3=Debug, 4=Extreme]
		public string? log_config { get; set; } = "console,2";

		//-------------------
		// Connection
		// This is the URL we actually bind to. /health and /metrics for hosting and prometheus.
		public string? conn_bindurl { get; set; } = "http://+:7777/";

		//-------------------
		// Storage - primarily for metadata, and it's always stored in .json format to make life simple.
		// Root of dynamic storage, ex: /data/  (required)
		public string? storage_config { get; set; }

		//-------------------
		// Authentication
		// To configure multiple providers, do --auth_config once followed by several definitions with a space between them.
		// "openid,<provider>,<well-known-openid-config-url>,<clientid>,<clientsecret> openid,..."  (required)
		public IEnumerable<string>? auth_config { get; set; }

		//-------------------
		// Duration of a logged in session in seconds, after which user will need to login again.
		public int session_duration { get; set; } = 3600;

		// Your application provides this secret to generate masquerade links, which prevents JWT theft resulting in account theft.  (required)
		public string? linkcreate_secret { get; set; }

		//-------------------
		// Downstream OIDC clients (allowlist). Repeat option to add more.
		// Each: "clientid,redirecturi1,redirecturi2,..." with exact-match redirect URIs.  (required)
		public IEnumerable<string>? client_config { get; set; }

		//-------------------
		// RSA signing key persistence. If empty, a key file is created under the storage folder on first run.
		public string? jwt_key_file { get; set; } = "";

		//-------------------
		// Static content and hosting
		// Comma-separated list of URLs that requests should look like to the server. Example: 'http://localhost:7777/,https://example.com:8080/wiki/'  (required)
		public string? advertise_urls { get; set; }

		// Path to the static client files. Can be relative to the executable or an absolute path.
		public string? static_root { get; set; } = "../static_root";

		//-------------------
		// Parses args into an options object.  Returns null (after printing usage) on any error or --help.
		static public TinyLinksOptions? Parse(string[] args)
		{
			TinyLinksOptions o = new TinyLinksOptions();
			List<string> authConfigs = new List<string>();
			List<string> clientConfigs = new List<string>();
			List<string> errors = new List<string>();

			int i = 0;
			while (i < args.Length)
			{
				string flag = args[i];
				if (flag == "--help" || flag == "-h" || flag == "help")
				{
					PrintUsage(null);
					return null;
				}
				if (!flag.StartsWith("--", StringComparison.Ordinal))
				{
					errors.Add($"Unexpected argument '{flag}'");
					i++;
					continue;
				}

				// Collect all values up to the next --flag
				List<string> values = new List<string>();
				i++;
				while (i < args.Length && !args[i].StartsWith("--", StringComparison.Ordinal))
				{
					values.Add(args[i]);
					i++;
				}

				switch (flag)
				{
					case "--log_config":        o.log_config        = Single(flag, values, errors); break;
					case "--conn_bindurl":      o.conn_bindurl      = Single(flag, values, errors); break;
					case "--storage_config":    o.storage_config    = Single(flag, values, errors); break;
					case "--session_duration":
					{
						string? v = Single(flag, values, errors);
						if (v != null)
						{
							if (int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out int duration))
								o.session_duration = duration;
							else
								errors.Add($"{flag} expects an integer, got '{v}'");
						}
						break;
					}
					case "--linkcreate_secret": o.linkcreate_secret = Single(flag, values, errors); break;
					case "--jwt_key_file":      o.jwt_key_file      = Single(flag, values, errors); break;
					case "--advertise_urls":    o.advertise_urls    = Single(flag, values, errors); break;
					case "--static_root":       o.static_root       = Single(flag, values, errors); break;
					case "--auth_config":
						if (values.Count == 0) errors.Add($"{flag} requires at least one value");
						authConfigs.AddRange(values);
						break;
					case "--client_config":
						if (values.Count == 0) errors.Add($"{flag} requires at least one value");
						clientConfigs.AddRange(values);
						break;
					default:
						errors.Add($"Unknown option '{flag}'");
						break;
				}
			}

			if (authConfigs.Count > 0)   o.auth_config   = authConfigs;
			if (clientConfigs.Count > 0) o.client_config = clientConfigs;

			// Required options
			if (string.IsNullOrWhiteSpace(o.storage_config))    errors.Add("--storage_config is required");
			if (o.auth_config == null)                          errors.Add("--auth_config is required");
			if (string.IsNullOrWhiteSpace(o.linkcreate_secret)) errors.Add("--linkcreate_secret is required");
			if (o.client_config == null)                        errors.Add("--client_config is required");
			if (string.IsNullOrWhiteSpace(o.advertise_urls))    errors.Add("--advertise_urls is required");

			if (errors.Count > 0)
			{
				PrintUsage(errors);
				return null;
			}
			return o;
		}

		static private string? Single(string flag, List<string> values, List<string> errors)
		{
			if (values.Count == 1)
				return values[0];
			errors.Add($"{flag} expects exactly one value, got {values.Count}");
			return null;
		}

		static private void PrintUsage(List<string>? errors)
		{
			StringBuilder sb = new StringBuilder();
			if (errors != null)
			{
				foreach (string e in errors)
					sb.AppendLine($"ERROR: {e}");
				sb.AppendLine();
			}
			sb.AppendLine("TinyLinks options:");
			sb.AppendLine("  --log_config        Must be: console,# or file,#,/path/file.log where [0=Errors, 1=Warnings, 2=Info, 3=Debug, 4=Extreme]  (default: console,2)");
			sb.AppendLine("  --conn_bindurl      This is the URL we actually bind to. /health and /metrics for hosting and prometheus.  (default: http://+:7777/)");
			sb.AppendLine("  --storage_config    REQUIRED. Root of dynamic storage, ex: /data/");
			sb.AppendLine("  --auth_config       REQUIRED. Authentication entries, space separated and/or repeated. Each: always or discord,<clientid>,<clientsecret> or openid,<provider>,<well-known-url>,<clientid>,<clientsecret>");
			sb.AppendLine("  --session_duration  Duration of a logged in session in seconds, after which user will need to login again.  (default: 3600)");
			sb.AppendLine("  --linkcreate_secret REQUIRED. Your application provides this secret to generate masquerade links, which prevents JWT theft resulting in account theft.");
			sb.AppendLine("  --client_config     REQUIRED. Allowed downstream OIDC clients, space separated and/or repeated. Each: clientid,redirecturi[,redirecturi...]");
			sb.AppendLine("  --jwt_key_file      Path to the RSA signing key (PKCS#8 PEM). Created on first run if absent. Defaults to <storage>/jwt_signing_key.pem.");
			sb.AppendLine("  --advertise_urls    REQUIRED. Comma-separated list of URLs that requests should look like to the server. Example: 'http://localhost:7777/,https://example.com:8080/wiki/'");
			sb.AppendLine("  --static_root       Path to the static client files. Can be relative to the executable or an absolute path.  (default: ../static_root)");
			Console.WriteLine(sb.ToString());
		}
	}
}
