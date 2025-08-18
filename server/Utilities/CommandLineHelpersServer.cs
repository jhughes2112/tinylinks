using Authentication;
using DataCollection;
using Logging;
using Storage;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Utilities
{
	static public class CommandLineHelpersServer
	{
		static public IDataCollection CreateDataCollection(string config, Dictionary<string, string> labels, ILogging logger)
		{
			string dctype = config.ToLowerInvariant();
			switch (dctype)
			{
				case "prometheus":
				{
					IDataCollection dc = new DataCollectionPrometheus(labels, logger); 
					Constants.Initialize(dc);
					return dc;
				}
				case "fake":
				{
					IDataCollection dc = new DataCollectionFake(labels, logger); 
					Constants.Initialize(dc);
					return dc;
				}
			}
			throw new Exception($"Invalid config: {dctype}  Expected: prometheus");
		}

		static public async Task<IAuthentication> CreateAuthentication(string config, ILogging logger)
		{
            // Supported:
            //  - always
            //  - openid,provider,wellknown-url
			string[] parts = config.Split(',');
			string authType  = parts[0].ToLowerInvariant();

			switch (authType)
			{
				case "always":
					return new AuthenticationAlways(logger);
				case "openid":
				{
					if (parts.Length != 5)
						throw new Exception("openid auth requires openid,provider,wellknown-url or openid,wellknown-url");

					string provider = parts[1];
					string openIdUrl = parts[2];
					string clientId = parts[3];
					string clientSecret = parts[4];

					OAuth2Helper helper = new OAuth2Helper(logger);
					Dictionary<string, RSA>? publicKeys = await helper.GetPublicKeys(openIdUrl).ConfigureAwait(false);
					(string? authEndpoint, string? tokenEndpoint) = await helper.GetEndpoints(openIdUrl).ConfigureAwait(false);
					if (publicKeys!=null && tokenEndpoint!=null && authEndpoint!=null)
						return new AuthenticationJWT(provider, authEndpoint, tokenEndpoint, clientId, clientSecret, publicKeys, logger);
					throw new Exception($"No public keys or missing endpoint for openId provider {provider}");
				}
			}
			throw new Exception($"Invalid authentication type: {authType}");
		}

		// New: Create multiple IAuthentication providers from multiple config strings
		static public async Task<List<IAuthentication>> CreateAuthentications(IEnumerable<string> configs, ILogging logger)
		{
			List<IAuthentication> list = new List<IAuthentication>();
			foreach (var c in configs)
			{
				string cfg = (c ?? string.Empty).Trim();
				if (string.IsNullOrWhiteSpace(cfg)) continue;
				list.Add(await CreateAuthentication(cfg, logger).ConfigureAwait(false));
			}
			return list;
		}

		static public ILogging CreateLogger(string prefix, string config)
		{
			// Where [0=Errors, 1=Warnings, 2=Info, 3=Debug, 4=Extreme]
			string[] parts = config.Split(',');
			string ltype = parts[0].ToLowerInvariant();
			int verbosity = int.Parse(parts[1], System.Globalization.NumberStyles.Integer, CultureInfo.InvariantCulture);
			string filePath = parts.Length>2 ? parts[2] : string.Empty;

			switch (ltype)
			{
				case "file": 
					return new LoggingFile(prefix, (EVerbosity)verbosity, filePath);  // file,#,/folder/path/ which turns into /folder/path/prefix.log
				case "console": 
					return new LoggingConsole(prefix, (EVerbosity)verbosity);  // console,#
			}
			throw new Exception($"Invalid config: {ltype}  Expected: file,console");
		}
	}
}
