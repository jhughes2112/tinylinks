using System;
using System.Collections.Generic;

namespace Utilities
{
	// Allowlist of downstream OIDC clients and the exact redirect URIs each is permitted to use.
	// Without this, the authorize endpoint would honor any attacker-supplied redirect_uri and leak
	// authorization codes / tokens to arbitrary sites.
	public sealed class ClientRegistry
	{
		private readonly Dictionary<string, HashSet<string>> _clientToRedirects = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);

		// Each config entry: "clientid,redirecturi1,redirecturi2,..." (exact-match redirect URIs).
		public ClientRegistry(IEnumerable<string> configs)
		{
			foreach (string raw in configs)
			{
				string cfg = (raw ?? string.Empty).Trim();
				if (string.IsNullOrWhiteSpace(cfg)) continue;

				string[] parts = cfg.Split(',');
				if (parts.Length < 2)
					throw new ArgumentException($"client_config entry must be 'clientid,redirecturi[,redirecturi...]': '{cfg}'");

				string clientId = parts[0].Trim();
				if (string.IsNullOrWhiteSpace(clientId))
					throw new ArgumentException($"client_config entry has empty client id: '{cfg}'");

				if (!_clientToRedirects.TryGetValue(clientId, out HashSet<string>? redirects))
				{
					redirects = new HashSet<string>(StringComparer.Ordinal);
					_clientToRedirects[clientId] = redirects;
				}
				for (int i = 1; i < parts.Length; i++)
				{
					string uri = parts[i].Trim();
					if (!string.IsNullOrWhiteSpace(uri)) redirects.Add(uri);
				}
			}
		}

		public int Count => _clientToRedirects.Count;

		// True only when the client id is registered and the redirect_uri exactly matches one of its allowed URIs.
		public bool IsAllowed(string? clientId, string? redirectUri)
		{
			if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(redirectUri))
				return false;
			return _clientToRedirects.TryGetValue(clientId!, out HashSet<string>? redirects) && redirects.Contains(redirectUri!);
		}
	}
}
