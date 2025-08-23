using System;
using System.Net;
using System.Threading.Tasks;

namespace Authentication
{
	// Request parameters coming from a downstream OIDC/OAuth client hitting /api/oauth/url
	public sealed class DownstreamAuthRequest
	{
		public string ResponseType { get; set; } = "code";
		public string? Scope { get; set; }
		public string? RedirectUri { get; set; }
		public string? ClientId { get; set; }
		public string? State { get; set; }
		public string? CodeChallenge { get; set; }
		public string? CodeChallengeMethod { get; set; }
	}

	// This allows us to have pluggable account authentication and OIDC provider flows.
	public interface IAuthentication
	{
		const string kAdminRole = "Admin";

		// Provider label (e.g., "google", "authentik") used in routing and selection
		string Provider { get; }

		// This gets called every second or so, allowing them to clean up if they made a mess.
		public void Tick();

		// Any kind of authentication system will return the statusCode, contentType, and content for the response.  It may set cookies or otherwise.
		// OpenID will internally track some stuff and redirect to the callback url.  Discord will do something similar, but WHAT it does is different.
		public Task<(int, string, byte[])> StartAuthenticate(Uri baseUri, HttpListenerContext httpContext, DownstreamAuthRequest downstream);

		// When the callback happens, we run through and figure out who owns this request.  It is up to the implementation to remember which ones were theirs.
		public bool IsThisYours(HttpListenerContext httpContext);

		// (upstreamSub, fullName, email, roles, linkcode, downstream)
		public Task<(string?, string?, string?, string[]?, string?, DownstreamAuthRequest?)> AuthenticateCallback(Uri baseUri, HttpListenerContext httpContext);
	}
}
