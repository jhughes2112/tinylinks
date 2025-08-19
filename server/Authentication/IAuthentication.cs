using System;
using System.Net;
using System.Threading.Tasks;

namespace Authentication
{
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
		public Task<(int, string, byte[])> StartAuthenticate(Uri baseUri, HttpListenerContext httpContext);

		// When the callback happens, we run through and figure out who owns this request.  It is up to the implementation to remember which ones were theirs.
		public bool IsThisYours(HttpListenerContext httpContext);

		// (upstreamSub, fullName, email, roles, linkcode) 
		public Task<(string?, string?, string?, string[]?, string?)> AuthenticateCallback(Uri baseUri, HttpListenerContext httpContext);
	}
}
