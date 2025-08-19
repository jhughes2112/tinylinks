using Logging;
using Shared;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Authentication
{
	// This checks nothing, only for use in non-production builds, generally.
	public class AuthenticationAlways : IAuthentication
	{
		private string   _sub;
		private string   _fullName;
		private string   _email;
		private string[] _roles;
		private ILogging _logger;

		// OAuth state (short TTL)
		private const    int    kAlwaysStateTtlSeconds = 9; // 9 seconds to complete your login right now, will adjust it up in a bit
		private const    string kAlwaysStateCookieName = "always_state";
		
		// When someone tries to authenticate, we stash some info in this object so it can be used when they finish the authentication flow and want to continue.
		private sealed class AlwaysStateEntry 
		{ 
			public DateTime CreatedUtc   { get; } 
			public string?  LinkCode     { get; } 
			public AlwaysStateEntry(DateTime createdUtc, string? linkCode) 
			{ 
				CreatedUtc   = createdUtc; 
				LinkCode     = linkCode; 
			} 
		}

		private readonly ThreadSafeDictionary<string, AlwaysStateEntry> _alwaysStates = new ThreadSafeDictionary<string, AlwaysStateEntry>();

		public AuthenticationAlways(string sub, string fullName, string email, string[] roles, ILogging logger)
		{
			_sub      = sub;
			_fullName = fullName;
			_email    = email;
			_roles    = roles;
			_logger   = logger;
		}

		public string Provider => "always";

		public void Tick()
		{
			// expire old auth states
			if (_alwaysStates.Count > 0)
			{
				List<string> expired = new List<string>();
				DateTime now = DateTime.UtcNow;
				_alwaysStates.Foreach((k, v) =>
				{
					if ((now - v.CreatedUtc).TotalSeconds > kAlwaysStateTtlSeconds)
					{
						expired.Add(k);
					}
				});
				foreach (string k in expired)
				{
					_alwaysStates.Remove(k);
				}
			}
		}

		// Any kind of authentication system will return the statusCode, contentType, and content for the response.  It may set cookies or otherwise.
		// Always just shortcuts the client to the callback url with the state in a cookie.
		public Task<(int, string, byte[])> StartAuthenticate(Uri baseUri, HttpListenerContext httpContext)
		{
			try
			{
				string state = UrlHelper.GenerateRandomDataBase64url(32);
				httpContext.Response.Headers.Add("Set-Cookie", $"{kAlwaysStateCookieName}={state}; Max-Age={kAlwaysStateTtlSeconds}; Path=/; HttpOnly");

				string callbackUrl = new Uri(baseUri, "/api/oauth/callback").AbsoluteUri;
				string? linkCode = httpContext.Request.QueryString["linkcode"];
				_alwaysStates.AddOrUpdate(state, new AlwaysStateEntry(DateTime.UtcNow, linkCode));

				// Just force the redirect in the client immediately without hitting any other servers.
				string url = $"{callbackUrl}?&state={Uri.EscapeDataString(state)}";
				httpContext.Response.RedirectLocation = url;
				return Task.FromResult((307, "text/plain", Encoding.UTF8.GetBytes("Redirecting")));
			}
			catch
			{
				return Task.FromResult((401, "text/plain", Encoding.UTF8.GetBytes("Cookie set failed")));
			}
		}

		// When the callback happens, we run through and figure out who owns this request.  It is up to the implementation to remember which ones were theirs.
		public bool IsThisYours(HttpListenerContext httpContext)
		{
			bool isMine = false;
			string? state = httpContext.Request.QueryString["state"];
			string? cookieHeader = httpContext.Request.Headers["Cookie"];
			if (!string.IsNullOrWhiteSpace(state) && !string.IsNullOrWhiteSpace(cookieHeader))
			{
				string? stateCookie = UrlHelper.ExtractCookie(cookieHeader, kAlwaysStateCookieName);
				isMine = !string.IsNullOrWhiteSpace(stateCookie) && string.Equals(stateCookie, state, StringComparison.Ordinal);
			}
			return isMine;
		}

		// (upstreamSub, fullName, email, roles, linkcode) 
		public Task<(string?, string?, string?, string[]?, string?)> AuthenticateCallback(Uri baseUri, HttpListenerContext httpContext)
		{
			// We already verified this is the correct state and it's ours.
			string state = httpContext.Request.QueryString["state"]!;
			if (_alwaysStates.TryRemove(state, out AlwaysStateEntry entry))
			{
				// wipe out that cookie
				try
				{
					httpContext.Response.Headers.Add("Set-Cookie", $"{kAlwaysStateCookieName}=; Max-Age=0; Path=/");
					return Task.FromResult<(string?,string?,string?,string[]?,string?)>((_sub, _fullName, _email, _roles, entry.LinkCode));
				}
				catch {}
			}
			return Task.FromResult<(string?,string?,string?,string[]?,string?)>((null, null, null, null, null));
		}
	}
}
