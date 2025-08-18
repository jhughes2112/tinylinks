using Logging;
using System;
using System.Threading.Tasks;

namespace Authentication
{
	// This checks nothing, only for use in non-production builds, generally.
	public class AuthenticationAlways : IAuthentication
	{
		private ILogging _logger;

		public AuthenticationAlways(ILogging logger)
		{
			_logger = logger;
		}

		public string Provider => "always";

		// This is set up to be a very simple format that is implicitly trusted (and should never be used in production).
		// accountId<->full name<->email<->role,role,role
		public (string?, string?, string?, string[]?) Authenticate(string? jwt)
		{
			string?   accountId = null;
			string?   fullName  = null;
			string?   email     = null;
			string[]? roles     = null;

			if (jwt!=null)
			{
				string[] parts = jwt.Split("<->");
				if (parts.Length >= 4)
				{
					accountId = parts[0];
					fullName  = parts[1];
					email     = parts[2];
					roles     = parts[3].Split(',');
					_logger.Log(EVerbosity.Info, $"AuthenticationAlways: {jwt} -> accountId={accountId} name={fullName} email={email} roles={string.Join(',', roles)}");
				}
				else
				{
					_logger.Log(EVerbosity.Warning, $"AuthenticationAlways: Invalid format for authentication string: {jwt}");
				}
			}
			return (accountId, fullName, email, roles);
		}

		// Call this with httpListenerContext.Request.Headers.GetValues("Authorization");
		public (string?, string?, string?, string[]?) AuthenticateRequest(string[]? authorizationHeaders)
		{
			// Always allow means any user who connects gets admin user, unless they provide a real login.
			string token = "adminAccount<->Admin User<->admin@localhost<->Admin";
			if (authorizationHeaders != null && authorizationHeaders.Length > 0)
			{
				token = authorizationHeaders[0];
				if (token!=null && token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
				{
					token = token.Substring("Bearer ".Length).Trim();
				}
			}
			return Authenticate(token);
		}

		public string BuildAuthorizeUrl(string redirectUri, string state, string codeChallenge)
		{
			// Not used for the 'always' provider; immediately redirect back
			return redirectUri;
		}

		public Task<string?> ExchangeCodeForJwtAsync(string code, string redirectUri, string codeVerifier)
		{
			// Not used; echo back the "code" as a fake token for testing
			return Task.FromResult<string?>(code);
		}
	}
}
