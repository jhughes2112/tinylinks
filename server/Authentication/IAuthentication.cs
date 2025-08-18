namespace Authentication
{
	// This allows us to have pluggable account authentication and OIDC provider flows.
	public interface IAuthentication
	{
		const string kAdminRole = "Admin";

		// Provider label (e.g., "google", "authentik") used in routing and selection
		string Provider { get; }

		// Helper that takes in httpListenerContext.Request.Headers.GetValues("Authorization")
		public (string?, string?, string?, string[]?) AuthenticateRequest(string[]? authorizationHeaders);

		// authstring is a JWT that is cracked into parts.  If it's invalid, accountId is returned null.  Otherwise you get a valid accountId and non-null roles.
		// Full name and email may or may not be set, so be prepared to fall back to accountId to display something, but always trust accountId is a unique string.
		// (accountId, full name, email, roles[])
		public (string?, string?, string?, string[]?) Authenticate(string authstring);

		// Build an authorization URL for the provider using server-managed flow (Authorization Code + PKCE)
		string BuildAuthorizeUrl(string redirectUri, string state, string codeChallenge);

		// Exchange an authorization code for a JWT using the given code_verifier, returns the id_token which has three parts and most of the important details (accountId, full name, email, roles[]).
		System.Threading.Tasks.Task<string?> ExchangeCodeForJwtAsync(string code, string redirectUri, string codeVerifier);
	}
}
