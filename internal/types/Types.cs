using System;

namespace Tinylinks.Types
{
    public class OAuthProviders
    {
        // Placeholder for OAuth providers; actual OAuth class not yet translated
        public object Github { get; set; }
        public object Google { get; set; }
        public object Microsoft { get; set; }
    }

    public class SessionCookie
    {
        public string Username { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Provider { get; set; }
        public string OAuthGroups { get; set; }
    }

    public class UserContext
    {
        public string Username { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public bool IsLoggedIn { get; set; }
        public bool OAuth { get; set; }
        public string Provider { get; set; }
        public string OAuthGroups { get; set; }
    }
}
