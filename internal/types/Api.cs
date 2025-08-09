using System;

namespace Tinylinks.Types
{
    public class OAuthRequest
    {
        public string Provider { get; set; }
    }

    public class UnauthorizedQuery
    {
        public string Resource { get; set; }
        public bool GroupErr { get; set; }
        public string IP { get; set; }
    }

    public class Proxy
    {
        public string ProxyUrl { get; set; }
    }

    public class UserContextResponse
    {
        public int Status { get; set; }
        public string Message { get; set; }
        public bool IsLoggedIn { get; set; }
        public string Username { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Provider { get; set; }
        public bool Oauth { get; set; }
    }

    public class AppContext
    {
        public int Status { get; set; }
        public string Message { get; set; }
        public string[] ConfiguredProviders { get; set; }
        public bool DisableContinue { get; set; }
        public string Title { get; set; }
        public string GenericName { get; set; }
        public string Domain { get; set; }
        public string BackgroundImage { get; set; }
        public string OAuthAutoRedirect { get; set; }
    }
}
