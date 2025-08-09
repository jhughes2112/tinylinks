using System;

namespace Tinylinks.Constants
{
    /// <summary>
    /// Claims are the OIDC supported claims (preferred username is included for convenience)
    /// </summary>
    public class Claims
    {
        public string Name { get; set; }
        public string Email { get; set; }
        public string PreferredUsername { get; set; }
        public object Groups { get; set; }
    }

    /// <summary>
    /// Version information
    /// </summary>
    public static class VersionInfo
    {
        public const string Version = "development";
        public const string CommitHash = "n/a";
        public const string BuildTimestamp = "n/a";
    }

    /// <summary>
    /// Base cookie names
    /// </summary>
    public static class CookieNames
    {
        public const string SessionCookieName = "tinyauth-session";
        public const string CsrfCookieName = "tinyauth-csrf";
        public const string RedirectCookieName = "tinyauth-redirect";
    }
}
