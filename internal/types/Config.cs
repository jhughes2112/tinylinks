using System;

namespace Tinylinks.Types
{
    public class Config
    {
        public int Port { get; set; }
        public string Address { get; set; }
        public string Secret { get; set; }
        public string SecretFile { get; set; }
        public string AppURL { get; set; }
        public bool CookieSecure { get; set; }
        public string GithubClientId { get; set; }
        public string GithubClientSecret { get; set; }
        public string GithubClientSecretFile { get; set; }
        public string GoogleClientId { get; set; }
        public string GoogleClientSecret { get; set; }
        public string GoogleClientSecretFile { get; set; }
        public string GenericClientId { get; set; }
        public string GenericClientSecret { get; set; }
        public string GenericClientSecretFile { get; set; }
        public string GenericScopes { get; set; }
        public string GenericAuthURL { get; set; }
        public string GenericTokenURL { get; set; }
        public string GenericUserURL { get; set; }
        public string GenericName { get; set; }
        public bool GenericSkipSSL { get; set; }
        public bool DisableContinue { get; set; }
        public string OAuthAutoRedirect { get; set; }
        public int SessionExpiry { get; set; }
        public sbyte LogLevel { get; set; }
        public string Title { get; set; }
        public string EnvFile { get; set; }
        public string BackgroundImage { get; set; }
        public string LinkDBPath { get; set; }
        public string AdminEmails { get; set; }
    }

    public class HandlersConfig
    {
        public string AppURL { get; set; }
        public string Domain { get; set; }
        public bool CookieSecure { get; set; }
        public bool DisableContinue { get; set; }
        public string GenericName { get; set; }
        public string Title { get; set; }
        public string BackgroundImage { get; set; }
        public string OAuthAutoRedirect { get; set; }
        public string CsrfCookieName { get; set; }
        public string RedirectCookieName { get; set; }
    }

    public class OAuthConfig
    {
        public string GithubClientId { get; set; }
        public string GithubClientSecret { get; set; }
        public string GoogleClientId { get; set; }
        public string GoogleClientSecret { get; set; }
        public string GenericClientId { get; set; }
        public string GenericClientSecret { get; set; }
        public string[] GenericScopes { get; set; }
        public string GenericAuthURL { get; set; }
        public string GenericTokenURL { get; set; }
        public string GenericUserURL { get; set; }
        public bool GenericSkipSSL { get; set; }
        public string AppURL { get; set; }
    }

    public class ServerConfig
    {
        public int Port { get; set; }
        public string Address { get; set; }
    }

    public class AuthConfig
    {
        public int SessionExpiry { get; set; }
        public bool CookieSecure { get; set; }
        public string Domain { get; set; }
        public string SessionCookieName { get; set; }
        public string HMACSecret { get; set; }
        public string EncryptionSecret { get; set; }
    }

    public class HooksConfig
    {
        public string Domain { get; set; }
    }

    public class OAuthLabels
    {
        public string Groups { get; set; }
    }

    public class IPLabels
    {
        public string[] Allow { get; set; }
        public string[] Block { get; set; }
        public string[] Bypass { get; set; }
    }

    public class Labels
    {
        public string Allowed { get; set; }
        public string[] Headers { get; set; }
        public string[] Domain { get; set; }
        public OAuthLabels OAuth { get; set; }
        public IPLabels IP { get; set; }
    }

    public class LdapConfig
    {
        public string Address { get; set; }
        public string BindDN { get; set; }
        public string BindPassword { get; set; }
        public string BaseDN { get; set; }
        public bool Insecure { get; set; }
        public string SearchFilter { get; set; }
    }
}
