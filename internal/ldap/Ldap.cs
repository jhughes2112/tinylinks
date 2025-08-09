using Tinylinks.Types;

namespace Tinylinks.Ldap
{
    public class Ldap
    {
        public LdapConfig Config;

        public Ldap(LdapConfig config)
        {
            Config = config;
        }

        public string Search(string username)
        {
            return string.Empty;
        }

        public bool Bind(string userDn, string password)
        {
            return false;
        }
    }
}
