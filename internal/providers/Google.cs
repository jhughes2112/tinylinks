using System.Net.Http;
using Tinylinks.Constants;

namespace Tinylinks.Providers
{
    public static class Google
    {
        public static string[] GoogleScopes()
        {
            return new[]
            {
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile"
            };
        }

        public static Claims GetGoogleUser(HttpClient client)
        {
            return new Claims();
        }
    }
}
