using System.Net.Http;
using Tinylinks.Constants;

namespace Tinylinks.Providers
{
    public static class Github
    {
        public static string[] GithubScopes()
        {
            return new[] { "user:email", "read:user" };
        }

        public static Claims GetGithubUser(HttpClient client)
        {
            return new Claims();
        }
    }
}
