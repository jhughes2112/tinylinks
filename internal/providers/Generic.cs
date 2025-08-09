using System.Net.Http;
using Tinylinks.Constants;

namespace Tinylinks.Providers
{
    public static class Generic
    {
        public static Claims GetGenericUser(HttpClient client, string url)
        {
            return new Claims();
        }
    }
}
