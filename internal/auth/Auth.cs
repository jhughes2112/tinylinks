using System;
using System.Collections.Generic;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Tinylinks.Types;
using Tinylinks.Utils;

namespace Tinylinks.Auth
{
    public class Context
    {
        public object Request { get; set; }
        public object Writer { get; set; }

        public Dictionary<string, string> QueryParameters = new Dictionary<string, string>();
        public string Body = string.Empty;

        public int ResponseStatus;
        public object ResponseBody;

        public void SetCookie(string name, string value, int maxAge, string path, string domain, bool secure, bool httpOnly)
        {
            if (Writer is HttpResponse resp)
            {
                var opts = new CookieOptions
                {
                    Path = path,
                    Domain = domain,
                    Secure = secure,
                    HttpOnly = httpOnly,
                    MaxAge = TimeSpan.FromSeconds(maxAge)
                };
                resp.Cookies.Append(name, value, opts);
            }
        }

        public string GetCookie(string name)
        {
            if (Request is HttpRequest req && req.Cookies.TryGetValue(name, out var v))
            {
                return v;
            }
            return string.Empty;
        }

        public string Query(string key)
        {
            string v;
            if (QueryParameters.TryGetValue(key, out v))
            {
                return v;
            }
            return string.Empty;
        }

        public bool BindJSON<T>(out T value)
        {
            try
            {
                value = JsonSerializer.Deserialize<T>(Body);
                return true;
            }
            catch
            {
                value = default(T);
                return false;
            }
        }

        public void JSON(int status, object obj)
        {
            ResponseStatus = status;
            ResponseBody = obj;
        }
    }

    public class Session
    {
        public Dictionary<string, object> Values = new Dictionary<string, object>();

        public void Save(object request, object writer)
        {
            // Placeholder for saving session
        }
    }

    public class CookieStore
    {
        public Session Get(object request, string name)
        {
            // Placeholder that always returns a new session
            return new Session();
        }
    }

    public class Auth
    {
        public AuthConfig Config { get; set; }
        public CookieStore Store { get; set; }

        public Auth(AuthConfig config)
        {
            Config = config;
            Store = new CookieStore();
        }

        public Session GetSession(Context c)
        {
            return Store.Get(c.Request, Config.SessionCookieName);
        }

        public bool CreateSessionCookie(Context c, SessionCookie data)
        {
            var session = GetSession(c);
            session.Values["username"] = data.Username;
            session.Values["name"] = data.Name;
            session.Values["email"] = data.Email;
            session.Values["provider"] = data.Provider;
            session.Values["expiry"] = DateTime.UtcNow.AddSeconds(Config.SessionExpiry).Ticks;
            session.Values["oauthGroups"] = data.OAuthGroups;
            session.Save(c.Request, c.Writer);
            return true;
        }

        public bool DeleteSessionCookie(Context c)
        {
            var session = GetSession(c);
            var keys = new List<string>();
            foreach (var kv in session.Values)
            {
                keys.Add(kv.Key);
            }
            for (int i = 0; i < keys.Count; i++)
            {
                session.Values.Remove(keys[i]);
            }
            session.Save(c.Request, c.Writer);
            return true;
        }

        public SessionCookie GetSessionCookie(Context c)
        {
            var session = GetSession(c);
            if (!session.Values.ContainsKey("username") || !session.Values.ContainsKey("provider") ||
                !session.Values.ContainsKey("expiry") || !session.Values.ContainsKey("email") ||
                !session.Values.ContainsKey("name") || !session.Values.ContainsKey("oauthGroups"))
            {
                DeleteSessionCookie(c);
                return null;
            }

            return new SessionCookie
            {
                Username = session.Values["username"] as string,
                Name = session.Values["name"] as string,
                Email = session.Values["email"] as string,
                Provider = session.Values["provider"] as string,
                OAuthGroups = session.Values["oauthGroups"] as string
            };
        }

        public bool ResourceAllowed(Context c, UserContext context, Labels labels)
        {
            if (context.OAuth)
            {
                return true;
            }
            return false;
        }

        public bool OAuthGroup(Context c, UserContext context, Labels labels)
        {
            if (labels.OAuth.Groups == "")
            {
                return true;
            }
            if (context.Provider != "generic")
            {
                return true;
            }

            var groups = context.OAuthGroups.Split(',');
            for (int i = 0; i < groups.Length; i++)
            {
                if (Utils.Utils.CheckFilter(labels.OAuth.Groups, groups[i]))
                {
                    return true;
                }
            }
            return false;
        }

        public bool AuthEnabled(string uri, Labels labels, out Exception err)
        {
            err = null;
            if (labels.Allowed == "")
            {
                return true;
            }
            try
            {
                if (System.Text.RegularExpressions.Regex.IsMatch(uri, labels.Allowed))
                {
                    return false;
                }
            }
            catch (Exception e)
            {
                err = e;
                return true;
            }
            return true;
        }

        public bool CheckIP(Labels labels, string ip)
        {
            if (labels.IP.Block != null)
            {
                for (int i = 0; i < labels.IP.Block.Length; i++)
                {
                    Exception e;
                    var res = Utils.Utils.FilterIP(labels.IP.Block[i], ip, out e);
                    if (e != null)
                    {
                        continue;
                    }
                    if (res)
                    {
                        return false;
                    }
                }
            }

            if (labels.IP.Allow != null)
            {
                for (int i = 0; i < labels.IP.Allow.Length; i++)
                {
                    Exception e;
                    var res = Utils.Utils.FilterIP(labels.IP.Allow[i], ip, out e);
                    if (e != null)
                    {
                        continue;
                    }
                    if (res)
                    {
                        return true;
                    }
                }
                if (labels.IP.Allow.Length > 0)
                {
                    return false;
                }
            }

            return true;
        }

        public bool BypassedIP(Labels labels, string ip)
        {
            if (labels.IP.Bypass != null)
            {
                for (int i = 0; i < labels.IP.Bypass.Length; i++)
                {
                    Exception e;
                    var res = Utils.Utils.FilterIP(labels.IP.Bypass[i], ip, out e);
                    if (e != null)
                    {
                        continue;
                    }
                    if (res)
                    {
                        return true;
                    }
                }
            }
            return false;
        }
    }
}
