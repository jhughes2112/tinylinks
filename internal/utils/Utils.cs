using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Tinylinks.Types;

namespace Tinylinks.Utils
{
    public static class Utils
    {
        public static string GetUpperDomain(string urlSrc)
        {
            var urlParsed = new Uri(urlSrc);
            var host = urlParsed.Host;
            var parts = host.Split('.');
            if (parts.Length <= 2)
            {
                return host;
            }
            var sb = new StringBuilder();
            for (int i = 1; i < parts.Length; i++)
            {
                if (i > 1)
                {
                    sb.Append('.');
                }
                sb.Append(parts[i]);
            }
            return sb.ToString();
        }

        public static string ReadFile(string file)
        {
            if (!File.Exists(file))
            {
                throw new FileNotFoundException();
            }
            return File.ReadAllText(file);
        }

        public static string GetSecret(string conf, string file)
        {
            if (string.IsNullOrEmpty(conf) && string.IsNullOrEmpty(file))
            {
                return "";
            }
            if (!string.IsNullOrEmpty(conf))
            {
                return conf;
            }
            try
            {
                var contents = ReadFile(file);
                return ParseSecretFile(contents);
            }
            catch
            {
                return "";
            }
        }

        public static Dictionary<string, string> ParseHeaders(string[] headers)
        {
            var headerMap = new Dictionary<string, string>();
            if (headers == null)
            {
                return headerMap;
            }
            for (int i = 0; i < headers.Length; i++)
            {
                var header = headers[i];
                var split = header.Split(new char[] { '=' }, 2);
                if (split.Length != 2 || string.IsNullOrWhiteSpace(split[0]) || string.IsNullOrWhiteSpace(split[1]))
                {
                    continue;
                }
                var key = SanitizeHeader(split[0].Trim());
                var value = SanitizeHeader(split[1].Trim());
                headerMap[key] = value;
            }
            return headerMap;
        }

        public static Labels GetLabels(Dictionary<string, string> labels)
        {
            var parsed = new Labels();
            if (labels == null)
            {
                parsed.OAuth = new OAuthLabels();
                parsed.IP = new IPLabels();
                return parsed;
            }
            string value;
            if (labels.TryGetValue("tinyauth.allowed", out value))
            {
                parsed.Allowed = value;
            }
            var headers = new List<string>();
            foreach (var kv in labels)
            {
                if (kv.Key.StartsWith("tinyauth.headers"))
                {
                    headers.Add(kv.Value);
                }
            }
            parsed.Headers = headers.ToArray();
            var domains = new List<string>();
            foreach (var kv in labels)
            {
                if (kv.Key.StartsWith("tinyauth.domain"))
                {
                    domains.Add(kv.Value);
                }
            }
            parsed.Domain = domains.ToArray();
            parsed.OAuth = new OAuthLabels();
            if (labels.TryGetValue("tinyauth.oauth.groups", out value))
            {
                parsed.OAuth.Groups = value;
            }
            var ip = new IPLabels();
            var allow = new List<string>();
            var block = new List<string>();
            var bypass = new List<string>();
            foreach (var kv in labels)
            {
                if (kv.Key.StartsWith("tinyauth.ip.allow"))
                {
                    allow.Add(kv.Value);
                }
                else if (kv.Key.StartsWith("tinyauth.ip.block"))
                {
                    block.Add(kv.Value);
                }
                else if (kv.Key.StartsWith("tinyauth.ip.bypass"))
                {
                    bypass.Add(kv.Value);
                }
            }
            ip.Allow = allow.ToArray();
            ip.Block = block.ToArray();
            ip.Bypass = bypass.ToArray();
            parsed.IP = ip;
            return parsed;
        }

        public static bool OAuthConfigured(Config config)
        {
            return (!string.IsNullOrEmpty(config.GithubClientId) && !string.IsNullOrEmpty(config.GithubClientSecret)) ||
                   (!string.IsNullOrEmpty(config.GoogleClientId) && !string.IsNullOrEmpty(config.GoogleClientSecret)) ||
                   (!string.IsNullOrEmpty(config.GenericClientId) && !string.IsNullOrEmpty(config.GenericClientSecret));
        }

        public static List<T> Filter<T>(List<T> slice, Func<T, bool> test)
        {
            var res = new List<T>();
            for (int i = 0; i < slice.Count; i++)
            {
                var value = slice[i];
                if (test(value))
                {
                    res.Add(value);
                }
            }
            return res;
        }

        public static string ParseSecretFile(string contents)
        {
            var lines = contents.Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i].Trim();
                if (line != "")
                {
                    return line;
                }
            }
            return "";
        }

        public static bool CheckFilter(string filter, string str)
        {
            if (string.IsNullOrWhiteSpace(filter))
            {
                return true;
            }
            if (filter.StartsWith("/") && filter.EndsWith("/"))
            {
                try
                {
                    var pattern = filter.Substring(1, filter.Length - 2);
                    if (System.Text.RegularExpressions.Regex.IsMatch(str, pattern))
                    {
                        return true;
                    }
                }
                catch
                {
                    return false;
                }
            }
            var items = filter.Split(',');
            for (int i = 0; i < items.Length; i++)
            {
                if (items[i].Trim() == str)
                {
                    return true;
                }
            }
            return false;
        }

        public static string Capitalize(string str)
        {
            if (string.IsNullOrEmpty(str))
            {
                return "";
            }
            var chars = str.ToCharArray();
            chars[0] = char.ToUpper(chars[0]);
            return new string(chars);
        }

        public static string SanitizeHeader(string header)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < header.Length; i++)
            {
                char r = header[i];
                if (r == ' ' || r == '\t' || (r >= 32 && r <= 126))
                {
                    sb.Append(r);
                }
            }
            return sb.ToString();
        }

        public static string GenerateIdentifier(string str)
        {
            var bytes = Encoding.UTF8.GetBytes(str);
            using (var sha1 = SHA1.Create())
            {
                var hash = sha1.ComputeHash(bytes);
                var guidBytes = new byte[16];
                for (int i = 0; i < 16; i++)
                {
                    guidBytes[i] = hash[i];
                }
                var uuid = new Guid(guidBytes);
                var uuidStr = uuid.ToString();
                var parts = uuidStr.Split('-');
                return parts[0];
            }
        }

        public static bool FilterIP(string filter, string ip, out Exception error)
        {
            error = null;
            IPAddress ipAddr;
            if (!IPAddress.TryParse(ip, out ipAddr))
            {
                error = new Exception("invalid IP address in filter");
                return false;
            }
            if (filter.IndexOf('/') >= 0)
            {
                var split = filter.Split('/');
                IPAddress netAddr;
                if (!IPAddress.TryParse(split[0], out netAddr))
                {
                    error = new Exception("invalid IP address in filter");
                    return false;
                }
                int prefix;
                if (!int.TryParse(split[1], out prefix))
                {
                    error = new Exception("invalid CIDR");
                    return false;
                }
                var bytesNet = netAddr.GetAddressBytes();
                var bytesIP = ipAddr.GetAddressBytes();
                int fullBytes = prefix / 8;
                int remBits = prefix % 8;
                for (int i = 0; i < fullBytes; i++)
                {
                    if (bytesNet[i] != bytesIP[i])
                    {
                        return false;
                    }
                }
                if (remBits > 0)
                {
                    int mask = (int)(byte.MaxValue << (8 - remBits));
                    if ((bytesNet[fullBytes] & mask) != (bytesIP[fullBytes] & mask))
                    {
                        return false;
                    }
                }
                return true;
            }
            IPAddress ipFilter;
            if (!IPAddress.TryParse(filter, out ipFilter))
            {
                error = new Exception("invalid IP address in filter");
                return false;
            }
            return ipFilter.Equals(ipAddr);
        }

        public static string DeriveKey(string secret, string info)
        {
            using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret)))
            {
                var key = hmac.ComputeHash(Encoding.UTF8.GetBytes(info));
                var key24 = new byte[24];
                for (int i = 0; i < 24 && i < key.Length; i++)
                {
                    key24[i] = key[i];
                }
                bool empty = true;
                for (int i = 0; i < key24.Length; i++)
                {
                    if (key24[i] != 0)
                    {
                        empty = false;
                        break;
                    }
                }
                if (empty)
                {
                    throw new Exception("derived key is empty");
                }
                return Convert.ToBase64String(key24);
            }
        }

        public static string CoalesceToString(object value)
        {
            if (value is object[])
            {
                var arr = (object[])value;
                var sb = new StringBuilder();
                for (int i = 0; i < arr.Length; i++)
                {
                    if (arr[i] is string)
                    {
                        if (sb.Length > 0)
                        {
                            sb.Append(',');
                        }
                        sb.Append((string)arr[i]);
                    }
                }
                return sb.ToString();
            }
            if (value is string)
            {
                return (string)value;
            }
            return "";
        }
    }
}
