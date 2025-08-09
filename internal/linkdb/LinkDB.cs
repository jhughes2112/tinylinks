using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Tinylinks.Linkdb
{
    // Simple file-based link database
    public class LinkDB
    {
        private readonly string dir;
        private readonly object mu = new object();

        public LinkDB(string directory)
        {
            Directory.CreateDirectory(directory);
            dir = directory;
        }

        private string PathFor(string sub)
        {
            return Path.Combine(dir, sub + ".json");
        }

        public string[] Get(string sub)
        {
            lock (mu)
            {
                var path = PathFor(sub);
                if (!File.Exists(path))
                {
                    return Array.Empty<string>();
                }
                var data = File.ReadAllText(path);
                try
                {
                    var links = JsonSerializer.Deserialize<string[]>(data);
                    return links ?? Array.Empty<string>();
                }
                catch
                {
                    return Array.Empty<string>();
                }
            }
        }

        private void Save(string sub, string[] links)
        {
            var data = JsonSerializer.Serialize(links);
            File.WriteAllText(PathFor(sub), data);
        }

        private static bool Contains(string[] list, string item)
        {
            for (int i = 0; i < list.Length; i++)
            {
                if (list[i] == item) return true;
            }
            return false;
        }

        private static string[] Remove(string[] list, string item)
        {
            var res = new List<string>();
            for (int i = 0; i < list.Length; i++)
            {
                if (list[i] != item)
                {
                    res.Add(list[i]);
                }
            }
            return res.ToArray();
        }

        public void AddLink(string a, string b)
        {
            lock (mu)
            {
                var linksA = Get(a);
                if (!Contains(linksA, b))
                {
                    var newList = new string[linksA.Length + 1];
                    for (int i = 0; i < linksA.Length; i++) newList[i] = linksA[i];
                    newList[linksA.Length] = b;
                    Save(a, newList);
                }
                var linksB = Get(b);
                if (!Contains(linksB, a))
                {
                    var newList = new string[linksB.Length + 1];
                    for (int i = 0; i < linksB.Length; i++) newList[i] = linksB[i];
                    newList[linksB.Length] = a;
                    Save(b, newList);
                }
            }
        }

        public void RemoveLink(string a, string b)
        {
            lock (mu)
            {
                var linksA = Get(a);
                if (Contains(linksA, b))
                {
                    Save(a, Remove(linksA, b));
                }
                var linksB = Get(b);
                if (Contains(linksB, a))
                {
                    Save(b, Remove(linksB, a));
                }
            }
        }
    }
}
