using System;
using System.IO;

namespace Tinylinks.Assets
{
    public static class Assets
    {
        private static readonly string Root = Path.Combine(Directory.GetCurrentDirectory(), "assets");

        public static byte[] Read(string relativePath)
        {
            var fullPath = Path.GetFullPath(Path.Combine(Root, relativePath));
            if (!fullPath.StartsWith(Root))
            {
                throw new IOException("Invalid asset path");
            }

            return File.ReadAllBytes(fullPath);
        }
    }
}
