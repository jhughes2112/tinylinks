using Tinylinks.Types;

namespace Tinylinks
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            var address = Environment.GetEnvironmentVariable("TINYLINKS_ADDRESS") ?? "0.0.0.0";
            var portStr = Environment.GetEnvironmentVariable("TINYLINKS_PORT");
            int port;
            if (!int.TryParse(portStr, out port))
            {
                port = 5000;
            }
            var config = new ServerConfig { Address = address, Port = port };

            var server = new Server.Server(config);
            server.Start(args);
        }
    }
}
