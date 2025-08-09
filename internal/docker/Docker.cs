using Tinylinks.Types;

namespace Tinylinks.Docker
{
    public class Docker
    {
        public Docker()
        {
        }

        public bool DockerConnected()
        {
            return false;
        }

        public Labels GetLabels(string app, string domain)
        {
            return new Labels();
        }
    }
}
