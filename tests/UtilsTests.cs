using Tinylinks.Utils;
using Xunit;

namespace Tinylinks.Tests
{
    public class UtilsTests
    {
        [Fact]
        public void Capitalize_UppercasesFirst()
        {
            var result = Utils.Capitalize("hello");
            Assert.Equal("Hello", result);
        }

        [Fact]
        public void ParseHeaders_BuildsMap()
        {
            var headers = Utils.ParseHeaders(new[] { "Key=Value" });
            Assert.True(headers.ContainsKey("Key"));
            Assert.Equal("Value", headers["Key"]);
        }
    }
}
