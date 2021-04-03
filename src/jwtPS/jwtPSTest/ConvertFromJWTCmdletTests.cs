using jwtPS.Extension;
using Xunit;

namespace jwtPSTest
{
    public class ConvertFromJWTCmdletTests
    {
        [Fact]
        public void ConvertJWTTest()
        {
            //-- Arrange
            var base64 = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";

            //-- Act
            var actual = Conversion.FromBase64(base64);

            //-- Assert
            Assert.IsType<string>(actual);
        }
    }
}
