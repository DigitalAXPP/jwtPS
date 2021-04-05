using jwtPS.PwShCmdlet;
using System.Linq;
using Xunit;

namespace jwtPSTest
{
    public class ConvertFromJWTCmdletTests
    {
        [Fact]
        public void ConvertJWTTest()
        {
            //-- Arrange
            var base64 = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VFb0qJ1LRg_4ujbZoRMXnVkUgiuKq5KxWqNdbKq_G9Vvz-S1zZa9LPxtHWKa64zDl2ofkT8F6jBt_K4riU-fPg";

            //-- Act
            var cmdlet = new ConvertFromJWTCmdlet()
            {
                JWT = base64
            };
            var actual = cmdlet.Invoke().OfType<string>().ToList();

            //-- Assert
            Assert.IsType<string>(actual);
        }
    }
}
