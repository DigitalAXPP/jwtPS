using jwtPS.Class;
using Xunit;

namespace jwtPSTest
{
    public class HeaderTests
    {
        [Fact]
        public void CreateTest()
        {
            //-- Arrange
            var jwt = new Header("HS256");

            //-- Act
            var header = jwt.Create();

            //-- Assert
            Assert.NotEmpty(header);
        }
    }
}
