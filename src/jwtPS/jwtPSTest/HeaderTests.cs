using jwtPS.Class;
using jwtPS.Enum;
using Xunit;

namespace jwtPSTest
{
    public class HeaderTests
    {
        [Fact]
        public void CreateTest()
        {
            //-- Arrange
            var jwt = new Header(Algorithm.HS256);

            //-- Act
            var header = jwt.Create();

            //-- Assert
            Assert.NotEmpty(header);
        }
    }
}
