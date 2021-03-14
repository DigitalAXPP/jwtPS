using jwtPS.Class;
using System.Collections;
using Xunit;

namespace jwtPSTest
{
    public class ClaimsetTests
    {
        [Fact]
        public void Create()
        {
            //-- Arrange
            var claim = new Claimset();
            var hashtable = new Hashtable()
            {
                { "aud", "jwtPS" },
                { "iss", "DigitalAXPP" },
                { "sub", "RS256 Test" },
                { "nbf", "0" }
            };

            //-- Act
            var set = claim.Create(hashtable);

            //-- Assert
            Assert.NotEmpty(set);
        }
    }
}
