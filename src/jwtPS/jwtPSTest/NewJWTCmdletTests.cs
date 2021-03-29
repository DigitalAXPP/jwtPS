using jwtPS;
using jwtPS.Enum;
using System;
using System.Collections;
using Xunit;

namespace jwtPSTest
{
    public class NewJWTCmdletTests
    {
        [Fact]
        public void HMACTests()
        {
            //-- Arrange
            var secret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
            var claim = new Hashtable()
            {
                { "name", "Alex" },
                { "age", 21},
                { "date", DateTimeOffset.Now.AddHours(3).ToUnixTimeSeconds() }
            };
            var cmdlet = new NewJWTCmdlet()
            {
                Secret = secret,
                Payload = claim,
                Algorithm = Algorithm.HS256
            };

            //-- Act
            var result = cmdlet.Invoke();

            //-- Assert
            Assert.NotNull(result);
        }
    }
}
