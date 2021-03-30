using jwtPS.Enum;
using jwtPS.PwShCmdlet;
using System;
using System.Collections;
using System.Linq;
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
            var result = cmdlet.Invoke().OfType<string>().ToList();
            var regex = @"(^[\w-]*\.[\w-]*\.[\w-]*$)";

            //-- Assert
            Assert.IsType<string>(result[0]);
            Assert.Matches(regex, result[0]);
        }
    }
}
