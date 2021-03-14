using jwtPS.Class;
using System;
using System.Collections.Generic;
using Xunit;

namespace jwtPSTest
{
    public class SignatureTests
    {
        [Fact]
        public void ConstructorTest()
        {
            //-- Arrange
            var payload = new List<KeyValuePair<string, object>>()
            {
                new KeyValuePair<string, object>( "aud", "jwtPS" ),
                new KeyValuePair<string, object>( "iss", "DigitalAXPP" ),
                new KeyValuePair<string, object>( "sub", "RS256 Test" ),
                new KeyValuePair<string, object>( "nbf", "0" ),
                new KeyValuePair<string, object>( "exp", DateTime.Today.AddDays(1))
            };

            //-- Act
            var signature = new Signature(payload, "HS256");

            //-- Assert
            Assert.IsType<Signature>(signature);
            Assert.Equal("HS256", signature.Algorithm);
        }
    }
}
