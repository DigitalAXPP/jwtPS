using jwtPS.Enum;
using jwtPS.PwShCmdlet;
using System;
using System.Collections;
using System.Linq;
using Xunit;

namespace jwtPSTest
{
    public class TestJWTCmdletTests
    {
        [Fact]
        public void HMAC256Test()
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
            var jwt = cmdlet.Invoke().OfType<string>().ToList();
            var test = new TestJWTCmdlet()
            {
                Secret = secret,
                JWT = jwt[0]
            };

            //-- Act
            var result = test.Invoke().OfType<string>().ToList();

            //-- Assert
            Assert.IsType<string>(result[0]);
        }

        [Fact]
        public void HMAC384Test()
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
                Algorithm = Algorithm.HS384
            };
            var jwt = cmdlet.Invoke().OfType<string>().ToList();
            var test = new TestJWTCmdlet()
            {
                Secret = secret,
                JWT = jwt[0]
            };

            //-- Act
            var result = test.Invoke().OfType<string>().ToList();

            //-- Assert
            Assert.IsType<string>(result[0]);
        }

        [Fact]
        public void HMAC512Test()
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
                Algorithm = Algorithm.HS512
            };
            var jwt = cmdlet.Invoke().OfType<string>().ToList();
            var test = new TestJWTCmdlet()
            {
                Secret = secret,
                JWT = jwt[0]
            };

            //-- Act
            var result = test.Invoke().OfType<string>().ToList();

            //-- Assert
            Assert.IsType<string>(result[0]);
        }
    }
}
