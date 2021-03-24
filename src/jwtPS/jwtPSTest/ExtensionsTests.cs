using jwtPS.Extension;
using System;
using System.Collections;
using System.Collections.Generic;
using Xunit;

namespace jwtPSTest
{
    public class ExtensionsTests
    {
        [Fact]
        public void ToDictionaryTest()
        {
            //-- Arrange
            var table = new Hashtable()
            {
                {"UK", "London, Manchester, Birmingham"},
                {"Date", new DateTimeOffset().ToUnixTimeSeconds()},
                {"Age", 32}
            };

            //-- Act
            var dict = Conversion.ToDictionary<string, object>(table);

            //-- Assert
            Assert.IsType<Dictionary<string, object>>(dict);
        }
    }
}
