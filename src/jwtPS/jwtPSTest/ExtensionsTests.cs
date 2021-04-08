﻿using jwtPS.Extension;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;
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

        [Fact]
        public void ToRSAPrivatekeyTest()
        {
            //-- Arrange
            var key = @"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC4yIC+wJeDpeBr
/RuXyCNuAZPj/qSCaBIV9qr0yjNV6VJsH2ULdvv9qSWTvcja2wMCzcYNUCtlwFLn
wCIahP7rKiB8jMsrONhub1qX175Z1XjTxNurIRHt5v5nuuOxO8AmcptKrtJGbvb8
QPQ6+BCJdc+M/3kRYDAPiju0iUmWCveK5DwTnorkevyexEVRUsoIkMhBVzD6LZy/
bOucp4oC7sXJ/HHaJ8/3/i6HekiPPe90w7QzJ5Un/zxlwbCd0T5Pm33BwS/Mnj/e
xZbew5ojY8Mjn92VrF7YjP139mY8qU+04h9kI//FbVKz/Po5n89BzQw1gWPUowFq
W3rCaUTxAgMBAAECggEAdchoOC6u5V1gVbU6V19dJgufZx6zYeRQUuuuQOZ6HnLg
9MZ2M/6d1SxyJWA9nTMpEipz6ZyGbQ9QSSSxGFJZ4zAxEPL1thE/8/TKvCrqzHxD
zkiW9NfZg9lPpHL+G8TIUDmRPuN8aSTmDhihFM12TQhpSai2VRsIx38HW6Z+30H8
sqv91Xx7vWVbEakmDn74Qxk/9nbEII9bKTHhRAYcq05W0FbavrX9YcjM2L1JgpN+
sVFgmE3Ge0xTZztYw9OIlLmwlC5MfhzlG4imUVuGGUFAfuzdTA4hbmg6wLTRcdUv
TcMZF7KTCtB68M9KpP+PjioKxB/rJPZh4m7GlmmPgQKBgQDk0TDjgAvYSIKnAEns
ly4JzQe8rEVFSfglkg4F+uglpCaoxwi0fdVmvGa5vqQZ7fmxZzp8qlayA3Pv/efx
nuYLUXM0AT8cLaz539eqPTI3G16s8UW3wZDTj9mVX9JjcVH/3StPbLxgoHz+Y513
qdB9Jz2Ue5yHX34E9rxvW4IG2QKBgQDOvCXLHbBTgysotIznkNIjUCdUm5xHo+HO
DCMbeZMqqIW+eTqJ1len/9QC5o7DLb5bj7YKCmBbMBjU1a0CmFSjhHlR0Ugi6hQA
Kxc93d7ZzbhTg7bXffkR5J3tHq0Mkik1YA1Zijn/qtr+Dr0N7YVvgjQHboZnxWDB
a3EzAejP2QKBgGc009BJWQ5c5lFdF/rW1bUl/W9kZHo0OvD3R8v6t+sCd015OLvw
ZejI4ay2CF6JsC4MWZ0RV7lDRW/iHlQlT62bN1MlnMmg8HxkMmpe399rQPDQgpm3
fRNvtrxhVAv2eP3nTDmu2ejbeoVjeQsYVSmeIXBvsNJ+h+DFSYkQxT1BAoGAMfHg
i46zn6lrzty3weYJ7oAZ0GX7vo8IKXhjLusTM9Yc4aR2EQDYknzK4pyC1wKBH6u7
hfd1yfH3vcuVja/xmsORb8PI0q6MgHHonoiwoxwBMSP8E1max8jcooGruwLAs+Vt
tDkhw/OqDoDPCcNdXlAtc7IvBHj55CCp63HFphkCgYEA3eHDbrPLKZToKvcJ7TI4
4azujEBqfq2Vc7vDn5T7fjPcUq8ZthdZADs6uL4EDdmCvjTmP68ndoJRWQiXfFQV
ddtmbgQcESw40/0fvd2NRABSZ/xbrKCFRiG6od0y9WSw1Kl0chMLlWhN1osbqbXZ
5h9Ey+dTqd9d5+lIRxlBjoQ=
-----END PRIVATE KEY-----";

            //-- Act
            var rsa = Conversion.ToRSA(key);

            //-- Assert
            Assert.IsAssignableFrom<RSA>(rsa);
        }

        [Fact]
        public void ToRSAPublickeyTest()
        {
            //-- Arrange
            var key = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuMiAvsCXg6Xga/0bl8gj
bgGT4/6kgmgSFfaq9MozVelSbB9lC3b7/aklk73I2tsDAs3GDVArZcBS58AiGoT+
6yogfIzLKzjYbm9al9e+WdV408TbqyER7eb+Z7rjsTvAJnKbSq7SRm72/ED0OvgQ
iXXPjP95EWAwD4o7tIlJlgr3iuQ8E56K5Hr8nsRFUVLKCJDIQVcw+i2cv2zrnKeK
Au7Fyfxx2ifP9/4uh3pIjz3vdMO0MyeVJ/88ZcGwndE+T5t9wcEvzJ4/3sWW3sOa
I2PDI5/dlaxe2Iz9d/ZmPKlPtOIfZCP/xW1Ss/z6OZ/PQc0MNYFj1KMBalt6wmlE
8QIDAQAB
-----END PUBLIC KEY-----";

            //-- Act
            var rsa = Conversion.ToRSA(key);

            //-- Assert
            Assert.IsAssignableFrom<RSA>(rsa);
        }
        /// <summary>
        /// This test uses an ES384 private key.
        /// </summary>
        [Fact]
        public void ToECDsaPrivatekeyTest()
        {
            //-- Arrange
            var key = @"-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDIBWp8sZe1ff5kmLHS3RFd1pHxOimPnO1vfrydzlm8UlYNBFnj0lrI
CoTPd1tg8HugBwYFK4EEACKhZANiAARtMhih0x3xd4OaZKXw64GApFQv2tPylyao
3gpcxbq62o6o0sk734KOwJTKkOVBElOJlAWRtkplBc9UkS7wQv7zo5cBwDO0v+nt
EzDFGAoqOg1lfMW22hDoyMCGywxdGhs=
-----END EC PRIVATE KEY-----";

            //-- Act
            var ecdsa = Conversion.ToECDsa(key);

            //-- Assert
            Assert.IsAssignableFrom<ECDsa>(ecdsa);
        }
        /// <summary>
        /// This test uses an ES384 public key.
        /// </summary>
        [Fact]
        public void ToECDsaPublickeyTest()
        {
            //-- Arrange
            var key = @"-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEfLxMoGVLJr4e4r/ZK2SUnT7vFauxSRPU
l6S+2JI3lVFxPChZMzSJju+jnkVAQ1QlxMhg8rt2ecp+ZBaC8zuoaFmThNQo+SFT
oGZhmXD3iid6G+xQ3aZCjoo5R6p0ilC3
-----END PUBLIC KEY-----";

            //-- Act
            var ecdsa = Conversion.ToECDsa(key);

            //-- Assert
            Assert.IsAssignableFrom<ECDsa>(ecdsa);
        }

        [Fact]
        public void FromBase64Test()
        {
            //-- Arrange
            var base64 = "V2VsY29tZSB0byB0aGUgand0UFMgbW9kdWxlIQ==";

            //-- Act
            var expected = "Welcome to the jwtPS module!";
            var actual = Conversion.FromBase64(base64);

            //-- Assert
            Assert.Equal(expected, actual);
        }
    }
}