using jwtPS.Class;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
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
        [Fact]
        public void CreateJWTwithHMACTest()
        {
            //-- Arrange
            var payload = new List<KeyValuePair<string, object>>()
            {
                new KeyValuePair<string, object>( "aud", "jwtPS" ),
                new KeyValuePair<string, object>( "iss", "DigitalAXPP" ),
                new KeyValuePair<string, object>( "sub", "RS256 Test" ),
                new KeyValuePair<string, object>( "nbf", "0" ),
                new KeyValuePair<string, object>( "exp", DateTimeOffset.Now.AddDays(1).ToUnixTimeSeconds())
            };
            const string secret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
            var signature = new Signature(payload, "HS256");

            //-- Act
            var tokenBase64 = signature.Create(secret);
            var regex = @"(^[\w-]*\.[\w-]*\.[\w-]*$)";

            //-- Assert
            Assert.IsType<string>(tokenBase64);
            Assert.Matches(regex, tokenBase64);
        }

        [Fact]
        public void CreatewithRSA()
        {
            //-- Arrange
            var payload = new List<KeyValuePair<string, object>>()
            {
                new KeyValuePair<string, object>( "aud", "jwtPS" ),
                new KeyValuePair<string, object>( "iss", "DigitalAXPP" ),
                new KeyValuePair<string, object>( "sub", "RS256 Test" ),
                new KeyValuePair<string, object>( "nbf", "0" ),
                new KeyValuePair<string, object>( "exp", DateTimeOffset.Now.AddDays(1).ToUnixTimeSeconds())
            };
            var privatekey = @"
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
5h9Ey+dTqd9d5+lIRxlBjoQ=";
            var privateKeyBytes = Convert.FromBase64String(privatekey);
            using var rsapriv = RSA.Create();
            rsapriv.ImportPkcs8PrivateKey(privateKeyBytes, out _);
            var publickey = @"
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuMiAvsCXg6Xga/0bl8gj
bgGT4/6kgmgSFfaq9MozVelSbB9lC3b7/aklk73I2tsDAs3GDVArZcBS58AiGoT+
6yogfIzLKzjYbm9al9e+WdV408TbqyER7eb+Z7rjsTvAJnKbSq7SRm72/ED0OvgQ
iXXPjP95EWAwD4o7tIlJlgr3iuQ8E56K5Hr8nsRFUVLKCJDIQVcw+i2cv2zrnKeK
Au7Fyfxx2ifP9/4uh3pIjz3vdMO0MyeVJ/88ZcGwndE+T5t9wcEvzJ4/3sWW3sOa
I2PDI5/dlaxe2Iz9d/ZmPKlPtOIfZCP/xW1Ss/z6OZ/PQc0MNYFj1KMBalt6wmlE
8QIDAQAB
";
            var publicKeyBytes = Convert.FromBase64String(publickey);
            using var rsapub = RSA.Create();
            rsapub.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
            var signatureSHA256 = new Signature(payload, "RS256");
            var signatureSHA384 = new Signature(payload, "RS384");
            var signatureSHA512 = new Signature(payload, "RS512");

            //-- Act
            var jwt256 = signatureSHA256.Create(rsapriv, rsapub);
            var jwt384 = signatureSHA384.Create(rsapriv, rsapub);
            var jwt512 = signatureSHA512.Create(rsapriv, rsapub);
            var regex = @"(^[\w-]*\.[\w-]*\.[\w-]*$)";

            //-- Assert
            Assert.IsType<string>(jwt256);
            Assert.Matches(regex, jwt256);
            Assert.IsType<string>(jwt384);
            Assert.Matches(regex, jwt384);
            Assert.IsType<string>(jwt512);
            Assert.Matches(regex, jwt512);
        }

        [Fact]
        public void CreateJWTwithECDSA()
        {
            //-- Arrange
            var payload = new List<KeyValuePair<string, object>>()
            {
                new KeyValuePair<string, object>( "aud", "jwtPS" ),
                new KeyValuePair<string, object>( "iss", "DigitalAXPP" ),
                new KeyValuePair<string, object>( "sub", "RS256 Test" ),
                new KeyValuePair<string, object>( "nbf", "0" ),
                new KeyValuePair<string, object>( "exp", DateTimeOffset.Now.AddDays(1).ToUnixTimeSeconds())
            };
            var signature = new Signature(payload, "ES256");
            using var ecdsapriv = ECDsa.Create();
            var privatekey = @"MHcCAQEEIO9Xgf50T8VO6GkncN1Q2oF0kq3IBrbkI+SSphg98VE2oAoGCCqGSM49
AwEHoUQDQgAEN9S07l/929SmRhf0yTvTykjwJd/QJXARITRQ5B8e00aSKR7uuguy
feGQEbNDmL21aAhy7RqmQBhx3ZcO71apFA==";
            var privbytes = Convert.FromBase64String(privatekey);
            ecdsapriv.ImportECPrivateKey(privbytes, out _);
            var publickey = @"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEN9S07l/929SmRhf0yTvTykjwJd/Q
JXARITRQ5B8e00aSKR7uuguyfeGQEbNDmL21aAhy7RqmQBhx3ZcO71apFA==";
            var pubbytes = Convert.FromBase64String(publickey);
            using var ecdsapub = ECDsa.Create();
            ecdsapub.ImportSubjectPublicKeyInfo(pubbytes, out _);

            //-- Act
            var jwt = signature.Create(ecdsapub, ecdsapriv);

            //-- Assert
            Assert.NotEmpty(jwt);
        }
    }
}
