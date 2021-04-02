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
        public void HMAC256Tests()
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

        [Fact]
        public void HMAC384Tests()
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

            //-- Act
            var result = cmdlet.Invoke().OfType<string>().ToList();
            var regex = @"(^[\w-]*\.[\w-]*\.[\w-]*$)";

            //-- Assert
            Assert.IsType<string>(result[0]);
            Assert.Matches(regex, result[0]);
        }

        [Fact]
        public void HMAC512Tests()
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

            //-- Act
            var result = cmdlet.Invoke().OfType<string>().ToList();
            var regex = @"(^[\w-]*\.[\w-]*\.[\w-]*$)";

            //-- Assert
            Assert.IsType<string>(result[0]);
            Assert.Matches(regex, result[0]);
        }

        [Fact]
        public void RSA256Tests()
        {
            //-- Arrange
            var privatekey = @"-----BEGIN PRIVATE KEY-----
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
            var publickey = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuMiAvsCXg6Xga/0bl8gj
bgGT4/6kgmgSFfaq9MozVelSbB9lC3b7/aklk73I2tsDAs3GDVArZcBS58AiGoT+
6yogfIzLKzjYbm9al9e+WdV408TbqyER7eb+Z7rjsTvAJnKbSq7SRm72/ED0OvgQ
iXXPjP95EWAwD4o7tIlJlgr3iuQ8E56K5Hr8nsRFUVLKCJDIQVcw+i2cv2zrnKeK
Au7Fyfxx2ifP9/4uh3pIjz3vdMO0MyeVJ/88ZcGwndE+T5t9wcEvzJ4/3sWW3sOa
I2PDI5/dlaxe2Iz9d/ZmPKlPtOIfZCP/xW1Ss/z6OZ/PQc0MNYFj1KMBalt6wmlE
8QIDAQAB
-----END PUBLIC KEY-----";
            var claim = new Hashtable()
            {
                { "name", "Alex" },
                { "age", 21},
                { "date", DateTimeOffset.Now.AddHours(3).ToUnixTimeSeconds() }
            };
            var cmdlet = new NewJWTCmdlet()
            {
                Privatekey = privatekey,
                Publickey = publickey,
                Payload = claim,
                Algorithm = Algorithm.RS256
            };

            //-- Act
            var result = cmdlet.Invoke().OfType<string>().ToList();
            var regex = @"(^[\w-]*\.[\w-]*\.[\w-]*$)";

            //-- Assert
            Assert.IsType<string>(result[0]);
            Assert.Matches(regex, result[0]);
        }

        [Fact]
        public void RSA384Tests()
        {
            //-- Arrange
            var privatekey = @"-----BEGIN PRIVATE KEY-----
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
            var publickey = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuMiAvsCXg6Xga/0bl8gj
bgGT4/6kgmgSFfaq9MozVelSbB9lC3b7/aklk73I2tsDAs3GDVArZcBS58AiGoT+
6yogfIzLKzjYbm9al9e+WdV408TbqyER7eb+Z7rjsTvAJnKbSq7SRm72/ED0OvgQ
iXXPjP95EWAwD4o7tIlJlgr3iuQ8E56K5Hr8nsRFUVLKCJDIQVcw+i2cv2zrnKeK
Au7Fyfxx2ifP9/4uh3pIjz3vdMO0MyeVJ/88ZcGwndE+T5t9wcEvzJ4/3sWW3sOa
I2PDI5/dlaxe2Iz9d/ZmPKlPtOIfZCP/xW1Ss/z6OZ/PQc0MNYFj1KMBalt6wmlE
8QIDAQAB
-----END PUBLIC KEY-----";
            var claim = new Hashtable()
            {
                { "name", "Alex" },
                { "age", 21},
                { "date", DateTimeOffset.Now.AddHours(3).ToUnixTimeSeconds() }
            };
            var cmdlet = new NewJWTCmdlet()
            {
                Privatekey = privatekey,
                Publickey = publickey,
                Payload = claim,
                Algorithm = Algorithm.RS384
            };

            //-- Act
            var result = cmdlet.Invoke().OfType<string>().ToList();
            var regex = @"(^[\w-]*\.[\w-]*\.[\w-]*$)";

            //-- Assert
            Assert.IsType<string>(result[0]);
            Assert.Matches(regex, result[0]);
        }

        [Fact]
        public void RSA512Tests()
        {
            //-- Arrange
            var privatekey = @"-----BEGIN PRIVATE KEY-----
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
            var publickey = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuMiAvsCXg6Xga/0bl8gj
bgGT4/6kgmgSFfaq9MozVelSbB9lC3b7/aklk73I2tsDAs3GDVArZcBS58AiGoT+
6yogfIzLKzjYbm9al9e+WdV408TbqyER7eb+Z7rjsTvAJnKbSq7SRm72/ED0OvgQ
iXXPjP95EWAwD4o7tIlJlgr3iuQ8E56K5Hr8nsRFUVLKCJDIQVcw+i2cv2zrnKeK
Au7Fyfxx2ifP9/4uh3pIjz3vdMO0MyeVJ/88ZcGwndE+T5t9wcEvzJ4/3sWW3sOa
I2PDI5/dlaxe2Iz9d/ZmPKlPtOIfZCP/xW1Ss/z6OZ/PQc0MNYFj1KMBalt6wmlE
8QIDAQAB
-----END PUBLIC KEY-----";
            var claim = new Hashtable()
            {
                { "name", "Alex" },
                { "age", 21},
                { "date", DateTimeOffset.Now.AddHours(3).ToUnixTimeSeconds() }
            };
            var cmdlet = new NewJWTCmdlet()
            {
                Privatekey = privatekey,
                Publickey = publickey,
                Payload = claim,
                Algorithm = Algorithm.RS512
            };

            //-- Act
            var result = cmdlet.Invoke().OfType<string>().ToList();
            var regex = @"(^[\w-]*\.[\w-]*\.[\w-]*$)";

            //-- Assert
            Assert.IsType<string>(result[0]);
            Assert.Matches(regex, result[0]);
        }

        [Fact]
        public void ES256Tests()
        {
            //-- Arrange
            var privatekey = @"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIO9Xgf50T8VO6GkncN1Q2oF0kq3IBrbkI+SSphg98VE2oAoGCCqGSM49
AwEHoUQDQgAEN9S07l/929SmRhf0yTvTykjwJd/QJXARITRQ5B8e00aSKR7uuguy
feGQEbNDmL21aAhy7RqmQBhx3ZcO71apFA==
-----END EC PRIVATE KEY-----";
            var publickey = @"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEN9S07l/929SmRhf0yTvTykjwJd/Q
JXARITRQ5B8e00aSKR7uuguyfeGQEbNDmL21aAhy7RqmQBhx3ZcO71apFA==
-----END PUBLIC KEY-----";
            var claim = new Hashtable()
            {
                { "name", "Alex" },
                { "age", 21},
                { "date", DateTimeOffset.Now.AddHours(3).ToUnixTimeSeconds() }
            };

            var cmdlet = new NewJWTCmdlet()
            {
                Privatekey = privatekey,
                Publickey = publickey,
                Payload = claim,
                Algorithm = Algorithm.ES256
            };

            //-- Act
            var result = cmdlet.Invoke().OfType<string>().ToList();
            var regex = @"(^[\w-]*\.[\w-]*\.[\w-]*$)";

            //-- Assert
            Assert.IsType<string>(result[0]);
            Assert.Matches(regex, result[0]);
        }

        [Fact]
        public void ES384Tests()
        {
            //-- Arrange
            var privatekey = @"-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDIBWp8sZe1ff5kmLHS3RFd1pHxOimPnO1vfrydzlm8UlYNBFnj0lrI
CoTPd1tg8HugBwYFK4EEACKhZANiAARtMhih0x3xd4OaZKXw64GApFQv2tPylyao
3gpcxbq62o6o0sk734KOwJTKkOVBElOJlAWRtkplBc9UkS7wQv7zo5cBwDO0v+nt
EzDFGAoqOg1lfMW22hDoyMCGywxdGhs=
-----END EC PRIVATE KEY-----";
            var publickey = @"-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEbTIYodMd8XeDmmSl8OuBgKRUL9rT8pcm
qN4KXMW6utqOqNLJO9+CjsCUypDlQRJTiZQFkbZKZQXPVJEu8EL+86OXAcAztL/p
7RMwxRgKKjoNZXzFttoQ6MjAhssMXRob
-----END PUBLIC KEY-----";
            var claim = new Hashtable()
            {
                { "name", "Alex" },
                { "age", 21},
                { "date", DateTimeOffset.Now.AddHours(3).ToUnixTimeSeconds() }
            };

            var cmdlet = new NewJWTCmdlet()
            {
                Privatekey = privatekey,
                Publickey = publickey,
                Payload = claim,
                Algorithm = Algorithm.ES384
            };

            //-- Act
            var result = cmdlet.Invoke().OfType<string>().ToList();
            var regex = @"(^[\w-]*\.[\w-]*\.[\w-]*$)";

            //-- Assert
            Assert.IsType<string>(result[0]);
            Assert.Matches(regex, result[0]);
        }

        [Fact]
        public void ES512Tests()
        {
            //-- Arrange
            var privatekey = @"-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIB383k8S7qBj3/wbufXKbnuXKVLhlZ+Rpzeox3Dc9phmLaKHKggePA
SivMyCaR7MZMWsYJ5UdG/covRbXxuQaenQqgBwYFK4EEACOhgYkDgYYABAFBKL3L
sMgI9Xc443ef8I63bS5hz703VtroGvOBQv4zuY2V8y3amqdgjas7FQlI4ZNQBohs
LHIRTaJy/uqpi3T3JAHLriR1QzEQ5S/WUiKx0iPUcM6ItuMaByaZGb11YMw/ygIy
+mpcE0LEEtuVsSuzuSSc5nnvgreD6h+mhHzKNxVOog==
-----END EC PRIVATE KEY-----";
            var publickey = @"-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBQSi9y7DICPV3OON3n/COt20uYc+9
N1ba6BrzgUL+M7mNlfMt2pqnYI2rOxUJSOGTUAaIbCxyEU2icv7qqYt09yQBy64k
dUMxEOUv1lIisdIj1HDOiLbjGgcmmRm9dWDMP8oCMvpqXBNCxBLblbErs7kknOZ5
74K3g+ofpoR8yjcVTqI=
-----END PUBLIC KEY-----";
            var claim = new Hashtable()
            {
                { "name", "Alex" },
                { "age", 21},
                { "date", DateTimeOffset.Now.AddHours(3).ToUnixTimeSeconds() }
            };

            var cmdlet = new NewJWTCmdlet()
            {
                Privatekey = privatekey,
                Publickey = publickey,
                Payload = claim,
                Algorithm = Algorithm.ES512
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
