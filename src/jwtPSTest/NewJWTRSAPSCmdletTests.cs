﻿using jwtPS.Enum;
using jwtPS.PwShCmdlet;
using System;
using System.Collections;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using Xunit;

namespace jwtPSTest
{
    public class NewJWTRSAPSCmdletTests
    {
        [Fact]
        public void NewJWTRSA256()
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
            var regex = @"(^[\w-]*\.[\w-]*\.[\w-]*$)";
            var initialSessionState = InitialSessionState.CreateDefault();
            initialSessionState.Commands.Add(
                new SessionStateCmdletEntry(
                    "New-JWT", typeof(NewJWTCmdlet), null)
                );
            using (var runspace = RunspaceFactory.CreateRunspace(initialSessionState))
            {
                runspace.Open();
                using (var powershell = PowerShell.Create())
                {
                    powershell.Runspace = runspace;

                    //-- Act
                    var newJWTCommand = new Command("New-JWT");
                    newJWTCommand.Parameters.Add("Privatekey", privatekey);
                    newJWTCommand.Parameters.Add("Publickey", publickey);
                    newJWTCommand.Parameters.Add("Payload", claim);
                    newJWTCommand.Parameters.Add("Algorithm", Algorithm.RS256);

                    powershell.Commands.AddCommand(newJWTCommand);
                    var result = powershell.Invoke<string>();

                    //-- Assert
                    Assert.IsType<string>(result[0]);
                    Assert.Matches(regex, result[0]);
                }
            }
        }

        [Fact]
        public void NewJWTRSA384()
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
            var regex = @"(^[\w-]*\.[\w-]*\.[\w-]*$)";
            var initialSessionState = InitialSessionState.CreateDefault();
            initialSessionState.Commands.Add(
                new SessionStateCmdletEntry(
                    "New-JWT", typeof(NewJWTCmdlet), null)
                );
            using (var runspace = RunspaceFactory.CreateRunspace(initialSessionState))
            {
                runspace.Open();
                using (var powershell = PowerShell.Create())
                {
                    powershell.Runspace = runspace;

                    //-- Act
                    var newJWTCommand = new Command("New-JWT");
                    newJWTCommand.Parameters.Add("Privatekey", privatekey);
                    newJWTCommand.Parameters.Add("Publickey", publickey);
                    newJWTCommand.Parameters.Add("Payload", claim);
                    newJWTCommand.Parameters.Add("Algorithm", Algorithm.RS384);

                    powershell.Commands.AddCommand(newJWTCommand);
                    var result = powershell.Invoke<string>();

                    //-- Assert
                    Assert.IsType<string>(result[0]);
                    Assert.Matches(regex, result[0]);
                }
            }
        }

        [Fact]
        public void NewJWTRSA512()
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
            var regex = @"(^[\w-]*\.[\w-]*\.[\w-]*$)";
            var initialSessionState = InitialSessionState.CreateDefault();
            initialSessionState.Commands.Add(
                new SessionStateCmdletEntry(
                    "New-JWT", typeof(NewJWTCmdlet), null)
                );
            using (var runspace = RunspaceFactory.CreateRunspace(initialSessionState))
            {
                runspace.Open();
                using (var powershell = PowerShell.Create())
                {
                    powershell.Runspace = runspace;

                    //-- Act
                    var newJWTCommand = new Command("New-JWT");
                    newJWTCommand.Parameters.Add("Privatekey", privatekey);
                    newJWTCommand.Parameters.Add("Publickey", publickey);
                    newJWTCommand.Parameters.Add("Payload", claim);
                    newJWTCommand.Parameters.Add("Algorithm", Algorithm.RS512);

                    powershell.Commands.AddCommand(newJWTCommand);
                    var result = powershell.Invoke<string>();

                    //-- Assert
                    Assert.IsType<string>(result[0]);
                    Assert.Matches(regex, result[0]);
                }
            }
        }
    }
}