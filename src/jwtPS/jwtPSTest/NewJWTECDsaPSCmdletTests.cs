using jwtPS.Enum;
using jwtPS.PwShCmdlet;
using System;
using System.Collections;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using Xunit;

namespace jwtPSTest
{
    public class NewJWTECDsaPSCmdletTests
    {
        [Fact]
        public void NewJWTECDsa256()
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
                    newJWTCommand.Parameters.Add("Algorithm", Algorithm.ES256);

                    powershell.Commands.AddCommand(newJWTCommand);
                    var result = powershell.Invoke<string>();

                    //-- Assert
                    Assert.IsType<string>(result[0]);
                    Assert.Matches(regex, result[0]);
                }
            }
        }

        [Fact]
        public void NewJWTECDsa384()
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
                    newJWTCommand.Parameters.Add("Algorithm", Algorithm.ES384);

                    powershell.Commands.AddCommand(newJWTCommand);
                    var result = powershell.Invoke<string>();

                    //-- Assert
                    Assert.IsType<string>(result[0]);
                    Assert.Matches(regex, result[0]);
                }
            }
        }

        [Fact]
        public void NewJWTECDsa512()
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
                    newJWTCommand.Parameters.Add("Algorithm", Algorithm.ES512);

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
