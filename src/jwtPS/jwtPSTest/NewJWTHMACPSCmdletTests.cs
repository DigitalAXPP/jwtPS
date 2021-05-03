using jwtPS.Enum;
using jwtPS.PwShCmdlet;
using System;
using System.Collections;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using Xunit;

namespace jwtPSTest
{
    public class NewJWTHMACPSCmdletTests
    {
        [Fact]
        public void NewJWTHMAC256()
        {
            //-- arrange
            var secret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
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

            //-- act
                    var newJWTCommand = new Command("New-JWT");
                    newJWTCommand.Parameters.Add("Secret", secret);
                    newJWTCommand.Parameters.Add("Payload", claim);

                    powershell.Commands.AddCommand(newJWTCommand);
                    var result = powershell.Invoke<string>();

            //-- assert
                    Assert.IsType<string>(result[0]);
                    Assert.Matches(regex, result[0]);
                }
            }
        }

        [Fact]
        public void NewJWTHMAC384()
        {
            //-- arrange
            var secret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
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

                    //-- act
                    var newJWTCommand = new Command("New-JWT");
                    newJWTCommand.Parameters.Add("Secret", secret);
                    newJWTCommand.Parameters.Add("Payload", claim);
                    newJWTCommand.Parameters.Add("Algorithm", Algorithm.HS384);

                    powershell.Commands.AddCommand(newJWTCommand);
                    var result = powershell.Invoke<string>();

                    //-- assert
                    Assert.IsType<string>(result[0]);
                    Assert.Matches(regex, result[0]);
                }
            }
        }

        [Fact]
        public void NewJWTHMAC512()
        {
            //-- arrange
            var secret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
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

                    //-- act
                    var newJWTCommand = new Command("New-JWT");
                    newJWTCommand.Parameters.Add("Secret", secret);
                    newJWTCommand.Parameters.Add("Payload", claim);
                    newJWTCommand.Parameters.Add("Algorithm", Algorithm.HS512);

                    powershell.Commands.AddCommand(newJWTCommand);
                    var result = powershell.Invoke<string>();

                    //-- assert
                    Assert.IsType<string>(result[0]);
                    Assert.Matches(regex, result[0]);
                }
            }
        }
    }
}
