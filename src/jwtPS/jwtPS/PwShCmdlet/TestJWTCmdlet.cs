using JWT.Algorithms;
using JWT.Builder;
using System.Management.Automation;

namespace jwtPS.PwShCmdlet
{
    [Cmdlet(VerbsDiagnostic.Test, "JWT")]
    public class TestJWTCmdlet : Cmdlet
    {
        [Parameter(HelpMessage = "Enter the JWT.")]
        public string JWT { get; set; }
        [Parameter(HelpMessage = "Enter the secret.")]
        public string Secret { get; set; }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            var builder = JwtBuilder.Create()
                                    .WithAlgorithm(new HMACSHA256Algorithm())
                                    .WithSecret(Secret)
                                    .MustVerifySignature()
                                    .Decode(JWT);
            WriteObject(builder);
        }
    }
}
