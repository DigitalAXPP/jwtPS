using JWT.Algorithms;
using JWT.Builder;
using jwtPS.Extension;
using System.Management.Automation;
using System.Text.Json;

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
            var parts = JWT.Split(".");
            var header = JsonSerializer.Deserialize<Class.JwtHeader>(Conversion.FromBase64(parts[0]));
            string builder = null;
            switch (header.alg)
            {
                case "HS256":
                    {
                        builder = JwtBuilder.Create()
                                            .WithAlgorithm(new HMACSHA256Algorithm())
                                            .WithSecret(Secret)
                                            .MustVerifySignature()
                                            .Decode(JWT);
                    }
                    break;
                case "HS384":
                    {
                        builder = JwtBuilder.Create()
                                            .WithAlgorithm(new HMACSHA384Algorithm())
                                            .WithSecret(Secret)
                                            .MustVerifySignature()
                                            .Decode(JWT);
                    }
                    break;
                case "HS512":
                    {
                        builder = JwtBuilder.Create()
                                            .WithAlgorithm(new HMACSHA512Algorithm())
                                            .WithSecret(Secret)
                                            .MustVerifySignature()
                                            .Decode(JWT);
                    }
                    break;
                case "RS256":
                    break;
                case "RS384":
                    break;
                case "RS512":
                    break;
                case "ES256":
                    break;
                case "ES384":
                    break;
                case "ES512":
                    break;
                default:
                    break;
            }
            WriteObject(builder);
        }
    }
}
