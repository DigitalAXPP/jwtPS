using JWT.Algorithms;
using JWT.Builder;
using jwtPS.Extension;
using System.Management.Automation;
using System.Text.Json;

namespace jwtPS.PwShCmdlet
{
    /// <summary>
    /// <para type="synopsis">The command verifies the JWT.</para>
    /// <para type="description">The command verifies the validity of the JWT signature and returns the content of the header and body.</para>
    /// </summary>
    [Cmdlet(VerbsDiagnostic.Test, "JWT", 
            SupportsShouldProcess = true, 
            ConfirmImpact = ConfirmImpact.Low, 
            DefaultParameterSetName = "Secret")]
    public class TestJWTCmdlet : Cmdlet
    {
        [Parameter(HelpMessage = "Enter the JWT.",
                   Mandatory = true,
                   ValueFromPipeline = true)]
        [ValidatePattern(@"(^[\w-]*\.[\w-]*\.[\w-]*$)")]
        public string JWT { get; set; }

        [Parameter(HelpMessage = "Enter the secret.",
                   Mandatory = true,
                   ParameterSetName = "Secret")]
        public string Secret { get; set; }

        [Parameter(HelpMessage = "Enter the public key.",
                   Mandatory = true,
                   ParameterSetName = "Key")]
        public string Publickey { get; set; }

        [Parameter(HelpMessage = "Enter the private key.",
                   Mandatory = true,
                   ParameterSetName = "Key")]
        public string Privatekey { get; set; }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            var parts = JWT.Split(".");
            var header = JsonSerializer.Deserialize<Class.JwtHeader>(Conversion.FromBase64(parts[0]));
            WriteDebug($"The header is: {header}");
            string builder = null;
            if (ShouldProcess("Verifying the JWT.",
                              "Do you want to verify the Json Web Token?",
                              "JWT verification"))
            {
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
                        {
                            var pubkey = Conversion.ToRSA(Publickey);
                            var privkey = Conversion.ToRSA(Privatekey);
                            builder = JwtBuilder.Create()
                                                .WithAlgorithm(new RS256Algorithm(pubkey, privkey))
                                                .MustVerifySignature()
                                                .Decode(JWT);
                        }
                        break;
                    case "RS384":
                        {
                            var pubkey = Conversion.ToRSA(Publickey);
                            var privkey = Conversion.ToRSA(Privatekey);
                            builder = JwtBuilder.Create()
                                                .WithAlgorithm(new RS384Algorithm(pubkey, privkey))
                                                .MustVerifySignature()
                                                .Decode(JWT);
                        }
                        break;
                    case "RS512":
                        {
                            var pubkey = Conversion.ToRSA(Publickey);
                            var privkey = Conversion.ToRSA(Privatekey);
                            builder = JwtBuilder.Create()
                                                .WithAlgorithm(new RS512Algorithm(pubkey, privkey))
                                                .MustVerifySignature()
                                                .Decode(JWT);
                        }
                        break;
                    //case "ES256":
                    //    {
                    //        var pubkey = Conversion.ToECDsa(Publickey);
                    //        var privkey = Conversion.ToECDsa(Privatekey);
                    //        builder = JwtBuilder.Create()
                    //                            .WithAlgorithm(new ES256Algorithm(pubkey, privkey))
                    //                            .MustVerifySignature()
                    //                            .Decode(JWT);
                    //    }
                    //    break;
                    //case "ES384":
                    //    {
                    //        var pubkey = Conversion.ToECDsa(Publickey);
                    //        var privkey = Conversion.ToECDsa(Privatekey);
                    //        builder = JwtBuilder.Create()
                    //                            .WithAlgorithm(new ES384Algorithm(pubkey, privkey))
                    //                            .MustVerifySignature()
                    //                            .Decode(JWT);
                    //    }
                    //    break;
                    //case "ES512":
                    //    {
                    //        var pubkey = Conversion.ToECDsa(Publickey);
                    //        var privkey = Conversion.ToECDsa(Privatekey);
                    //        builder = JwtBuilder.Create()
                    //                            .WithAlgorithm(new ES512Algorithm(pubkey, privkey))
                    //                            .MustVerifySignature()
                    //                            .Decode(JWT);
                    //    }
                    //    break;
                    default:
                        break;
                }
                WriteObject(builder);
            }
        }
    }
}