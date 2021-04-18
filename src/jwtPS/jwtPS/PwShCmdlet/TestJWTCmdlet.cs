﻿using JWT.Algorithms;
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
        [Parameter(HelpMessage = "Enter the public key.")]
        public string Publickey { get; set; }
        [Parameter(HelpMessage = "Enter the private key.")]
        public string Privatekey { get; set; }

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
                case "ES256":
                    {
                        var pubkey = Conversion.ToECDsa(Publickey);
                        var privkey = Conversion.ToECDsa(Privatekey);
                        builder = JwtBuilder.Create()
                                            .WithAlgorithm(new ES256Algorithm(pubkey, privkey))
                                            .MustVerifySignature()
                                            .Decode(JWT);
                    }
                    break;
                case "ES384":
                    {
                        var pubkey = Conversion.ToECDsa(Publickey);
                        var privkey = Conversion.ToECDsa(Privatekey);
                        builder = JwtBuilder.Create()
                                            .WithAlgorithm(new ES384Algorithm(pubkey, privkey))
                                            .MustVerifySignature()
                                            .Decode(JWT);
                    }
                    break;
                case "ES512":
                    {
                        var pubkey = Conversion.ToECDsa(Publickey);
                        var privkey = Conversion.ToECDsa(Privatekey);
                        builder = JwtBuilder.Create()
                                            .WithAlgorithm(new ES512Algorithm(pubkey, privkey))
                                            .MustVerifySignature()
                                            .Decode(JWT);
                    }
                    break;
                default:
                    break;
            }
            WriteObject(builder);
        }
    }
}
