using JWT.Algorithms;
using JWT.Builder;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace jwtPS.Class
{
    public class Signature
    {
        public List<KeyValuePair<string, object>> ClaimSet { get; set; }
        public string Algorithm { get; set; }

        public Signature(List<KeyValuePair<string, object>> Data, string Algorithm)
        {
            ClaimSet = Data;
            this.Algorithm = Algorithm;
        }

        public string Create(RSA PrivateKey, RSA PublicKey)
        {
            string token = null;
            switch (Algorithm)
            {
                case "RS256":
                    {
                        token = JwtBuilder.Create()
                                          .WithAlgorithm(new RS256Algorithm(PublicKey, PrivateKey))
                                          .AddClaims(ClaimSet)
                                          .MustVerifySignature()
                                          .Encode();
                    }
                    break;
                default:
                    break;
            }
            return token;
        }
        public string Create(string Secret)
        {
            var token = JwtBuilder.Create()
                                  .WithAlgorithm(new HMACSHA256Algorithm())
                                  .WithSecret(Secret)
                                  .AddClaims(ClaimSet)
                                  .Encode();
            return token;
        }
        public string Create(ECDsa PublicKey, ECDsa PrivateKey)
        {
            var token = JwtBuilder.Create()
                                          .WithAlgorithm(new ES256Algorithm(PublicKey, PrivateKey))
                                          .AddClaims(ClaimSet)
                                          .MustVerifySignature()
                                          .Encode();
            return token;
        }
    }
}
