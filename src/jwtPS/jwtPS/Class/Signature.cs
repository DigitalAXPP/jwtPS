using JWT.Algorithms;
using JWT.Builder;
using jwtPS.Enum;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace jwtPS.Class
{
    public class Signature
    {
        public Dictionary<string, object> ClaimSet { get; set; }
        public Algorithm Algorithm { get; set; }


        public Signature(Dictionary<string, object> Data, Algorithm Algorithm)
        {
            ClaimSet = Data;
            this.Algorithm = Algorithm;
        }
        /// <summary>
        /// The method returns a JWT with an RSA key pair.
        /// </summary>
        /// <param name="PrivateKey"></param>
        /// <param name="PublicKey"></param>
        /// <returns>string</returns>
        public string Create(RSA PrivateKey, RSA PublicKey)
        {
            string token = null;
            switch (Algorithm)
            {
                case Algorithm.RS256:
                    {
                        token = JwtBuilder.Create()
                                          .WithAlgorithm(new RS256Algorithm(PublicKey, PrivateKey))
                                          .AddClaims(ClaimSet)
                                          .MustVerifySignature()
                                          .Encode();
                    }
                    break;
                case Algorithm.RS384:
                    {
                        token = JwtBuilder.Create()
                                          .WithAlgorithm(new RS384Algorithm(PublicKey, PrivateKey))
                                          .AddClaims(ClaimSet)
                                          .MustVerifySignature()
                                          .Encode();
                    }
                    break;
                case Algorithm.RS512:
                    {
                        token = JwtBuilder.Create()
                                          .WithAlgorithm(new RS512Algorithm(PublicKey, PrivateKey))
                                          .AddClaims(ClaimSet)
                                          .MustVerifySignature()
                                          .Encode();
                    }
                    break;
                default:
                    break;
            }
            PublicKey.Dispose();
            PrivateKey.Dispose();
            return token;
        }
        /// <summary>
        /// This method returns a JWT with an HMAC signature. Create a secret which will be used for encryption and decryption
        /// </summary>
        /// <param name="Secret"></param>
        /// <returns>string</returns>
        public string Create(string Secret)
        {
            string token = null;
            switch (Algorithm)
            {
                case Algorithm.HS256:
                    {
                        token = JwtBuilder.Create()
                                          .WithAlgorithm(new HMACSHA256Algorithm())
                                          .WithSecret(Secret)
                                          .AddClaims(ClaimSet)
                                          .Encode();
                    }
                    break;
                case Algorithm.HS384:
                    {
                        token = JwtBuilder.Create()
                                          .WithAlgorithm(new HMACSHA384Algorithm())
                                          .WithSecret(Secret)
                                          .AddClaims(ClaimSet)
                                          .Encode();
                    }
                    break;
                case Algorithm.HS512:
                    {
                        token = JwtBuilder.Create()
                                          .WithAlgorithm(new HMACSHA512Algorithm())
                                          .WithSecret(Secret)
                                          .AddClaims(ClaimSet)
                                          .Encode();
                    }
                    break;
                default:
                    break;
            }
            return token;
        }
        /// <summary>
        /// This method returns a JWT with an ECDsa key pair.
        /// </summary>
        /// <param name="PublicKey"></param>
        /// <param name="PrivateKey"></param>
        /// <returns>string</returns>
        public string Create(ECDsa PublicKey, ECDsa PrivateKey)
        {
            string token = null;
            switch (Algorithm)
            {
                case Algorithm.ES256:
                    {
                        token = JwtBuilder.Create()
                                          .WithAlgorithm(new ES256Algorithm(PublicKey, PrivateKey))
                                          .AddClaims(ClaimSet)
                                          .MustVerifySignature()
                                          .Encode();
                    }
                    break;
                case Algorithm.ES384:
                    {
                        token = JwtBuilder.Create()
                                          .WithAlgorithm(new ES384Algorithm(PublicKey, PrivateKey))
                                          .AddClaims(ClaimSet)
                                          .MustVerifySignature()
                                          .Encode();
                    }
                    break;
                case Algorithm.ES512:
                    {
                        token = JwtBuilder.Create()
                                          .WithAlgorithm(new ES512Algorithm(PublicKey, PrivateKey))
                                          .AddClaims(ClaimSet)
                                          .MustVerifySignature()
                                          .Encode();
                    }
                    break;
                default:
                    break;
            }
            PublicKey.Dispose();
            PrivateKey.Dispose();
            return token;
        }
    }
}
