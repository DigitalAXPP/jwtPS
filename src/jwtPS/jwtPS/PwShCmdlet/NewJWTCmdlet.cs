using jwtPS.Enum;
using jwtPS.Extension;
using System.Collections;
using System.Management.Automation;
using Signature = jwtPS.Class.Signature;

namespace jwtPS.PwShCmdlet
{
    [Cmdlet(VerbsCommon.New, "JWT", 
            SupportsShouldProcess = true, 
            ConfirmImpact = ConfirmImpact.Low, 
            DefaultParameterSetName = "Secret")]
    [OutputType(typeof(string))]
    public class NewJWTCmdlet : Cmdlet
    {
        [Parameter(HelpMessage = "Enter the private key.",
                   Mandatory = true,
                   ParameterSetName = "Key")]
        public string Privatekey { get; set; }
        [Parameter(HelpMessage = "Enter the public key",
                   Mandatory = true,
                   ParameterSetName = "Key")]
        public string Publickey { get; set; }
        [Parameter(HelpMessage = "Enter the HMAC secret.",
                   Mandatory = true,
                   ParameterSetName = "Secret",
                   ValueFromPipeline = true)]
        public string Secret { get; set; }
        [Parameter(HelpMessage = "Enter the desired algorithm for the JWT.")]
        public Algorithm Algorithm { get; set; }
        [Parameter(HelpMessage = "Enter the payload.",
                   Mandatory = true)]
        public Hashtable Payload { get; set; }
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            var claim = Conversion.ToDictionary<string, object>(Payload);
            var jwt = new Signature(claim, Algorithm);
            string token = null;
            if (ShouldProcess("Creating a new Json Web Token",
                              "Do you want to create a new JWT?",
                              "Create JWT"))
            {
                switch (Algorithm)
                {
                    case Algorithm.HS256:
                    case Algorithm.HS384:
                    case Algorithm.HS512:
                        {
                            token = jwt.Create(Secret);
                        }
                        break;
                    case Algorithm.RS256:
                    case Algorithm.RS384:
                    case Algorithm.RS512:
                        {
                            var rsapriv = Conversion.ToRSA(Privatekey);
                            var rsapub = Conversion.ToRSA(Publickey);
                            token = jwt.Create(rsapriv, rsapub);
                        }
                        break;
                    case Algorithm.ES256:
                    case Algorithm.ES384:
                    case Algorithm.ES512:
                        {
                            var ecdsapriv = Conversion.ToECDsa(Privatekey);
                            var ecdsapub = Conversion.ToECDsa(Publickey);
                            token = jwt.Create(ecdsapub, ecdsapriv);
                        }
                        break;
                    default:
                        break;
                }
            }
            WriteObject(token);
        }
    }
}
