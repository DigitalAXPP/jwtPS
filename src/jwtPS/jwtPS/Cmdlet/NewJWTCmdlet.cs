using jwtPS.Enum;
using jwtPS.Extension;
using System.Collections;
using System.Management.Automation;
using Signature = jwtPS.Class.Signature;

namespace jwtPS
{
    [Cmdlet(VerbsCommon.New, "JWT")]
    public class NewJWTCmdlet : PSCmdlet
    {
        [Parameter(HelpMessage = "Enter the private key.")]
        public string Privatekey { get; set; }
        [Parameter(HelpMessage = "Enter the public key")]
        public string Publickey { get; set; }
        [Parameter(HelpMessage = "Enter the HMAC secret.")]
        public string Secret { get; set; }
        [Parameter(HelpMessage = "Enter the desired algorithm for the JWT.")]
        public Algorithm Algorithm { get; set; }
        [Parameter(HelpMessage = "Enter the payload.")]
        public Hashtable Payload { get; set; }
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            //var header = new Header(Algorithm).Create();
            //var claimset = new Claimset().Create(Payload);
            var claim = Conversion.ToDictionary<string, object>(Payload);
            var jwt = new Signature(claim, Algorithm);
            var rsapriv = Conversion.ToRSA(Privatekey);
            var rsapub = Conversion.ToRSA(Publickey);
            string token = null;
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
                        token = jwt.Create(rsapriv, rsapub);
                    }
                    break;
                default:
                    break;
            }
            WriteObject(token);
        }
    }
}
