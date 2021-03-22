using jwtPS.Enum;
using System.Collections.Generic;
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
        [Parameter(HelpMessage = "Enter the desired algorithm for the JWT.")]
        public Algorithm Algorithm { get; set; }
        [Parameter(HelpMessage = "Enter the payload.")]
        public Dictionary<string, object> Payload { get; set; }
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            //var header = new Header(Algorithm).Create();
            //var claimset = new Claimset().Create(Payload);
            var jwt = new Signature(Payload, Algorithm);
            //switch (ParameterSetName)
            //{
            //    default:
            //        break;
            //}
            WriteObject("Test");
        }
    }
}
