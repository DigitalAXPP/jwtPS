using jwtPS.Class;
using jwtPS.Enum;
using System.Collections;
using System.Management.Automation;

namespace jwtPS
{
    [Cmdlet(VerbsCommon.New, "JWT")]
    public class NewJWTCmdlet : PSCmdlet
    {
        [Parameter(Mandatory = true, HelpMessage = "Enter the private key.")]
        public string Privatekey { get; set; }
        [Parameter(HelpMessage = "Enter the desired algorithm for the JWT.")]
        public Algorithm Algorithm { get; set; }
        [Parameter(HelpMessage = "Enter the payload.")]
        public Hashtable Payload { get; set; }
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            var header = new Header(Algorithm).Create();
            var claimset = new Claimset().Create(Payload);
            WriteObject($"{header}.{claimset}");
        }
    }
}
