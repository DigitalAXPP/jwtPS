using jwtPS.Extension;
using System.Collections;
using System.Management.Automation;

namespace jwtPS.PwShCmdlet
{
    [Cmdlet(VerbsData.ConvertFrom, "JWT", 
            SupportsShouldProcess = true, 
            ConfirmImpact = ConfirmImpact.Low)]
    public class ConvertFromJWTCmdlet : Cmdlet
    {
        [Parameter(
            Mandatory = true,
            ValueFromPipeline = true,
            Position = 1,
            HelpMessage = "Enter a valid JWT token.")]
        public string JWT { get; set; }

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            WriteVerbose("Converting a BASE64 string to as hashtable.");
        }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            if (ShouldProcess("Converting the Base64 string", 
                              "Are you sure to convert the Base64 string?", 
                              "Convert string"))
            {
                var jwtParts = JWT.Split('.');
                var table = new Hashtable()
                {
                    { "Header", Conversion.FromBase64(jwtParts[0]) },
                    { "Payload", Conversion.FromBase64(jwtParts[1]) }
                };
                WriteObject(table);
            }
        }

        protected override void EndProcessing()
        {
            base.EndProcessing();
        }

        protected override void StopProcessing()
        {
            base.StopProcessing();
        }
    }
}
