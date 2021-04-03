using jwtPS.Extension;
using System.Collections;
using System.Management.Automation;

namespace jwtPS.PwShCmdlet
{
    [Cmdlet(VerbsData.ConvertFrom, "JWT")]
    public class ConvertFromJWTCmdlet : Cmdlet
    {
        [Parameter(HelpMessage = "Enter a valid JWT token.")]
        public string JWT { get; set; }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();

            var jwtParts = JWT.Split('.');
            var table = new Hashtable()
            {
                { "Header", Conversion.FromBase64(jwtParts[0]) },
                { "Payload", Conversion.FromBase64(jwtParts[1]) }
            };
            WriteObject(table);
        }
    }
}
