namespace jwtPS
open System
open System.Collections
open System.Collections.Generic
open System.Management.Automation
open jwtFunction
open jwtTypes

[<Cmdlet("New", "Jwt")>]
[<OutputType(typeof<string>)>]
type NewJwtCommand () =
    inherit PSCmdlet ()
    [<Parameter(
        HelpMessage="Provide the claimset of the JWT in hashtable.",
        Mandatory=true,
        ValueFromPipelineByPropertyName=true)>]
    [<ValidateNotNullOrEmpty>]
    member val Payload : Hashtable = Hashtable () with get, set
    [<Parameter(
        HelpMessage="Set the Algorithm how you want your JWT to be signed.",
        Mandatory=true,
        ValueFromPipelineByPropertyName=true)>]
    member val Algorithm : cryptographyType = { Algorithm = HMAC; Encryption = SHA256 } with get, set
    [<Parameter(
        HelpMessage="Here you can provide a hashtable with additional parameters for the JWT header.",
        Mandatory=false,
        ValueFromPipelineByPropertyName=true)>]
    member val Header : Hashtable = Hashtable () with get, set
    [<Parameter(
        HelpMessage="Provide the key file content or HMAC secret.",
        ParameterSetName="Key",
        Mandatory=true,
        ValueFromPipelineByPropertyName=true)>]
    [<ValidateNotNullOrEmpty>]
    member val Secret : string = String.Empty with get, set
    [<Parameter(
        HelpMessage="Provide the path to the key.",
        ParameterSetName="FilePath",
        Mandatory=true,
        ValueFromPipelineByPropertyName=true)>]
    [<ValidateNotNullOrEmpty>]
    member val FilePath : System.IO.FileInfo = null with get, set

    override x.BeginProcessing () =
        x.WriteDebug ($"Parameter set: {x.ParameterSetName}")
        base.BeginProcessing()

    override x.ProcessRecord () =
        let jwt = 
                match x.ParameterSetName with
                | "Key" -> newJwtWithPemContent x.Algorithm x.Payload x.Secret
                | "FilePath" -> if x.FilePath.Extension = ".pem" then
                                    x.WriteDebug ("The file extension matches .pem")
                                    newJwtWithPemFile x.Algorithm x.Payload x.FilePath.FullName x.Header
                                else
                                    x.WriteDebug ("The file extension doesn't match .pem")
                                    newJwtWithDerFile x.Algorithm x.Payload x.FilePath.FullName
                | _ -> "Incorrect ParameterSet selected."
          
        x.WriteObject (jwt)
        base.ProcessRecord ()

[<Cmdlet("ConvertFrom", "Jwt")>]
type ConvertFromJwtCommand () =
    inherit PSCmdlet ()
    [<Parameter(
        Mandatory=true,
        ValueFromPipeline=true)>]
    [<ValidateNotNullOrEmpty>]
    [<ValidatePattern(@"(^[\w-]+\.[\w-]+\.[\w-]+$)")>]
    member val Jwt : string = String.Empty with get, set

    override x.ProcessRecord () =
        x.WriteVerbose ($"The JWT you provided is:\r\n{x.Jwt}")
        let jwtSplit = x.Jwt.Split "."
        x.WriteDebug ($"The three parts of the JWT are:\r\n{jwtSplit.[0]}\r\n{jwtSplit.[1]}\r\n{jwtSplit.[2]}")
        let dict = Dictionary<string, string> ()
        dict.Add("Header", (convertFromBase64 jwtSplit.[0]))
        dict.Add("Claimset", (convertFromBase64 jwtSplit.[1]))
        x.WriteObject (dict)
        base.ProcessRecord ()