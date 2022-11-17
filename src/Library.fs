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
        Mandatory=true,
        ValueFromPipelineByPropertyName=true)>]
    [<ValidateNotNullOrEmpty>]
    member val Payload : Hashtable = Hashtable () with get, set
    [<Parameter(
        Mandatory=true,
        ValueFromPipelineByPropertyName=true)>]
    member val Algorithm : cryptographyType = { Algorithm = HMAC; Encryption = SHA256 } with get, set
    [<Parameter(
        Mandatory=true,
        ValueFromPipelineByPropertyName=true)>]
    [<ValidateNotNullOrEmpty>]
    member val Secret : string = String.Empty with get, set

    override x.ProcessRecord () =
        let jwt = newJwt x.Algorithm x.Payload x.Secret
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