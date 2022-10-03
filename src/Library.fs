namespace jwtPS
open System
open System.Collections
open System.Collections.Generic
open System.Management.Automation
open jwtFunction

[<Cmdlet("New", "Jwt")>]
[<OutputType(typeof<string>)>]
type NewJwtCommand () =
    inherit PSCmdlet ()
    [<Parameter(Mandatory=true)>]
    [<ValidateNotNullOrEmpty>]
    member val Payload : Hashtable = Hashtable () with get, set
    [<Parameter(Mandatory=true)>]
    member val Algorithm : Algorithm = HMAC SHA256 with get, set
    [<Parameter(Mandatory=true)>]
    [<ValidateNotNullOrEmpty>]
    member val Secret : string = String.Empty with get, set

    override x.ProcessRecord () =
        let jwt = newJwt x.Algorithm x.Payload x.Secret
        x.WriteObject (jwt)
        base.ProcessRecord ()

[<Cmdlet("ConvertFrom", "Jwt")>]
type ConvertFromJwtCommand () =
    inherit PSCmdlet ()
    [<Parameter(Mandatory=true)>]
    [<ValidateNotNullOrEmpty>]
    member val Jwt : string = String.Empty with get, set

    override x.ProcessRecord () =
        let jwtSplit = x.Jwt.Split "."
        let dict = Dictionary<string, string> ()
        dict.Add("Header", (convertFromBase64 jwtSplit.[0]))
        dict.Add("Claimset", (convertFromBase64 jwtSplit.[1]))
        x.WriteObject (dict)
        base.ProcessRecord ()