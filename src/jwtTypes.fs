module jwtTypes

open Microsoft.FSharp.Collections
open System.Text.Json
open System.Collections
open System

    //type jwtHeader = 
    //    {
    //        typ: string
    //        alg: string
    //    }

    type encryption = 
        | SHA256
        | SHA384
        | SHA512
        member this.IdSuffix =
            match this with
            | SHA256 -> "256"
            | SHA384 -> "384"
            | SHA512 -> "512"

    type algorithm = 
        | HMAC
        | RSA
        | ECDsa
        | PSS
        member this.IdPrefix =
            match this with
            | HMAC -> "HS"
            | RSA -> "RS"
            | ECDsa -> "ES"
            | PSS -> "PS"

    type cryptographyType = 
        {
            Algorithm: algorithm
            Encryption: encryption
        } member this.Id = this.Algorithm.IdPrefix + this.Encryption.IdSuffix

    // new Header type to allow in the future a dynamic JWT header in jwtFunction.
    type Header = Header of System.Collections.Hashtable

    let convertBytesToBase64Url (content: byte[]) =
        let base64 = System.Convert.ToBase64String content
        base64
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")

    let convertStringToBase64Url (content: string) =
        let contentBytes = System.Text.Encoding.UTF8.GetBytes content
        convertBytesToBase64Url contentBytes

    let convertTableToBase64 (table: Hashtable) =
        let jsonPayload = JsonSerializer.Serialize table
        convertStringToBase64Url jsonPayload

    let createJwtHeader (algorithm : cryptographyType) (headerTable : Hashtable) =
        [ ("alg", algorithm.Id); ("typ", "JWT") ]
        |> List.iter (fun item -> 
                        match item with
                        | (k, _) when headerTable.ContainsKey k -> ()
                        | (k, v) -> headerTable.Add(k, v)
                     )
        convertTableToBase64 headerTable

    let getMissingRegisteredKeys (claimset : IDictionary) =
        let registeredKeys =
                seq {
                    "iss";
                    "sub";
                    "aud";
                    "exp";
                    "nbf";
                    "iat";
                    "jti"
                }
        try
            claimset
            |> Seq.cast<string>
            |> Seq.except registeredKeys
            |> Seq.toList
        with
        | :? InvalidCastException as ice -> raise (ArgumentException(nameof(claimset), "Table must only have string keys"))