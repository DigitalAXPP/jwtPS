module jwtTypes

open Microsoft.FSharp.Collections

    type jwtHeader = 
        {
            typ: string
            alg: string
        }

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

    let createHeader (algorithm : cryptographyType) (headerTable : System.Collections.Hashtable) : Header =
        [ ("alg", algorithm.Id); ("type", "JWT") ]
        |> List.iter (fun item -> 
                        match item with
                        | (k, _) when headerTable.ContainsKey k -> ()
                        | (k, v) -> headerTable.Add(k, v)
                     )
        Header headerTable

    let convertToBase64UrlString (content: byte[]) =
        let base64 = System.Convert.ToBase64String content
        base64
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")
