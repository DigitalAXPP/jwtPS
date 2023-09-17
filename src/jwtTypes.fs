module jwtTypes
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

    let createHD (algorithm : cryptographyType) (etc : System.Collections.Hashtable) : Header =
        etc.Add("alg", algorithm.Id)
        etc.Add("type", "JWT")
        Header etc
