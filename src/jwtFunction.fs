module jwtFunction
    open System.Text.Json
    open System.Collections
    open System.Security.Cryptography
    open jwtTypes
    open jwtRsaEncryption
    open jwtEcdsaEncryption
    open jwtPssEncryption
    
    let createJwtHeader (algorithm: string) =
        let header = {typ = "JWT"; alg = algorithm}
        let jsonHeader = JsonSerializer.Serialize header
        let bytes = System.Text.Encoding.UTF8.GetBytes jsonHeader
        let base64 = System.Convert.ToBase64String bytes
        base64
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")

    let createJwtClaimset (payload: Hashtable) =
        let jsonPayload = JsonSerializer.Serialize payload
        let bytes = System.Text.Encoding.UTF8.GetBytes jsonPayload
        let base64 = System.Convert.ToBase64String bytes
        base64
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")

    let hashHS (msg: string) (algorithm: encryption) (secret: string) =
        let dataInBytes = System.Text.Encoding.UTF8.GetBytes msg
        let secretInBytes = System.Text.Encoding.UTF8.GetBytes secret
        let hsHash = match algorithm with
                        | SHA256 -> HMACSHA256.HashData (secretInBytes, dataInBytes)
                        | SHA384 -> HMACSHA384.HashData (secretInBytes, dataInBytes)
                        | SHA512 -> HMACSHA512.HashData (secretInBytes, dataInBytes)
        let base64 = System.Convert.ToBase64String hsHash
        base64
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")

    let convertFromBase64 (jwt: string) =
        let str = match jwt.Length % 4 with
                    | 1 -> jwt.Substring (1, jwt.Length - 1)
                    | 2 -> jwt + string "=="
                    | 3 -> jwt + string "="
                    | _ -> jwt
        let strReplaced = str
                            .Replace("-", "+")
                            .Replace("_", "/")
        let bytes = System.Convert.FromBase64String strReplaced
        System.Text.Encoding.UTF8.GetString bytes

    let newJwtWithPemFile (algorithm: cryptographyType) (claimSet: Hashtable) (secretOrKeyPath: string) =
        let jHeader = createJwtHeader (algorithm.Id)
        let jClaimSet = createJwtClaimset claimSet
        let jSignature = match algorithm.Algorithm with
                            | HMAC -> hashHS $"{jHeader}.{jClaimSet}" algorithm.Encryption secretOrKeyPath
                            | RSA -> hashRSWithPemFile $"{jHeader}.{jClaimSet}" algorithm.Encryption secretOrKeyPath
                            | ECDsa -> hashESWithPemFile $"{jHeader}.{jClaimSet}" algorithm.Encryption secretOrKeyPath
                            | PSS -> hashPSWithPemFile $"{jHeader}.{jClaimSet}" algorithm.Encryption secretOrKeyPath
        $"{jHeader}.{jClaimSet}.{jSignature}"

    let newJwtWithPemContent (algorithm: cryptographyType) (claimSet: Hashtable) (secretOrKeyPath: string) =
        let jHeader = createJwtHeader (algorithm.Id)
        let jClaimSet = createJwtClaimset claimSet
        let jSignature = match algorithm.Algorithm with
                            | HMAC -> hashHS $"{jHeader}.{jClaimSet}" algorithm.Encryption secretOrKeyPath
                            | RSA -> hashRSWithPemContent $"{jHeader}.{jClaimSet}" algorithm.Encryption secretOrKeyPath
                            | ECDsa -> hashESWithPemContnent $"{jHeader}.{jClaimSet}" algorithm.Encryption secretOrKeyPath
                            | PSS -> hashPSWithPemContent $"{jHeader}.{jClaimSet}" algorithm.Encryption secretOrKeyPath
        $"{jHeader}.{jClaimSet}.{jSignature}"

    let newJwtWithDerFile (algorithm: cryptographyType) (claimSet: Hashtable) (secretOrKeyPath: string) =
        let jHeader = createJwtHeader (algorithm.Id)
        let jClaimSet = createJwtClaimset claimSet
        let jSignature = match algorithm.Algorithm with
                            | HMAC -> hashHS $"{jHeader}.{jClaimSet}" algorithm.Encryption secretOrKeyPath
                            | RSA -> hashRSWithDerFile $"{jHeader}.{jClaimSet}" algorithm.Encryption secretOrKeyPath
                            | ECDsa -> hashESWithDerFile $"{jHeader}.{jClaimSet}" algorithm.Encryption secretOrKeyPath
                            | PSS -> hashPSWithDerFile $"{jHeader}.{jClaimSet}" algorithm.Encryption secretOrKeyPath
        $"{jHeader}.{jClaimSet}.{jSignature}"

    let verifyJwt (jwt: string) =
       let jwtSplit = jwt.Split "."
       let bodyBytes = System.Text.Encoding.UTF8.GetBytes $"{jwtSplit.[0]}.{jwtSplit.[1]}"
       let signatureBytes = System.Text.Encoding.UTF8.GetBytes jwtSplit.[2]

       let rsa = RSA.Create()
        
    //    let pubKey = System.IO.File.ReadAllText @"C:\Users\alexande.piepenhagen\Documents\FSharp\pubkey.pem"
       let pubKey = System.IO.File.ReadAllBytes @"C:\Users\apiep\Documents\keys\rsapubkey.der"
    //    let pubKeyBytes = System.Text.Encoding.UTF8.GetBytes pubKey
    //    rsa.ImportFromPem pubKey
       rsa.ImportSubjectPublicKeyInfo pubKey |> ignore

       rsa.VerifyData(bodyBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)