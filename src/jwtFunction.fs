module jwtFunction
    open System
    open System.Text.Json
    open System.Collections
    open System.Security.Cryptography

    type jwtHeader = {
        typ: string
        alg: string
    }

    type hsAlgorithm = HS256 | HS384 | HS512
    type rsAlgorithm = RS256 | RS384 | RS512
    type esAlgorithm = ES256 | ES384 | ES512

    type Algorithm = 
        | HMAC of hsAlgorithm
        | RSA of rsAlgorithm
        | ECDsa of esAlgorithm

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

    let hashHS (msg: string) (algorithm: hsAlgorithm) (secret: string) =
        let dataInBytes = System.Text.Encoding.UTF8.GetBytes msg
        let secretInBytes = System.Text.Encoding.UTF8.GetBytes secret
        let hsHash = match algorithm with
                        | HS256 -> HMACSHA256.HashData (secretInBytes, dataInBytes)
                        | HS384 -> HMACSHA384.HashData (secretInBytes, dataInBytes)
                        | HS512 -> HMACSHA512.HashData (secretInBytes, dataInBytes)
        let base64 = System.Convert.ToBase64String hsHash
        base64
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")

    let hashRS (msg: string) (algorithm: rsAlgorithm) (privateKeyPath: string) =
        let rsa = RSA.Create()
        // let privKey = System.IO.File.ReadAllText @"C:\Users\Alexande.Piepenhagen\Documents\FSharp\privkey.pem"
        let privKey = System.IO.File.ReadAllText privateKeyPath
        // let derB64 = priv
        //                 .Replace("-----BEGIN PRIVATE KEY-----", "")
        //                 .Replace("-----END PRIVATE KEY-----", "")
        //                 .Replace("\r\n", "")
        // let privKeyBytes = Convert.FromBase64String derB64
        // rsa.ImportPkcs8PrivateKey privKeyBytes |> ignore
        // rsa.ImportFromEncryptedPem (privKey, password)
        rsa.ImportFromPem privKey
        let dataInBytes = System.Text.Encoding.UTF8.GetBytes msg
        let bytes = match algorithm with
                    | RS256 -> rsa.SignData(dataInBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                    | RS384 -> rsa.SignData(dataInBytes, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1)
                    | RS512 -> rsa.SignData(dataInBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)
        let base64 = System.Convert.ToBase64String bytes
        base64
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")

    let hashES (msg: string) (algorithm: esAlgorithm) (privateKeyPath: string) =
        let rsa = ECDsa.Create()
        // let privKey = System.IO.File.ReadAllText @"C:\Users\Alexande.Piepenhagen\Documents\FSharp\private_ec.pem"
        let privKey = System.IO.File.ReadAllText privateKeyPath
        rsa.ImportFromPem privKey
        let dataInBytes = System.Text.Encoding.UTF8.GetBytes msg
        let bytes = match algorithm with
                    | ES256 -> rsa.SignData(dataInBytes, HashAlgorithmName.SHA256)
                    | ES384 -> rsa.SignData(dataInBytes, HashAlgorithmName.SHA384)
                    | ES512 -> rsa.SignData(dataInBytes, HashAlgorithmName.SHA512)
        let base64 = System.Convert.ToBase64String bytes
        base64
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")

    let newJwtHMAC (algorithm: hsAlgorithm) (claimSet: Hashtable) (secret: string) =
        let jHeader = createJwtHeader (algorithm.ToString())
        let jClaimSet = createJwtClaimset claimSet
        let jSignature = hashHS $"{jHeader}.{jClaimSet}" algorithm secret
        $"{jHeader}.{jClaimSet}.{jSignature}"

    let newJwtRS (algorithm: rsAlgorithm) (claimSet: Hashtable) (keyPath: string) =
        let jHeader = createJwtHeader (algorithm.ToString())
        let jClaimSet = createJwtClaimset claimSet
        let jSignature = hashRS $"{jHeader}.{jClaimSet}" algorithm keyPath
        $"{jHeader}.{jClaimSet}.{jSignature}"

    let newJwtES (algorithm: esAlgorithm) (claimSet: Hashtable) (keyPath: string) =
        let jHeader = createJwtHeader (algorithm.ToString())
        let jClaimSet = createJwtClaimset claimSet
        let jSignature = hashES $"{jHeader}.{jClaimSet}" algorithm keyPath
        $"{jHeader}.{jClaimSet}.{jSignature}"

    let extractAlgorithm (algorithm: Algorithm) =
        match algorithm with
        | HMAC x -> x.ToString()
        | RSA x -> x.ToString()
        | ECDsa x -> x.ToString()

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

    let newJwt (algorithm: Algorithm) (claimSet: Hashtable) (secretOrKeyPath: string) =
        let jHeader = createJwtHeader (extractAlgorithm algorithm)
        let jClaimSet = createJwtClaimset claimSet
        let jSignature = match algorithm with
                            | HMAC x -> hashHS $"{jHeader}.{jClaimSet}" x secretOrKeyPath
                            | RSA x -> hashRS $"{jHeader}.{jClaimSet}" x secretOrKeyPath
                            | ECDsa x -> hashES $"{jHeader}.{jClaimSet}" x secretOrKeyPath
        $"{jHeader}.{jClaimSet}.{jSignature}"

    //let verifyJwt (jwt: string) =
    //    let jwtSplit = x.Jwt.Split "."
    //    let bodyBytes = System.Text.Encoding.UTF8.GetBytes $"{jwtSplit.[0]}.{jwtSplit.[1]}"
    //    let signatureBytes = System.Text.Encoding.UTF8.GetBytes jwtSplit.[2]

    //    let rsa = RSA.Create()
        
    //    let pubKey = System.IO.File.ReadAllText @"C:\Users\alexande.piepenhagen\Documents\FSharp\pubkey.pem"
    //    let pubKeyBytes = System.Text.Encoding.UTF8.GetBytes pubKey
    //    rsa.ImportFromPem pubKey

    //    rsa.VerifyData(bodyBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)