module jwtRsaEncryption
    open System.Security.Cryptography
    open jwtTypes

    let hashRSWithPemFile (msg: string) (algorithm: encryption) (privateKeyPath: string) =
        let rsa = RSA.Create()
        let privKey = System.IO.File.ReadAllText privateKeyPath
        rsa.ImportFromPem privKey
        let dataInBytes = System.Text.Encoding.UTF8.GetBytes msg
        let bytes = match algorithm with
                    | SHA256 -> rsa.SignData(dataInBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                    | SHA384 -> rsa.SignData(dataInBytes, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1)
                    | SHA512 -> rsa.SignData(dataInBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)
        let base64 = System.Convert.ToBase64String bytes
        base64
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")

    let hashRSWithPemContent (msg: string) (algorithm: encryption) (privateKey: string) =
        let rsa = RSA.Create()
        rsa.ImportFromPem privateKey
        let dataInBytes = System.Text.Encoding.UTF8.GetBytes msg
        let bytes = match algorithm with
                    | SHA256 -> rsa.SignData(dataInBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                    | SHA384 -> rsa.SignData(dataInBytes, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1)
                    | SHA512 -> rsa.SignData(dataInBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)
        let base64 = System.Convert.ToBase64String bytes
        base64
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")

    let hashRSWithDerFile (msg: string) (algorithm: encryption) (privateKeyPath: string) =
        let rsa = RSA.Create()
        let privKey = System.IO.File.ReadAllBytes privateKeyPath
        rsa.ImportPkcs8PrivateKey privKey |> ignore
        let dataInBytes = System.Text.Encoding.UTF8.GetBytes msg
        let bytes = match algorithm with
                    | SHA256 -> rsa.SignData(dataInBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                    | SHA384 -> rsa.SignData(dataInBytes, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1)
                    | SHA512 -> rsa.SignData(dataInBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)
        let base64 = System.Convert.ToBase64String bytes
        base64
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")