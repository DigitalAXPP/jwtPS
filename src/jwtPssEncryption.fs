module jwtPssEncryption
    open System.Security.Cryptography
    open jwtTypes

    let hashPSWithPemFile (msg: string) (algorithm: encryption) (privateKeyPath: string) =
        let pss = RSA.Create()
        let privKey = System.IO.File.ReadAllText privateKeyPath
        pss.ImportFromPem privKey
        let dataInBytes = System.Text.Encoding.UTF8.GetBytes msg
        let bytes = match algorithm with
                    | SHA256 -> pss.SignData(dataInBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)
                    | SHA384 -> pss.SignData(dataInBytes, HashAlgorithmName.SHA384, RSASignaturePadding.Pss)
                    | SHA512 -> pss.SignData(dataInBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pss)
        let base64 = System.Convert.ToBase64String bytes
        base64
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")

    let hashPSWithPemContent (msg: string) (algorithm: encryption) (privateKey: string) =
        let pss = RSA.Create()
        pss.ImportFromPem privateKey
        let dataInBytes = System.Text.Encoding.UTF8.GetBytes msg
        let bytes = match algorithm with
                    | SHA256 -> pss.SignData(dataInBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)
                    | SHA384 -> pss.SignData(dataInBytes, HashAlgorithmName.SHA384, RSASignaturePadding.Pss)
                    | SHA512 -> pss.SignData(dataInBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pss)
        let base64 = System.Convert.ToBase64String bytes
        base64
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")

    let hashPSWithDerFile (msg: string) (algorithm: encryption) (privateKeyPath: string) =
        let pss = RSA.Create()
        let privKey = System.IO.File.ReadAllBytes privateKeyPath
        pss.ImportPkcs8PrivateKey privKey |> ignore
        let dataInBytes = System.Text.Encoding.UTF8.GetBytes msg
        let bytes = match algorithm with
                    | SHA256 -> pss.SignData(dataInBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)
                    | SHA384 -> pss.SignData(dataInBytes, HashAlgorithmName.SHA384, RSASignaturePadding.Pss)
                    | SHA512 -> pss.SignData(dataInBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pss)
        let base64 = System.Convert.ToBase64String bytes
        base64
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")