module jwtEcdsaEncryption
    open System.Security.Cryptography
    open jwtTypes

    let hashESWithPemFile (msg: string) (algorithm: encryption) (privateKeyPath: string) =
        let es = ECDsa.Create()
        let privKey = System.IO.File.ReadAllText privateKeyPath
        es.ImportFromPem privKey
        let dataInBytes = System.Text.Encoding.UTF8.GetBytes msg
        let bytes = match algorithm with
                    | SHA256 -> es.SignData(dataInBytes, HashAlgorithmName.SHA256)
                    | SHA384 -> es.SignData(dataInBytes, HashAlgorithmName.SHA384)
                    | SHA512 -> es.SignData(dataInBytes, HashAlgorithmName.SHA512)
        let base64 = System.Convert.ToBase64String bytes
        base64
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")

    let hashESWithPemContnent (msg: string) (algorithm: encryption) (privateKey: string) =
        let es = ECDsa.Create()
        es.ImportFromPem privateKey
        let dataInBytes = System.Text.Encoding.UTF8.GetBytes msg
        let bytes = match algorithm with
                    | SHA256 -> es.SignData(dataInBytes, HashAlgorithmName.SHA256)
                    | SHA384 -> es.SignData(dataInBytes, HashAlgorithmName.SHA384)
                    | SHA512 -> es.SignData(dataInBytes, HashAlgorithmName.SHA512)
        let base64 = System.Convert.ToBase64String bytes
        base64
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")

    let hashESWithDerFile (msg: string) (algorithm: encryption) (privateKeyPath: string) =
        let es = ECDsa.Create()
        let privKey = System.IO.File.ReadAllBytes privateKeyPath
        es.ImportPkcs8PrivateKey privKey |> ignore
        let dataInBytes = System.Text.Encoding.UTF8.GetBytes msg
        let bytes = match algorithm with
                    | SHA256 -> es.SignData(dataInBytes, HashAlgorithmName.SHA256)
                    | SHA384 -> es.SignData(dataInBytes, HashAlgorithmName.SHA384)
                    | SHA512 -> es.SignData(dataInBytes, HashAlgorithmName.SHA512)
        let base64 = System.Convert.ToBase64String bytes
        base64
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")