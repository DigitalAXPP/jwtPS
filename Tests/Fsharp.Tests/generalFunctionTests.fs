module Fsharp.Tests

open NUnit.Framework
open jwtTypes
open jwtFunction
open jwtRsaEncryption
open jwtEcdsaEncryption
open jwtPssEncryption
open System.IO

//[<SetUp>]
//let Setup () =
//    ()

//[<Test>]
//let Test1 () =
//    Assert.Pass()
[<TestFixture>]
type TestClass () =
    
    let getFiles (dir: DirectoryInfo) =
        dir.EnumerateFiles()
        |> Seq.map (fun file -> file.FullName)
        |> List.ofSeq
    let rootDir = DirectoryInfo("..\..")
    let allDir = rootDir.GetDirectories ("*.*", SearchOption.AllDirectories)
    let rec getDirHierarchy (directories: DirectoryInfo list) =
            directories
            |> List.map
                (fun dir -> getFiles dir )

    let files = getDirHierarchy (Array.toList allDir)
    let flatfiles = files |> List.concat
    
    [<Test>]
    member this.TestMethodPassing () =
        Assert.True(true)

    [<Test>]
    member this.TestJwtHeader () =
        let cryptoType = {Algorithm = RSA; Encryption = SHA256}

        let customHashtable = System.Collections.Hashtable ()
        customHashtable.Add("cty", "JWT")
        customHashtable.Add("enc", "A128CBC-HS256")
        let jwtHeader = createJwtHeader cryptoType customHashtable
        let assertHashTable = convertFromBase64 jwtHeader
        match assertHashTable with
        | x when x.Contains "RS256" &&
                 x.Contains "JWT" &&
                 x.Contains "cty" &&
                 x.Contains "enc" &&
                 x.Contains "typ" &&
                 x.Contains "alg" &&
                 x.Contains "A128CBC-HS256" -> Assert.True (true)
        | _ -> Assert.True (false)

    [<Test>]
    member this.TestJwtHeaderWithEmptyTable () =
        let cryptoType = {Algorithm = RSA; Encryption = SHA256}

        let customHashtable = System.Collections.Hashtable ()
        let jwtHeader = createJwtHeader cryptoType customHashtable
        let assertHashTable = convertFromBase64 jwtHeader
        match assertHashTable with
        | x when x.Contains "RS256" &&
                 x.Contains "typ" &&
                 x.Contains "alg" &&
                 x.Contains "JWT" -> Assert.True (true)
        | _ -> Assert.True (false)

    [<Test>]
    member this.TestTableConversion () =
        let customHashtable = System.Collections.Hashtable ()
        customHashtable.Add("cty", "JWT")
        let result = "eyJjdHkiOiJKV1QifQ"
        
        Assert.AreEqual(result, convertTableToBase64 customHashtable)

    [<Test>]
    member this.TestHmacFunction () =
        let message = "{typ: Hello world!}"
        let password = "SbH<En}K>gIC[Xx{Z56I"
        let result256 = "eCPvWfTQ-1agIloOiBGygcQjf6LBKg2Y3BhU_64D3lY"
        let result384 = "OqUWJ9kW2BJO_bIabLdAU2hBWCwc5PPbOJw5ESv4_YQFxG2lnbgivw6j4iro3frS"
        let result512 = "SR9PQXTg4S8jH3Ha0tdtEsD2A2JqvTUTT86nAGX5gxJibFKLgC_gPMoZCZ8d1Uq2_e_yFLDkmlLUZG9GrdQQNQ"
      
        Assert.AreEqual(result256, hashHS message SHA256 password)
        Assert.AreEqual(result384, hashHS message SHA384 password)
        Assert.AreEqual(result512, hashHS message SHA512 password)

    [<Test>]
    member this.TestRSAPemFileFunction () =
        let message = "{typ: Hello world!}"
        //let path = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\privkey.pem"
        //let sourcePath = System.Environment.GetEnvironmentVariable ("GITHUB_WORKSPACE")
        
        //let a = files |> List.contains "C:\Users\apiep\AppData\Local\Temp\wctBBC7.tmp"
        let path = flatfiles |> List.find (fun x -> x.EndsWith "privkey.pem")
        //let path = System.IO.Path.Combine ("home", "runner", "work", "jwtPS", "jwtPS", ".github", "workflows", "privkey.pem")
        let result256 = "soVkOOKzIHIgJH9bdSMghMEOCO8hFd4saHvvvme2iAoeykLsnbdTgvOfdQ1cd135y3XbkVV3Di29wbB33u_QlpcYeYj1Zdwb_AHniISV9X1xT1MIVRpEL_Te7cBwtQNigacsqQekxsulXNr98W4WnuWVTNZ9vABqBaQBAHcgUAo8vWsieL-Ay4t7Z2YU8dG3Lw0lIFaph6caFFZC3UFqcxYGvW7tLRtKdiEqhLahul0MWBYycuNrKPlO8_-WSulyJevNIeN8je3gzemFnsACs8f4hlrv1PYKhwBgtTM4AbUkdtu0ys4mYK57wgjAvWMY_Y0jbWCwt71-BWxKwd-_d56tm5zNPHl4kcHqr-nj_zAudK1I_bs4qQXF2C3q39ip5rLzcQ_gB70K1ByBJf7syPBd6tP1D53i1NFpf2OX3zKCDLPRYIfCvAM6NWDg2kmnNRxg8VeRq3xmvUSP1spXP3dBd2coRIjSwOOpM-Yg4YBAvMNu7oYNGmftOIZsLdVe"
        let result384 = "SsXf-Ih_4JrYNvNmH_tlE7L8G_0MRU2ys93o34DhwFLkv00vxlnrZN-qMty7Tz9NN0MxSHz-2iCir7fuF84MDTAzczTICx84tYgjnrN7q2b_g1kWC1VaW4Jgrn450hBxmNZybOJyNVfpkvL1SlNOrILNJW1ia9Kurd379YO4JOiE_FdYx-_YkjKA97C6ZlMBtI22DsYGKy7QTpMYJgXxfejhdHVaLyUV40D-3luCJZuBUHWlVu0OSGPEqAjyzAh52q0xNIMTBZtM1A9NTn1LKrPjIU8arXRTmRruIrRJCQxErK6nzPQPvWItP1NE7EIBXgNkNTCrEUbki8RcfsNx1dsDSjypA-lhdfmgdBSA_feO4hL0AZ-5cNz7F4XGD00v0-f0nF8MGaHhj7jzbPjDl5SeKjiR76KZeVOhWqn66nYmuDbJdLPT-lfpXYMEN-slxbJxoF46vVrnk4HGvy0GJMXmh7jfTCi9B68o92gKgvpAIDMl6WuPCeq94WOuzQes"
        let result512 = "X47POlIOg_8H7O2HzEozxnfeww-mH7ggkmfAH_fD6kZUw_455aT1qlJkaWXgkqGYBYjJr9zgocvBPoocyztYxJrCuX_k5WwVyg38OPpwVq1RFm017doB9fKKNopyXeBlQYrnJQzKgUfqeD2P2PKknL_slo5Q9red-SyeEdEr0AesmTU-eUQw-hY6IuZmuuwFKKfyQy-dkrUZVtZGB01rFcAHwA9efLUaIY9v5REIKSKbYEOdUewdJ7M8RS7bCJtOYER0nzZM_ED33AEajPiPjIlaC7EStnjHVnOBsN36l3Uzmgv04rcUMsxOx61bqpju9ULIDjWBZfd_BJw2aJQTbokA19oKwe6e51yOQYZulCUb3PvrhMfCCFnSYxZG3ApDitOlg1USmvC1v_lRMBR9Zs1O8kFrNLhbpFzTVqFZ3Zx-GghetIyvA5vMwZjZGuUj0ye__zC10zQx8_MwTtefI17NOp3IMHP-AI4QbcpmnRzILXEI7c0vk9XvqoNHO7QQ"
        
        Assert.AreEqual(result256, hashRSWithPemFile message SHA256 path)
        Assert.AreEqual(result384, hashRSWithPemFile message SHA384 path)
        Assert.AreEqual(result512, hashRSWithPemFile message SHA512 path)

    [<Test>]
    member this.TestRSAPemContentFunction () =
        let message = "{typ: Hello world!}"
        let path = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\privkey.pem"
        let privKey = System.IO.File.ReadAllText path
        let result256 = "soVkOOKzIHIgJH9bdSMghMEOCO8hFd4saHvvvme2iAoeykLsnbdTgvOfdQ1cd135y3XbkVV3Di29wbB33u_QlpcYeYj1Zdwb_AHniISV9X1xT1MIVRpEL_Te7cBwtQNigacsqQekxsulXNr98W4WnuWVTNZ9vABqBaQBAHcgUAo8vWsieL-Ay4t7Z2YU8dG3Lw0lIFaph6caFFZC3UFqcxYGvW7tLRtKdiEqhLahul0MWBYycuNrKPlO8_-WSulyJevNIeN8je3gzemFnsACs8f4hlrv1PYKhwBgtTM4AbUkdtu0ys4mYK57wgjAvWMY_Y0jbWCwt71-BWxKwd-_d56tm5zNPHl4kcHqr-nj_zAudK1I_bs4qQXF2C3q39ip5rLzcQ_gB70K1ByBJf7syPBd6tP1D53i1NFpf2OX3zKCDLPRYIfCvAM6NWDg2kmnNRxg8VeRq3xmvUSP1spXP3dBd2coRIjSwOOpM-Yg4YBAvMNu7oYNGmftOIZsLdVe"
        let result384 = "SsXf-Ih_4JrYNvNmH_tlE7L8G_0MRU2ys93o34DhwFLkv00vxlnrZN-qMty7Tz9NN0MxSHz-2iCir7fuF84MDTAzczTICx84tYgjnrN7q2b_g1kWC1VaW4Jgrn450hBxmNZybOJyNVfpkvL1SlNOrILNJW1ia9Kurd379YO4JOiE_FdYx-_YkjKA97C6ZlMBtI22DsYGKy7QTpMYJgXxfejhdHVaLyUV40D-3luCJZuBUHWlVu0OSGPEqAjyzAh52q0xNIMTBZtM1A9NTn1LKrPjIU8arXRTmRruIrRJCQxErK6nzPQPvWItP1NE7EIBXgNkNTCrEUbki8RcfsNx1dsDSjypA-lhdfmgdBSA_feO4hL0AZ-5cNz7F4XGD00v0-f0nF8MGaHhj7jzbPjDl5SeKjiR76KZeVOhWqn66nYmuDbJdLPT-lfpXYMEN-slxbJxoF46vVrnk4HGvy0GJMXmh7jfTCi9B68o92gKgvpAIDMl6WuPCeq94WOuzQes"
        let result512 = "X47POlIOg_8H7O2HzEozxnfeww-mH7ggkmfAH_fD6kZUw_455aT1qlJkaWXgkqGYBYjJr9zgocvBPoocyztYxJrCuX_k5WwVyg38OPpwVq1RFm017doB9fKKNopyXeBlQYrnJQzKgUfqeD2P2PKknL_slo5Q9red-SyeEdEr0AesmTU-eUQw-hY6IuZmuuwFKKfyQy-dkrUZVtZGB01rFcAHwA9efLUaIY9v5REIKSKbYEOdUewdJ7M8RS7bCJtOYER0nzZM_ED33AEajPiPjIlaC7EStnjHVnOBsN36l3Uzmgv04rcUMsxOx61bqpju9ULIDjWBZfd_BJw2aJQTbokA19oKwe6e51yOQYZulCUb3PvrhMfCCFnSYxZG3ApDitOlg1USmvC1v_lRMBR9Zs1O8kFrNLhbpFzTVqFZ3Zx-GghetIyvA5vMwZjZGuUj0ye__zC10zQx8_MwTtefI17NOp3IMHP-AI4QbcpmnRzILXEI7c0vk9XvqoNHO7QQ"
        
        Assert.AreEqual(result256, hashRSWithPemContent message SHA256 privKey)
        Assert.AreEqual(result384, hashRSWithPemContent message SHA384 privKey)
        Assert.AreEqual(result512, hashRSWithPemContent message SHA512 privKey)

    [<Test>]
    member this.TestRSADerFunction () =
        let message = "{typ: Hello world!}"
        let path = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\rsaprivkey.der"
        let result256 = "KW7CQyKLTnx2pvm36UOHnU7VYEpF47vGbOoTUqPF2QDt2y3Chuq5mwzJRC5yxdu7uL95OtTWA5W_CNCvaeZtIIltiEZzLSbwAxSiBPvtG3kmoUrBZVk2B8WwOHEsRYXXoAR-cWKU5UOnf85sDnt2rr4Vsk9Ve3xqFJlfmMk-Q6v1B2PPv5tVYC2Z7ZLYgGTGT5qDGjABxRWue6lrMI7MBiBmXTT1ZSt9HLA-Nc-3shkKrQs3vD_jgyzA_L7xWO1AtEPGIpZ3u9m_VuTBGo74AA_M72rfZXDzB8u2-O9LanoAhFwTpbahm1Fm9hexFgv6tCQ3cG3uHS4TcA_qfrO0Ag"
        let result384 = "ptLNDHO1WAgeCNq2jdiiIJlQ2_CmLh6Ey2Fm55mx9FUe_HD-qgIImmXaEzm0SpPH7F-YmkT9GoMjdD1W82L7UytUl4Qkn1XkMbGuy_6BQpd-DFsDCqY0wK2_RKheG8R16lv5EBmbQdp9NjqZeEQdnvzdKSdUVZ6UrdyYaqP-YTGFHtVaAATSxHcsnk_IJ2c2WMBMvZH8OoRuUqgfJ416Ze2jvdrWtTq_tf138tUQjZbjegQulw0XqyZQKn4VbIq2AmayWBKLliQGPBus-m2a1DApiglcwIte0Qej_P2S9QDu3TVirdjoavkQta-d_CfG6hbzPbgjDXrcgU60hFTXTg"
        let result512 = "5HTyZuQGmau53ae5-u80gn1ihOiRbc_IcUxCykS6GQVrX8oEho7kpxyt7fBRxXvXHfqsIPr4WFlF9l-zWUapPFIQEeqmx89Emo8RYXueUSUMXhuAstvU0VCMZAc9o9nEjHNZweQOjUn8p-JwTXB6NewJgeE_-2tE7BwWleOIpSxctDcn1XB4NQxo7xRPR9WY3HhUOdtaL6r2UtKdm_W26KjYCLZPn9wtm3hm0G5HauG5dXZF7vR33dU8WzJvTroZzwz8Y9DgpX1ZkSNWDmO1ggcMQqLKITicT8eKMyJ_lS77Htd1S0xMEG13Pt1SJbT9OBV4HuFnM7lqT1O7g1ndnw"
        
        Assert.AreEqual(result256, hashRSWithDerFile message SHA256 path)
        Assert.AreEqual(result384, hashRSWithDerFile message SHA384 path)
        Assert.AreEqual(result512, hashRSWithDerFile message SHA512 path)

    [<Test>]
    member this.TestEcdsaPemContentFunction () =
        let message = "{typ: Hello world!}"
        let path256 = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\private_es256.pem"
        let privKey256 = System.IO.File.ReadAllText path256
        let path384 = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\private_es384.pem"
        let privKey384 = System.IO.File.ReadAllText path384
        let path512 = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\private_es512.pem"
        let privKey512 = System.IO.File.ReadAllText path512
        let result256 = "_4ZlRb7Xkzr52xQqY_gy7uzI-UfIcZEi_twMwiWi0Acu3aKYkyN9klcx2XYdUE3OJwbk0hq9uVb62NoWSffYyg"
        let result384 = "ft1Y9sZbMvDXH--Fql3IsyKE2j5A8YvMKofjMHY-WbVxhv2-O0iLTxYtV6hp_nY2vpXnz4OMCxIXaTonrCZCOocZlKmFmFJwIKIbSfDia2SEscRjpIC2FV4J0qXut-gA"
        let result512 = "AFGMZtO7dsd3s-rOUfmLORyW7rwgZCsS1pQi-rPiZck58cxnjFxjSz8PkOCzTy87WWNy20NNw48pV8S9OXsRsiQ4AB0DDaG5mPDxTyFgpNO4Gult7q815hdMmwzw9s-iWNhV5L9jhhpW7YhTmLAD0lidwWlUH3lBE5Eho9Oydm56quUB"
           
        Assert.AreEqual(result256.Length, (hashESWithPemContent message SHA256 privKey256).Length)
        Assert.AreEqual(result384.Length, (hashESWithPemContent message SHA384 privKey384).Length)
        Assert.AreEqual(result512.Length, (hashESWithPemContent message SHA512 privKey512).Length)

    [<Test>]
    member this.TestEcdsaPemFileFunction () =
        let message = "{typ: Hello world!}"
        let path256 = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\private_es256.pem"
        let path384 = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\private_es384.pem"
        let path512 = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\private_es512.pem"
        let result256 = "_4ZlRb7Xkzr52xQqY_gy7uzI-UfIcZEi_twMwiWi0Acu3aKYkyN9klcx2XYdUE3OJwbk0hq9uVb62NoWSffYyg"
        let result384 = "ft1Y9sZbMvDXH--Fql3IsyKE2j5A8YvMKofjMHY-WbVxhv2-O0iLTxYtV6hp_nY2vpXnz4OMCxIXaTonrCZCOocZlKmFmFJwIKIbSfDia2SEscRjpIC2FV4J0qXut-gA"
        let result512 = "AFGMZtO7dsd3s-rOUfmLORyW7rwgZCsS1pQi-rPiZck58cxnjFxjSz8PkOCzTy87WWNy20NNw48pV8S9OXsRsiQ4AB0DDaG5mPDxTyFgpNO4Gult7q815hdMmwzw9s-iWNhV5L9jhhpW7YhTmLAD0lidwWlUH3lBE5Eho9Oydm56quUB"
        
        Assert.AreEqual(result256.Length, (hashESWithPemFile message SHA256 path256).Length)
        Assert.AreEqual(result384.Length, (hashESWithPemFile message SHA384 path384).Length)
        Assert.AreEqual(result512.Length, (hashESWithPemFile message SHA512 path512).Length)

    [<Test>]
    member this.TestEcdsaDerFileFunction () =
        let message = "{typ: Hello world!}"
        let path256 = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\private_ES256_pkcs8.der"
        let path384 = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\private_ES384_pkcs8.der"
        let path512 = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\private_ES512_pkcs8.der"
        let result256 = "_4ZlRb7Xkzr52xQqY_gy7uzI-UfIcZEi_twMwiWi0Acu3aKYkyN9klcx2XYdUE3OJwbk0hq9uVb62NoWSffYyg"
        let result384 = "ft1Y9sZbMvDXH--Fql3IsyKE2j5A8YvMKofjMHY-WbVxhv2-O0iLTxYtV6hp_nY2vpXnz4OMCxIXaTonrCZCOocZlKmFmFJwIKIbSfDia2SEscRjpIC2FV4J0qXut-gA"
        let result512 = "AFGMZtO7dsd3s-rOUfmLORyW7rwgZCsS1pQi-rPiZck58cxnjFxjSz8PkOCzTy87WWNy20NNw48pV8S9OXsRsiQ4AB0DDaG5mPDxTyFgpNO4Gult7q815hdMmwzw9s-iWNhV5L9jhhpW7YhTmLAD0lidwWlUH3lBE5Eho9Oydm56quUB"
        
        Assert.AreEqual(result256.Length, (hashESWithDerFile message SHA256 path256).Length)
        Assert.AreEqual(result384.Length, (hashESWithDerFile message SHA384 path384).Length)
        Assert.AreEqual(result512.Length, (hashESWithDerFile message SHA512 path512).Length)

    [<Test>]
    member this.TestPssPemFileFunction () =
        let message = "{typ: Hello world!}"
        let path = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\privkey.pem"
        let result256 = "PTbNG7_INEDS2ln-EAN8Mmb2WLxwvAgg8vbiNwdgpvTX5ARGHEJBPeCGXgxhLRDjg6C9-aecYDwfn6EBMq4YiUKu3phoFiBNIzggL4NOt6_ntDh1wayp6H3kSsogsurkDM9DlZgW485dJyMxpQoqXZI3vGcOtQ2ZxCUR910REdxykl_q_Ek6sW6sQGl9VYp5DUoPm0j7J5GSNpdzCBKRBS9Xt25V_dvaUran3HpDe7_k5lyFmmJ4kCWe4WDcB2xxN8PRHnykvDtQCvOrKjAKiSWGtBEUvVovfev2K9mXX2_YWAz-ftuJO70lCWsN-wrgdwgauvSqJ6Evjb2d8B2K6ZNxCq5KKaNl7Wz8nqUkr-8m3m06rv0jrH3UHhp0QDQpq_K8kamSyoa2IPc3BQj8z0hFyBL4chrqHpExTViugXQeNyifdPjTtNCHctATPb8HCELxiOPP6kHodp0z5iCV4fC3xnCs223umX2D5ARrkcN9svNOmZo6PaHWwiWWsSRw"
        let result384 = "kJ27vDflHJQ7LapunDjdX6eVa4SiuXu1l4RqpG6uiBtoTikD9dNLQspg41E0jSVxTysyVHl1x617EIpyQtI1VSCzHArC9eFamPyg_5CSFw9jze55fk4Sa45jjGAMLpyzraX2qDMOOuCKOOFqWIAdxT-YyRWG12z6aoEKBbEODAmz_r5QJBVpINRrdhjzflNwMDpML0TllcMSBrLnqtOiWYx2I4J0a4Bz19gCuJLFpNaKrw_T0Ydu72rBzuJceKaQ0ifQDElVJ8eNMPKJXEfWNMPy6GJler_GfX06iTtBfIzntA454dQ9jB6oDuKGrNMvKnG_ulicojxSrJSQ1eMfGt7dYZDH5Bk4RIF7AyrvpQX-xPqqMDDwwjjUiVi1HGAaUVV_FZ-SE2OfZ4uox4QmyZsiLORpWusodNhyKuGDqifVXvSumMfslrm2mkp2kMKLvlz1fTV-ESdmZiV-24c1-rzkw2PxmAcEk_BqBtCvULJproWD-JFIsfJ24J0uOCom"
        let result512 = "u0orvMdbKYHNVFfNL4UdhEMw2lzcHX_Kh1cfORuMDHI5u90r_GimDhZoNEZOy9vJ7FsWoBcUeyxSGa_aSVXKGuKyUi5PZffRZGUxHtV7H7VGpoQ530aRoc9LrK_2mcVBay8zbX6HeLFO9aG4RQMpgRxEBvlbCSv83WD2shERD5XqZZirlsI2Au0Aih83RZUWB8xnC_xINzkqnYYxclG8MBhzxo2xy8px3FtG_o_Kooitb70fLeyq_P7AwQ3TAgeUe9QuFNA5CRNrWXPdxcdGCp4p06925A8ZbxrvxtavGMaWbihA4EmChv9Z0KeSEIEsikdMP4-aJer77Z7fPwZHQHIaPzkrteNcoVJsoG6-JjLJp7m0ARf5d4YAxVjmCNmnNvADFNZ1L7vsdLX1_UaKFLjQeSoAPgo4bRRi3eb-9RDq98pzFCjgWxnhm6uwLzDJw3XeXtGxDtrOW-R6pYa2S11v1ipBggJhbLtmMIAW0i5k9D11_Qp9c94IWAyHEjW2"
        
        Assert.AreEqual(result256.Length, (hashPSWithPemFile message SHA256 path).Length)
        Assert.AreEqual(result384.Length, (hashPSWithPemFile message SHA384 path).Length)
        Assert.AreEqual(result512.Length, (hashPSWithPemFile message SHA512 path).Length)

    [<Test>]
    member this.TestPssPemContentFunction () =
        let message = "{typ: Hello world!}"
        let path = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\privkey.pem"
        let privKey = System.IO.File.ReadAllText path
        let result256 = "PTbNG7_INEDS2ln-EAN8Mmb2WLxwvAgg8vbiNwdgpvTX5ARGHEJBPeCGXgxhLRDjg6C9-aecYDwfn6EBMq4YiUKu3phoFiBNIzggL4NOt6_ntDh1wayp6H3kSsogsurkDM9DlZgW485dJyMxpQoqXZI3vGcOtQ2ZxCUR910REdxykl_q_Ek6sW6sQGl9VYp5DUoPm0j7J5GSNpdzCBKRBS9Xt25V_dvaUran3HpDe7_k5lyFmmJ4kCWe4WDcB2xxN8PRHnykvDtQCvOrKjAKiSWGtBEUvVovfev2K9mXX2_YWAz-ftuJO70lCWsN-wrgdwgauvSqJ6Evjb2d8B2K6ZNxCq5KKaNl7Wz8nqUkr-8m3m06rv0jrH3UHhp0QDQpq_K8kamSyoa2IPc3BQj8z0hFyBL4chrqHpExTViugXQeNyifdPjTtNCHctATPb8HCELxiOPP6kHodp0z5iCV4fC3xnCs223umX2D5ARrkcN9svNOmZo6PaHWwiWWsSRw"
        let result384 = "kJ27vDflHJQ7LapunDjdX6eVa4SiuXu1l4RqpG6uiBtoTikD9dNLQspg41E0jSVxTysyVHl1x617EIpyQtI1VSCzHArC9eFamPyg_5CSFw9jze55fk4Sa45jjGAMLpyzraX2qDMOOuCKOOFqWIAdxT-YyRWG12z6aoEKBbEODAmz_r5QJBVpINRrdhjzflNwMDpML0TllcMSBrLnqtOiWYx2I4J0a4Bz19gCuJLFpNaKrw_T0Ydu72rBzuJceKaQ0ifQDElVJ8eNMPKJXEfWNMPy6GJler_GfX06iTtBfIzntA454dQ9jB6oDuKGrNMvKnG_ulicojxSrJSQ1eMfGt7dYZDH5Bk4RIF7AyrvpQX-xPqqMDDwwjjUiVi1HGAaUVV_FZ-SE2OfZ4uox4QmyZsiLORpWusodNhyKuGDqifVXvSumMfslrm2mkp2kMKLvlz1fTV-ESdmZiV-24c1-rzkw2PxmAcEk_BqBtCvULJproWD-JFIsfJ24J0uOCom"
        let result512 = "u0orvMdbKYHNVFfNL4UdhEMw2lzcHX_Kh1cfORuMDHI5u90r_GimDhZoNEZOy9vJ7FsWoBcUeyxSGa_aSVXKGuKyUi5PZffRZGUxHtV7H7VGpoQ530aRoc9LrK_2mcVBay8zbX6HeLFO9aG4RQMpgRxEBvlbCSv83WD2shERD5XqZZirlsI2Au0Aih83RZUWB8xnC_xINzkqnYYxclG8MBhzxo2xy8px3FtG_o_Kooitb70fLeyq_P7AwQ3TAgeUe9QuFNA5CRNrWXPdxcdGCp4p06925A8ZbxrvxtavGMaWbihA4EmChv9Z0KeSEIEsikdMP4-aJer77Z7fPwZHQHIaPzkrteNcoVJsoG6-JjLJp7m0ARf5d4YAxVjmCNmnNvADFNZ1L7vsdLX1_UaKFLjQeSoAPgo4bRRi3eb-9RDq98pzFCjgWxnhm6uwLzDJw3XeXtGxDtrOW-R6pYa2S11v1ipBggJhbLtmMIAW0i5k9D11_Qp9c94IWAyHEjW2"
        
        Assert.AreEqual(result256.Length, (hashPSWithPemContent message SHA256 privKey).Length)
        Assert.AreEqual(result384.Length, (hashPSWithPemContent message SHA384 privKey).Length)
        Assert.AreEqual(result512.Length, (hashPSWithPemContent message SHA512 privKey).Length)

    [<Test>]
    member this.TestPssDerFileFunction () =
        let message = "{typ: Hello world!}"
        let path256 = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\rsaprivkey.der"
        let path384 = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\rsaprivkey.der"
        let path512 = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\rsaprivkey.der"
        let result256 = "r6qIeAJ119Jy5C9E1nX0VNz1C80BlW2gxWbjbUUVDS_bT_sQmoo7kaCOForsM6i22vjcSERhdU0OixgUyHNRxzhoG371EpUvLQQq8l3MZ2ejFC2USwplU857d0iuWxdk2ZMfvzbqcM99rGli1x2FtD3bUY0otlM5oPr7g0elDWXghaewzONmmTGm9frliVVAJDoEJH5JieYrGaw1qPYUm4xisuoHytdZqurnXwMbezj-Z-BRd6WY5w1E6LBwRpq8N1Kop9rQt3TdclKSQBOcEAdz4i-eZqi311yiWeuRrUz456AIUfjxClg8yTKtnwQxYbeMjyDkHi8kOdYJ7J9VlA"
        let result384 = "1jcBbritDQhF3uev22adpKcIrCLxxO1w4CJYacBBCW6Gd-u_BH6EFz4i70j5MI9UaK9KklokY3rO_tShqfAilbTBKg7br2AgAk2rLVpqQwhDBZ9L2VGA5D1HAYlBPYDiQjVnHD87HGw0wUSvxO0VWWDuKsMGNTWf41PljbkyG-Gp1rQz5zk5J9Waseg8JW56HpDPdfrijxy8YUwB8bN0TS5CWBsYR8JBYluKD0wvBevnq65FrY-cE2up4sD5C_XxCCCTF3FAXUjHLSeAla5zS8jx8m-5BbX8yUN9j7BtbrjfLhkZgRe2aZ8s-cV7hhxQnvB4yAxK2enr2RrAjpv1rg"
        let result512 = "9RT8kbKFdnVsr98he3oWh7EaXbTcySdsX5Flpqc9DiITiHdeFnvyLCvPUXRUTYnGLQ59t5TzBT3Ey6b4vKtFpCci9ZCOh0LoEws0leRUswnrZxp9c3QNNzQnxbZwWM8b7tsXUftDjoix0u4lKZfQwAk_0iAKgZ_P8BOSHdJCrwM9HV9IaBODrBct3D8JT0VWJrbOCDbtqvQVpSE-r27C0LnfhPCDRU61KXekKkrbpGsB7O0DnDIeVFBQGklKVPSgRzczlciTBdYgiDH5rr0oyueNHdQQ-L_HNCizWrsuy24Iji-1iigyCY-30VSQHHcVFq_eIRqSvymqcsMZdaC2vA"
        
        Assert.AreEqual(result256.Length, (hashPSWithDerFile message SHA256 path256).Length)
        Assert.AreEqual(result384.Length, (hashPSWithDerFile message SHA384 path384).Length)
        Assert.AreEqual(result512.Length, (hashPSWithDerFile message SHA512 path512).Length)