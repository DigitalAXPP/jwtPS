module Fsharp.Tests

open NUnit.Framework
open jwtTypes
open jwtFunction
open jwtRsaEncryption

//[<SetUp>]
//let Setup () =
//    ()

//[<Test>]
//let Test1 () =
//    Assert.Pass()
[<TestFixture>]
type TestClass () =
    [<Test>]
    member this.TestMethodPassing () =
        Assert.True(true)

    [<Test>]
    member this.TestJwtHeader () =
        let encryption = SHA256
        let algorithm = RSA
        let cryptoType = {Algorithm = algorithm; Encryption = encryption}

        let customHashtable = System.Collections.Hashtable ()
        customHashtable.Add("cty", "JWT")
        customHashtable.Add("enc", "A128CBC-HS256")
        let jwtHeader = createHeader cryptoType customHashtable
        
        Assert.True (jwtHeader.ContainsKey "cty")
        Assert.True (jwtHeader.ContainsKey "enc")
        Assert.True (jwtHeader.ContainsKey "typ")
        Assert.True (jwtHeader.ContainsKey "alg")

    [<Test>]
    member this.TestTableConversion () =
        let customHashtable = System.Collections.Hashtable ()
        customHashtable.Add("cty", "JWT")
        let result = "eyJjdHkiOiJKV1QifQ"
        
        Assert.AreEqual(result, convertTableToBase64 customHashtable)

    [<Test>]
    member this.TestHmacFunction () =
        let hmacEncryption256 = SHA256
        let hmacEncryption384 = SHA384
        let hmacEncryption512 = SHA512
        let message = "{typ: Hello world!}"
        let password = "SbH<En}K>gIC[Xx{Z56I"
        let result256 = "eCPvWfTQ-1agIloOiBGygcQjf6LBKg2Y3BhU_64D3lY"
        let result384 = "OqUWJ9kW2BJO_bIabLdAU2hBWCwc5PPbOJw5ESv4_YQFxG2lnbgivw6j4iro3frS"
        let result512 = "SR9PQXTg4S8jH3Ha0tdtEsD2A2JqvTUTT86nAGX5gxJibFKLgC_gPMoZCZ8d1Uq2_e_yFLDkmlLUZG9GrdQQNQ"
      
        Assert.AreEqual(result256, hashHS message hmacEncryption256 password)
        Assert.AreEqual(result384, hashHS message hmacEncryption384 password)
        Assert.AreEqual(result512, hashHS message hmacEncryption512 password)

    [<Test>]
    member this.TestRSAPemFileFunction () =
        let encryption256 = SHA256
        let encryption384 = SHA384
        let encryption512 = SHA512
        let message = "{typ: Hello world!}"
        let path = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\privkey.pem"
        let result256 = "soVkOOKzIHIgJH9bdSMghMEOCO8hFd4saHvvvme2iAoeykLsnbdTgvOfdQ1cd135y3XbkVV3Di29wbB33u_QlpcYeYj1Zdwb_AHniISV9X1xT1MIVRpEL_Te7cBwtQNigacsqQekxsulXNr98W4WnuWVTNZ9vABqBaQBAHcgUAo8vWsieL-Ay4t7Z2YU8dG3Lw0lIFaph6caFFZC3UFqcxYGvW7tLRtKdiEqhLahul0MWBYycuNrKPlO8_-WSulyJevNIeN8je3gzemFnsACs8f4hlrv1PYKhwBgtTM4AbUkdtu0ys4mYK57wgjAvWMY_Y0jbWCwt71-BWxKwd-_d56tm5zNPHl4kcHqr-nj_zAudK1I_bs4qQXF2C3q39ip5rLzcQ_gB70K1ByBJf7syPBd6tP1D53i1NFpf2OX3zKCDLPRYIfCvAM6NWDg2kmnNRxg8VeRq3xmvUSP1spXP3dBd2coRIjSwOOpM-Yg4YBAvMNu7oYNGmftOIZsLdVe"
        let result384 = "SsXf-Ih_4JrYNvNmH_tlE7L8G_0MRU2ys93o34DhwFLkv00vxlnrZN-qMty7Tz9NN0MxSHz-2iCir7fuF84MDTAzczTICx84tYgjnrN7q2b_g1kWC1VaW4Jgrn450hBxmNZybOJyNVfpkvL1SlNOrILNJW1ia9Kurd379YO4JOiE_FdYx-_YkjKA97C6ZlMBtI22DsYGKy7QTpMYJgXxfejhdHVaLyUV40D-3luCJZuBUHWlVu0OSGPEqAjyzAh52q0xNIMTBZtM1A9NTn1LKrPjIU8arXRTmRruIrRJCQxErK6nzPQPvWItP1NE7EIBXgNkNTCrEUbki8RcfsNx1dsDSjypA-lhdfmgdBSA_feO4hL0AZ-5cNz7F4XGD00v0-f0nF8MGaHhj7jzbPjDl5SeKjiR76KZeVOhWqn66nYmuDbJdLPT-lfpXYMEN-slxbJxoF46vVrnk4HGvy0GJMXmh7jfTCi9B68o92gKgvpAIDMl6WuPCeq94WOuzQes"
        let result512 = "X47POlIOg_8H7O2HzEozxnfeww-mH7ggkmfAH_fD6kZUw_455aT1qlJkaWXgkqGYBYjJr9zgocvBPoocyztYxJrCuX_k5WwVyg38OPpwVq1RFm017doB9fKKNopyXeBlQYrnJQzKgUfqeD2P2PKknL_slo5Q9red-SyeEdEr0AesmTU-eUQw-hY6IuZmuuwFKKfyQy-dkrUZVtZGB01rFcAHwA9efLUaIY9v5REIKSKbYEOdUewdJ7M8RS7bCJtOYER0nzZM_ED33AEajPiPjIlaC7EStnjHVnOBsN36l3Uzmgv04rcUMsxOx61bqpju9ULIDjWBZfd_BJw2aJQTbokA19oKwe6e51yOQYZulCUb3PvrhMfCCFnSYxZG3ApDitOlg1USmvC1v_lRMBR9Zs1O8kFrNLhbpFzTVqFZ3Zx-GghetIyvA5vMwZjZGuUj0ye__zC10zQx8_MwTtefI17NOp3IMHP-AI4QbcpmnRzILXEI7c0vk9XvqoNHO7QQ"
        let test = hashRSWithPemFile message encryption384 path
        
        Assert.AreEqual(result256, hashRSWithPemFile message encryption256 path)
        Assert.AreEqual(result384, hashRSWithPemFile message encryption384 path)
        Assert.AreEqual(result512, hashRSWithPemFile message encryption512 path)

    [<Test>]
    member this.TestRSAPemContentFunction () =
        let encryption256 = SHA256
        let encryption384 = SHA384
        let encryption512 = SHA512
        let message = "{typ: Hello world!}"
        let path = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\privkey.pem"
        let privKey = System.IO.File.ReadAllText path
        let result256 = "soVkOOKzIHIgJH9bdSMghMEOCO8hFd4saHvvvme2iAoeykLsnbdTgvOfdQ1cd135y3XbkVV3Di29wbB33u_QlpcYeYj1Zdwb_AHniISV9X1xT1MIVRpEL_Te7cBwtQNigacsqQekxsulXNr98W4WnuWVTNZ9vABqBaQBAHcgUAo8vWsieL-Ay4t7Z2YU8dG3Lw0lIFaph6caFFZC3UFqcxYGvW7tLRtKdiEqhLahul0MWBYycuNrKPlO8_-WSulyJevNIeN8je3gzemFnsACs8f4hlrv1PYKhwBgtTM4AbUkdtu0ys4mYK57wgjAvWMY_Y0jbWCwt71-BWxKwd-_d56tm5zNPHl4kcHqr-nj_zAudK1I_bs4qQXF2C3q39ip5rLzcQ_gB70K1ByBJf7syPBd6tP1D53i1NFpf2OX3zKCDLPRYIfCvAM6NWDg2kmnNRxg8VeRq3xmvUSP1spXP3dBd2coRIjSwOOpM-Yg4YBAvMNu7oYNGmftOIZsLdVe"
        let result384 = "SsXf-Ih_4JrYNvNmH_tlE7L8G_0MRU2ys93o34DhwFLkv00vxlnrZN-qMty7Tz9NN0MxSHz-2iCir7fuF84MDTAzczTICx84tYgjnrN7q2b_g1kWC1VaW4Jgrn450hBxmNZybOJyNVfpkvL1SlNOrILNJW1ia9Kurd379YO4JOiE_FdYx-_YkjKA97C6ZlMBtI22DsYGKy7QTpMYJgXxfejhdHVaLyUV40D-3luCJZuBUHWlVu0OSGPEqAjyzAh52q0xNIMTBZtM1A9NTn1LKrPjIU8arXRTmRruIrRJCQxErK6nzPQPvWItP1NE7EIBXgNkNTCrEUbki8RcfsNx1dsDSjypA-lhdfmgdBSA_feO4hL0AZ-5cNz7F4XGD00v0-f0nF8MGaHhj7jzbPjDl5SeKjiR76KZeVOhWqn66nYmuDbJdLPT-lfpXYMEN-slxbJxoF46vVrnk4HGvy0GJMXmh7jfTCi9B68o92gKgvpAIDMl6WuPCeq94WOuzQes"
        let result512 = "X47POlIOg_8H7O2HzEozxnfeww-mH7ggkmfAH_fD6kZUw_455aT1qlJkaWXgkqGYBYjJr9zgocvBPoocyztYxJrCuX_k5WwVyg38OPpwVq1RFm017doB9fKKNopyXeBlQYrnJQzKgUfqeD2P2PKknL_slo5Q9red-SyeEdEr0AesmTU-eUQw-hY6IuZmuuwFKKfyQy-dkrUZVtZGB01rFcAHwA9efLUaIY9v5REIKSKbYEOdUewdJ7M8RS7bCJtOYER0nzZM_ED33AEajPiPjIlaC7EStnjHVnOBsN36l3Uzmgv04rcUMsxOx61bqpju9ULIDjWBZfd_BJw2aJQTbokA19oKwe6e51yOQYZulCUb3PvrhMfCCFnSYxZG3ApDitOlg1USmvC1v_lRMBR9Zs1O8kFrNLhbpFzTVqFZ3Zx-GghetIyvA5vMwZjZGuUj0ye__zC10zQx8_MwTtefI17NOp3IMHP-AI4QbcpmnRzILXEI7c0vk9XvqoNHO7QQ"
        let test = hashRSWithPemContent message encryption384 privKey
        
        Assert.AreEqual(result256, hashRSWithPemContent message encryption256 privKey)
        Assert.AreEqual(result384, hashRSWithPemContent message encryption384 privKey)
        Assert.AreEqual(result512, hashRSWithPemContent message encryption512 privKey)

    [<Test>]
    member this.TestRSADerFunction () =
        let encryption256 = SHA256
        let encryption384 = SHA384
        let encryption512 = SHA512
        let message = "{typ: Hello world!}"
        let path = @"C:\Users\apiep\Documents\github\jwtPS\.github\workflows\rsaprivkey.der"
        let result256 = "KW7CQyKLTnx2pvm36UOHnU7VYEpF47vGbOoTUqPF2QDt2y3Chuq5mwzJRC5yxdu7uL95OtTWA5W_CNCvaeZtIIltiEZzLSbwAxSiBPvtG3kmoUrBZVk2B8WwOHEsRYXXoAR-cWKU5UOnf85sDnt2rr4Vsk9Ve3xqFJlfmMk-Q6v1B2PPv5tVYC2Z7ZLYgGTGT5qDGjABxRWue6lrMI7MBiBmXTT1ZSt9HLA-Nc-3shkKrQs3vD_jgyzA_L7xWO1AtEPGIpZ3u9m_VuTBGo74AA_M72rfZXDzB8u2-O9LanoAhFwTpbahm1Fm9hexFgv6tCQ3cG3uHS4TcA_qfrO0Ag"
        let result384 = "ptLNDHO1WAgeCNq2jdiiIJlQ2_CmLh6Ey2Fm55mx9FUe_HD-qgIImmXaEzm0SpPH7F-YmkT9GoMjdD1W82L7UytUl4Qkn1XkMbGuy_6BQpd-DFsDCqY0wK2_RKheG8R16lv5EBmbQdp9NjqZeEQdnvzdKSdUVZ6UrdyYaqP-YTGFHtVaAATSxHcsnk_IJ2c2WMBMvZH8OoRuUqgfJ416Ze2jvdrWtTq_tf138tUQjZbjegQulw0XqyZQKn4VbIq2AmayWBKLliQGPBus-m2a1DApiglcwIte0Qej_P2S9QDu3TVirdjoavkQta-d_CfG6hbzPbgjDXrcgU60hFTXTg"
        let result512 = "5HTyZuQGmau53ae5-u80gn1ihOiRbc_IcUxCykS6GQVrX8oEho7kpxyt7fBRxXvXHfqsIPr4WFlF9l-zWUapPFIQEeqmx89Emo8RYXueUSUMXhuAstvU0VCMZAc9o9nEjHNZweQOjUn8p-JwTXB6NewJgeE_-2tE7BwWleOIpSxctDcn1XB4NQxo7xRPR9WY3HhUOdtaL6r2UtKdm_W26KjYCLZPn9wtm3hm0G5HauG5dXZF7vR33dU8WzJvTroZzwz8Y9DgpX1ZkSNWDmO1ggcMQqLKITicT8eKMyJ_lS77Htd1S0xMEG13Pt1SJbT9OBV4HuFnM7lqT1O7g1ndnw"
        let test = hashRSWithDerFile message encryption512 path
        
        Assert.AreEqual(result256, hashRSWithDerFile message encryption256 path)
        Assert.AreEqual(result384, hashRSWithDerFile message encryption384 path)
        Assert.AreEqual(result512, hashRSWithDerFile message encryption512 path)