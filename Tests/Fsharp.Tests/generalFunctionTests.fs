module Fsharp.Tests

open NUnit.Framework
open jwtTypes
open jwtFunction

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
        let test = hashHS message hmacEncryption512 password
        Assert.AreEqual(result256, hashHS message hmacEncryption256 password)
        Assert.AreEqual(result384, hashHS message hmacEncryption384 password)
        Assert.AreEqual(result512, hashHS message hmacEncryption512 password)