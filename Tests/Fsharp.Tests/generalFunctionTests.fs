module Fsharp.Tests

open NUnit.Framework
open jwtTypes

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
        customHashtable.Add("enc", "A128CBC-HS256")
        let result = "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIn0"
        Assert.AreEqual(result, convertTableToBase64 customHashtable)