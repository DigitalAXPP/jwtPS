module PowerShellFunctionTests

open NUnit.Framework
open jwtTypes

[<TestFixture>]
type TestClass () =
    [<Test>]
    member this.TestMethodPassing () =
        Assert.True(true)

    [<Test>]
    member this.TestMissingRegisteredKeys () =
        //-- Arrange
        let hashtable = System.Collections.Hashtable ()
        hashtable.Add ("sub", "1234567890")
        hashtable.Add ("name", "John Doe")
        hashtable.Add ("iat", "1516239022")
        let hashSet = hashtable.Keys |> Seq.cast<string>

        // -- Act
        let missingregisteredKeys = getMissingRegisteredKeys hashSet

        // -- Assert
        let expectedList = ["iss"; "aud"; "exp"; "nbf"; "jti"]
        Assert.AreEqual (expectedList, missingregisteredKeys)

    [<Test>]
    member this.TestConvertHashtableToSequence () =
        //-- Arrange
        let hashtable = System.Collections.Hashtable ()
        hashtable.Add ("sub", "1234567890")
        hashtable.Add ("name", "John Doe")
        hashtable.Add ("iat", "1516239022")

        // -- Act
        let tableSequence = convertTableToSequence hashtable

        // -- Assert
        Assert.IsTrue (Seq.contains "sub" tableSequence)
        Assert.IsTrue (Seq.contains "name" tableSequence)
        Assert.IsTrue (Seq.contains "iat" tableSequence)