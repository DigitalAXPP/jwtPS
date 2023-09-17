module Fsharp.Tests

open NUnit.Framework

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
