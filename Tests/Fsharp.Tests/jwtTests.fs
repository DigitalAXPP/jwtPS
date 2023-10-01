namespace jwtPS

open jwtFunction
open jwtTypes
open System
open NUnit.Framework

[<TestFixtures>]
type TestClass () =
    [<Test>]
    member this.TestMethodPassing () =
        Assert.True(true)