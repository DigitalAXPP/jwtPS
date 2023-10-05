module PowerShellFunctionTests

open NUnit.Framework

[<TestFixture>]
type TestClass () =
    [<Test>]
    member this.TestMethodPassing () =
        Assert.True(true)