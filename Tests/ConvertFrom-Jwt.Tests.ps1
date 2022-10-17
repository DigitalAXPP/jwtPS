Describe "ConvertFrom-JWT" {
    BeforeAll {
        if ($IsLinux -or $IsMacOS) {
            Import-Module -Global "$env:GITHUB_WORKSPACE/src/bin/Debug/net6.0/publish/jwtPS.dll"
        }
        elseif ($IsWindows) {
            Import-Module -Global "$env:GITHUB_WORKSPACE\src\bin\Debug\net6.0\publish\jwtPS.dll"
        }
    }
    Context "Verify parameter" {
        $mandatoryParameter = @(
            @{ parameter = 'JWT' }
        )
        It '<parameter> is mandatory' -TestCases $mandatoryParameter {
            param($parameter)
            $command = Get-Command -Name ConvertFrom-JWT
            $command.Parameters[$parameter].Attributes.Mandatory | Should -BeTrue
        }
    }
    Context "Converting a JSON Web Token" {
        BeforeEach {
            $claim = @{
                aud = "jwtPS"
                iss = "DigitalAXPP-$(Get-Random -Maximum 10000)"
                sub = "HS256 Test"
                nbf = "0"
                exp = ([System.DateTimeOffset]::Now.AddHours(3)).ToUnixTimeSeconds()
                iat = ([System.DateTimeOffset]::Now).ToUnixTimeSeconds()
                jti = [guid]::NewGuid()
            }
            $encryption = [jwtFunction+encryption]::SHA256
            $algorithm = [jwtFunction+algorithm]::HMAC
            $alg = [jwtFunction+cryptographyType]::new($algorithm, $encryption)
        }
        It "Verification of the header" {
            $jwt = New-JWT -Secret 'S3cuR3$3cR3T' -Algorithm $alg -Payload $claim
            $conversion = ConvertFrom-JWT -JWT $jwt
            $conversion.Header | Should -BeExactly '{"typ":"JWT","alg":"HS256"}'
        }
        It "Verification of the payload" {
            $jwt = New-JWT -Secret 'S3cuR3$3cR3T' -Algorithm $alg -Payload $claim
            $conversion = ConvertFrom-JWT -JWT $jwt
            $conversion.Claimset | Should -Match $claim.iss
            $conversion.Claimset | Should -Match $claim.exp
            $conversion.Claimset | Should -Match $claim.iat
            $conversion.Claimset | Should -Match $claim.jti
        }
    }
}