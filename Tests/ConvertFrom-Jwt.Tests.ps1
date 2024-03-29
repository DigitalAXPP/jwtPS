Describe "ConvertFrom-JWT" {
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
            $encryption = [jwtTypes+encryption]::SHA256
            $algorithm = [jwtTypes+algorithm]::HMAC
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
        }
        It "Verification of the header" {
            $jwt = New-JWT -Secret 'S3cuR3$3cR3T' -Algorithm $alg -Payload $claim
            $conversion = ConvertFrom-JWT -JWT $jwt
            $conversion.Header | Should -Match '"alg":"HS256"'
	    $conversion.Header | Should -Match '"typ":"JWT"'
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