Describe "ConvertFrom-JWT" {
    BeforeAll {
        Import-Module D:\a\jwtPS\jwtPS\jwtPS.psd1
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
        }
        It "Verification of the header" {
            $jwt = New-JWT -PrivateKey 'S3cuR3$3cR3T' -Algorithm HS256 -Payload $claim
            $conversion = ConvertFrom-JWT -JWT $jwt
            $conversion.Header.alg | Should -BeExactly 'HS256'
            $conversion.Header.typ | Should -BeExactly 'JWT'
        }
        It "Verification of the payload" {
            $jwt = New-JWT -PrivateKey 'S3cuR3$3cR3T' -Algorithm HS256 -Payload $claim
            $conversion = ConvertFrom-JWT -JWT $jwt
            $conversion.Payload.iss | Should -BeExactly $claim.iss
            $conversion.Payload.exp | Should -BeExactly $claim.exp
            $conversion.Payload.iat | Should -BeExactly $claim.iat
            $conversion.Payload.jti | Should -BeExactly $claim.jti
        }
    }
}
