Describe "ConvertFrom-JWT" {
    BeforeAll {
        Import-Module -Name jwtPS
    }
    Context "Verify parameter" {
        $mandatoryParameter = @(
            @{ parameter = 'JWT' }
        )
        It "Parameter '{$parameter}' is mandatory" -TestCases $mandatoryParameter {
            param($parameter)
            $command = Get-Command -Name New-JWT
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
            $jwt = New-JWT -PrivateKey 'P@ssw0rd' -Algorithm HS256 -Payload $claim
            $conversion = ConvertFrom-JWT -JWT $jwt
            $conversion.Header.alg | Should -BeExactly 'HS256'
            $conversion.Header.type | Should -BeExactly 'type'
        }
    }
}