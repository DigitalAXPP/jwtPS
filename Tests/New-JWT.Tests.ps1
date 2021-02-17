Describe "New-JWT" {
    BeforeAll {
        Import-Module -Name jwtPS
    }
    Context "Verify parameter" {
        $mandatoryParameter = @(
            @{ parameter = 'PrivateKey' },
            @{ parameter = 'Payload' }
        )
        It "<parameter> is mandatory" -TestCases $mandatoryParameter {
            param($parameter)
            $command = Get-Command -Name New-JWT
            $command.Parameters[$parameter].Attributes.Mandatory | Should -BeTrue
        }
    }
    Context "Verify payload" {
        $claims = @(
            @{
                payload = @{
                    aud = "jwtPS"        
                    iss = "DigitalAXPP"        
                    sub = "RS256 Test"        
                    nbf = "0"        
                    exp = ([System.DateTimeOffset]::Now.AddHours(3)).ToUnixTimeSeconds()
                    iat = ([System.DateTimeOffset]::Now).ToUnixTimeSeconds()
                }
                match = 'jti'
                total = 6
            },
            @{
                payload = @{
                    aud = "jwtPS"        
                    iss = "DigitalAXPP"        
                    sub = "RS256 Test"        
                    nbf = "0"        
                    exp = ([System.DateTimeOffset]::Now.AddHours(3)).ToUnixTimeSeconds()
                }
                match = 'jti', 'iat'
                total = 5
            },
            @{
                payload = @{
                    aud = "jwtPS"        
                    iss = "DigitalAXPP"
                    sub = "RS256 Test"        
                    nbf = "0"
                }
                match = 'jti', 'iat', 'exp'
                total = 4
            }
        )
        It "With <total> properties" -TestCases $claims {
            param($payload, $match)
            $jwt = New-JWT -Algorithm HS256 -PrivateKey "P@ssw0rd" -Payload $payload -VerifyPayload
            $match | ForEach-Object {
                [bool]($jwt -match $_) | Should -BeTrue
            }
        }
    }
    Context "Creating RSA signature" {
        BeforeEach {
            $key = Get-Content -Path $env:HOMEPATH\Documents\PowerShell\rsa2048.json | ConvertFrom-Json
            $claim = @{
                aud = "jwtPS"        
                iss = "DigitalAXPP"        
                sub = "RS256 Test"        
                nbf = "0"        
                exp = ([System.DateTimeOffset]::Now.AddHours(3)).ToUnixTimeSeconds()
                iat = ([System.DateTimeOffset]::Now).ToUnixTimeSeconds()
                jti = [guid]::NewGuid()
            }
        }
        It "With SHA256" {
            $jwt = New-JWT -PrivateKey $key.PrivateKey -Algorithm RS256 -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]*\.[\w-]*\.[\w-]*$)'
        }
        It "With SHA384" {
            $jwt = New-JWT -PrivateKey $key.PrivateKey -Algorithm RS384 -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]*\.[\w-]*\.[\w-]*$)'
        }
        It "With SHA512" {
            $jwt = New-JWT -PrivateKey $key.PrivateKey -Algorithm RS512 -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]*\.[\w-]*\.[\w-]*$)'
        }
    }
    Context "Creating HMAC signature" {
        BeforeEach {
            $claim = @{
                aud = "jwtPS"        
                iss = "DigitalAXPP"        
                sub = "HS256 Test"        
                nbf = "0"        
                exp = ([System.DateTimeOffset]::Now.AddHours(3)).ToUnixTimeSeconds()
                iat = ([System.DateTimeOffset]::Now).ToUnixTimeSeconds()
                jti = [guid]::NewGuid()
            }
        }
        It "With SHA256" {
            $jwt = New-JWT -Algorithm HS256 -Payload $claim -PrivateKey 'P@ssw0rd'
            $jwt | Should -Match -RegularExpression '(^[\w-]*\.[\w-]*\.[\w-]*$)'
        }
        It "With SHA384" {
            $jwt = New-JWT -Algorithm HS384 -Payload $claim -PrivateKey 'P@ssw0rd'
            $jwt | Should -Match -RegularExpression '(^[\w-]*\.[\w-]*\.[\w-]*$)'
        }
        It "With SHA512" {
            $jwt = New-JWT -Algorithm HS512 -Payload $claim -PrivateKey 'P@ssw0rd'
            $jwt | Should -Match -RegularExpression '(^[\w-]*\.[\w-]*\.[\w-]*$)'
        }
    }
}