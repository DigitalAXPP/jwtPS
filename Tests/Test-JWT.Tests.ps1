Describe "Test-JWT" {
    BeforeAll {
        Import-Module -Name jwtPS
    }
    Context "Verify mandatory Parameter" {
        $mandatoryParameter = @(
            @{ 
                parameter = 'JWT'
                parameterset = 'RSA'
            }
            @{ 
                parameter = 'JWT'
                parameterset = 'HMAC'
            }
            @{ 
                parameter = 'PublicKey'
                parameterset = 'RSA'
            }
            @{ 
                parameter = 'Secret'
                parameterset = 'HMAC'
            }
        )
        It "<parameter> is mandatory in parameter set <parameterset>" -TestCases $mandatoryParameter {
            param($parameter, $parameterset)
            $command = Get-Command -Name Test-JWT
            $command.Parameters[$parameter].ParameterSets[$parameterset].IsMandatory | Should -BeTrue
        }
    }
    
    Context "RSA encryption" {
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
        It "with SHA 256" {
            $jwt = New-JWT -PrivateKey $key.PrivateKey -Algorithm RS256 -Payload $claim
            $result = Test-JWT -JWT $jwt -PublicKey $env:HOMEPATH\Documents\PowerShell\public2048.pem
            $result | Should -Match "OK"
        }
        It "with SHA 384" {
            $jwt = New-JWT -PrivateKey $key.PrivateKey -Algorithm RS384 -Payload $claim
            $result = Test-JWT -JWT $jwt -PublicKey $env:HOMEPATH\Documents\PowerShell\public2048.pem
            $result | Should -Match "OK"
        }
        It "with SHA 512" {
            $jwt = New-JWT -PrivateKey $key.PrivateKey -Algorithm RS512 -Payload $claim
            $result = Test-JWT -JWT $jwt -PublicKey $env:HOMEPATH\Documents\PowerShell\public2048.pem
            $result | Should -Match "OK"
        }
    }
}