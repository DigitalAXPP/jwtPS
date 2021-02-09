Describe "New-JWT" {
    BeforeAll {
        Import-Module -Name jwtPS
    }
    Context "Verify parameter" {
        $mandatoryParameter = @(
            @{ parameter = 'PrivateKey' },
            @{ parameter = 'Payload' }
        )
        It "{parameter} is mandatory" -TestCases $mandatoryParameter {
            param($parameter)
            $command = Get-Command -Name New-JWT
            $command.Parameters[$parameter].Attributes.Mandatory | Should -BeTrue
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
    }
}