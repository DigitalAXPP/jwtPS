Describe "New-JWT" {
    BeforeAll {
        Import-Module -Name C:\Users\apiep\Documents\github\jwtPS\jwtPS.psd1
    }
    Context "Verify parameter" {
        $mandatoryParameter = @(
            @{ parameter = 'Secret' },
            @{ parameter = 'Payload' }
        )
        It "<parameter> is mandatory" -TestCases $mandatoryParameter {
            param($parameter)
            $command = Get-Command -Name New-JWT
            $command.Parameters[$parameter].Attributes.Mandatory | Should -BeTrue
        }
    }
    Context "Creating RSA signature" {
        BeforeEach {
            $key = "C:\Users\apiep\Documents\keys\privkey.pem"
            $claim = @{
                aud = "jwtPS"
                iss = "DigitalAXPP"
                sub = "RS256 Test"
                nbf = "0"
                exp = ([System.DateTimeOffset]::Now.AddHours(3)).ToUnixTimeSeconds()
                iat = ([System.DateTimeOffset]::Now).ToUnixTimeSeconds()
                jti = [guid]::NewGuid()
            }
            $alg256 = [jwtFunction+Algorithm+RSA]::NewRSA([jwtFunction+encryption]::SHA256)
            $alg384 = [jwtFunction+Algorithm+RSA]::NewRSA([jwtFunction+encryption]::SHA384)
            $alg512 = [jwtFunction+Algorithm+RSA]::NewRSA([jwtFunction+encryption]::SHA512)
        }
        It "With SHA256" {
            $jwt = New-JWT -Secret $key -Algorithm $alg256 -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With SHA384" {
            $jwt = New-JWT -Secret $key -Algorithm $alg384 -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With SHA512" {
            $jwt = New-JWT -Secret $key -Algorithm $alg512 -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
    }
    Context "Creating ECDSA signature" {
        BeforeEach {
            $key_256 = "C:\Users\apiep\Documents\keys\private_es256.pem"
            $key_384 = "C:\Users\apiep\Documents\keys\private_es384.pem"
            $key_512 = "C:\Users\apiep\Documents\keys\private_es512.pem"
            $claim = @{
                aud = "jwtPS"
                iss = "DigitalAXPP"
                sub = "ES Test"
                nbf = "0"
                exp = ([System.DateTimeOffset]::Now.AddHours(3)).ToUnixTimeSeconds()
                iat = ([System.DateTimeOffset]::Now).ToUnixTimeSeconds()
                jti = [guid]::NewGuid()
            }
            $alg256 = [jwtFunction+Algorithm+ECDsa]::NewECDsa([jwtFunction+encryption]::SHA256)
            $alg384 = [jwtFunction+Algorithm+ECDsa]::NewECDsa([jwtFunction+encryption]::SHA384)
            $alg512 = [jwtFunction+Algorithm+ECDsa]::NewECDsa([jwtFunction+encryption]::SHA512)
        }
        It "With SHA256" {
            $jwt = New-JWT -Secret $key_256 -Algorithm $alg256 -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With SHA384" {
            $jwt = New-JWT -Secret $key_384 -Algorithm $alg384 -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With SHA512" {
            $jwt = New-JWT -Secret $key_512 -Algorithm $alg512 -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
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
            $alg256 = [jwtFunction+Algorithm+HMAC]::NewHMAC([jwtFunction+encryption]::SHA256)
            $alg384 = [jwtFunction+Algorithm+HMAC]::NewHMAC([jwtFunction+encryption]::SHA384)
            $alg512 = [jwtFunction+Algorithm+HMAC]::NewHMAC([jwtFunction+encryption]::SHA512)
        }
        It "With SHA256" {
            $jwt = New-JWT -Algorithm $alg256 -Payload $claim -Secret 'P@ssw0rd'
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With SHA384" {
            $jwt = New-JWT -Algorithm $alg384 -Payload $claim -Secret 'P@ssw0rd'
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With SHA512" {
            $jwt = New-JWT -Algorithm $alg512 -Payload $claim -Secret 'P@ssw0rd'
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
    }
}