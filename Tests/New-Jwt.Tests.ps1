Describe "New-JWT" {
    BeforeAll {
        Import-Module -Name $env:GITHUB_WORKSPACE\jwtPS.psd1
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
        }
        It "With SHA256" {
            $encryption = [jwtFunction+encryption]::SHA256
            $algorithm = [jwtFunction+algorithm]::RSA
            $alg = [jwtFunction+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Secret $key -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With SHA384" {
            $encryption = [jwtFunction+encryption]::SHA384
            $algorithm = [jwtFunction+algorithm]::RSA
            $alg = [jwtFunction+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Secret $key -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With SHA512" {
            $encryption = [jwtFunction+encryption]::SHA512
            $algorithm = [jwtFunction+algorithm]::RSA
            $alg = [jwtFunction+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Secret $key -Algorithm $alg -Payload $claim
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
        }
        It "With SHA256" {
            $encryption = [jwtFunction+encryption]::SHA256
            $algorithm = [jwtFunction+algorithm]::ECDsa
            $alg = [jwtFunction+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Secret $key_256 -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With SHA384" {
            $encryption = [jwtFunction+encryption]::SHA384
            $algorithm = [jwtFunction+algorithm]::ECDsa
            $alg = [jwtFunction+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Secret $key_384 -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With SHA512" {
            $encryption = [jwtFunction+encryption]::SHA512
            $algorithm = [jwtFunction+algorithm]::ECDsa
            $alg = [jwtFunction+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Secret $key_512 -Algorithm $alg -Payload $claim
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
        }
        It "With SHA256" {
            $encryption = [jwtFunction+encryption]::SHA256
            $algorithm = [jwtFunction+algorithm]::HMAC
            $alg = [jwtFunction+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Algorithm $alg -Payload $claim -Secret 'P@ssw0rd'
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With SHA384" {
            $encryption = [jwtFunction+encryption]::SHA384
            $algorithm = [jwtFunction+algorithm]::HMAC
            $alg = [jwtFunction+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Algorithm $alg -Payload $claim -Secret 'P@ssw0rd'
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With SHA512" {
            $encryption = [jwtFunction+encryption]::SHA512
            $algorithm = [jwtFunction+algorithm]::HMAC
            $alg = [jwtFunction+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Algorithm $alg -Payload $claim -Secret 'P@ssw0rd'
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
    }
}