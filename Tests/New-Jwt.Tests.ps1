Describe "New-JWT" {
    Context "Verify parameter" {
        $mandatoryParameter = @(
            @{ parameter = 'Secret' },
            @{ parameter = 'Payload' }
            @{ parameter = 'FilePath' }
        )
        It "<parameter> is mandatory" -TestCases $mandatoryParameter {
            param($parameter)
            $command = Get-Command -Name New-JWT
            $command.Parameters[$parameter].Attributes.Mandatory | Should -BeTrue
        }
    }
    Context "Creating RSA signature" {
        BeforeEach {
            $keyPem = [IO.Path]::Combine("$env:GITHUB_WORKSPACE", '.github', 'workflows', 'privkey.pem')
            $keyDer = [IO.Path]::Combine("$env:GITHUB_WORKSPACE", '.github', 'workflows', 'rsaprivkey.der')
            
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
        It "With PEM and SHA256" {
            $encryption = [jwtTypes+encryption]::SHA256
            $algorithm = [jwtTypes+algorithm]::RSA
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $keyPem -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With DER and SHA256" {
            $encryption = [jwtTypes+encryption]::SHA256
            $algorithm = [jwtTypes+algorithm]::RSA
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $keyDer -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With String and SHA256" {
            $content = (Get-Content -Path $keyPem) -join ""
            $encryption = [jwtTypes+encryption]::SHA256
            $algorithm = [jwtTypes+algorithm]::RSA
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Secret $content -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With PEM and SHA384" {
            $encryption = [jwtTypes+encryption]::SHA384
            $algorithm = [jwtTypes+algorithm]::RSA
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $keyPem -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With DER and SHA384" {
            $encryption = [jwtTypes+encryption]::SHA384
            $algorithm = [jwtTypes+algorithm]::RSA
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $keyDer -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With String and SHA384" {
            $content = (Get-Content -Path $keyPem) -join ""
            $encryption = [jwtTypes+encryption]::SHA384
            $algorithm = [jwtTypes+algorithm]::RSA
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Secret $content -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With PEM and SHA512" {
            $encryption = [jwtTypes+encryption]::SHA512
            $algorithm = [jwtTypes+algorithm]::RSA
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $keyPem -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With DER and SHA512" {
            $encryption = [jwtTypes+encryption]::SHA512
            $algorithm = [jwtTypes+algorithm]::RSA
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $keyDer -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With String and SHA512" {
            $content = (Get-Content -Path $keyPem) -join ""
            $encryption = [jwtTypes+encryption]::SHA512
            $algorithm = [jwtTypes+algorithm]::RSA
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Secret $content -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
    }
    Context "Creating ECDSA signature" {
        BeforeEach {
            $key_256 = [IO.Path]::Combine("$env:GITHUB_WORKSPACE", '.github', 'workflows', 'private_es256.pem')
            $key_256_DER = [IO.Path]::Combine("$env:GITHUB_WORKSPACE", '.github', 'workflows', 'private_ES256_pkcs8.der')
            $key_384 = [IO.Path]::Combine("$env:GITHUB_WORKSPACE", '.github', 'workflows', 'private_es384.pem')
            $key_384_DER = [IO.Path]::Combine("$env:GITHUB_WORKSPACE", '.github', 'workflows', 'private_ES384_pkcs8.der')
            $key_512 = [IO.Path]::Combine("$env:GITHUB_WORKSPACE", '.github', 'workflows', 'private_es512.pem')
            $key_512_DER = [IO.Path]::Combine("$env:GITHUB_WORKSPACE", '.github', 'workflows', 'private_ES512_pkcs8.der')
            
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
        It "With PEM and SHA256" {
            $encryption = [jwtTypes+encryption]::SHA256
            $algorithm = [jwtTypes+algorithm]::ECDsa
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $key_256 -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With String and SHA256" {
            $content = (Get-Content -Path $key_256) -join ""
            $encryption = [jwtTypes+encryption]::SHA256
            $algorithm = [jwtTypes+algorithm]::ECDsa
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Secret $content -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With DER and SHA256" {
            $encryption = [jwtTypes+encryption]::SHA256
            $algorithm = [jwtTypes+algorithm]::ECDsa
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $key_256_DER -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With PEM and SHA384" {
            $encryption = [jwtTypes+encryption]::SHA384
            $algorithm = [jwtTypes+algorithm]::ECDsa
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $key_384 -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With String and SHA384" {
            $content = (Get-Content -Path $key_384) -join ""
            $encryption = [jwtTypes+encryption]::SHA384
            $algorithm = [jwtTypes+algorithm]::ECDsa
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Secret $content -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With PEM and SHA384" {
            $encryption = [jwtTypes+encryption]::SHA384
            $algorithm = [jwtTypes+algorithm]::ECDsa
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $key_384_DER -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With PEM and SHA512" {
            $encryption = [jwtTypes+encryption]::SHA512
            $algorithm = [jwtTypes+algorithm]::ECDsa
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $key_512 -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With String and SHA512" {
            $content = (Get-Content -Path $key_512) -join ""
            $encryption = [jwtTypes+encryption]::SHA512
            $algorithm = [jwtTypes+algorithm]::ECDsa
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Secret $content -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With PEM and SHA512" {
            $encryption = [jwtTypes+encryption]::SHA512
            $algorithm = [jwtTypes+algorithm]::ECDsa
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $key_512_DER -Algorithm $alg -Payload $claim
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
            $encryption = [jwtTypes+encryption]::SHA256
            $algorithm = [jwtTypes+algorithm]::HMAC
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Algorithm $alg -Payload $claim -Secret 'P@ssw0rd'
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With SHA384" {
            $encryption = [jwtTypes+encryption]::SHA384
            $algorithm = [jwtTypes+algorithm]::HMAC
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Algorithm $alg -Payload $claim -Secret 'P@ssw0rd'
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With SHA512" {
            $encryption = [jwtTypes+encryption]::SHA512
            $algorithm = [jwtTypes+algorithm]::HMAC
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Algorithm $alg -Payload $claim -Secret 'P@ssw0rd'
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
    }
    Context "Creating RSA-PSS signature" {
        BeforeEach {
            $key = [IO.Path]::Combine("$env:GITHUB_WORKSPACE", '.github', 'workflows', 'privkey.pem')
            $keyDer = [IO.Path]::Combine("$env:GITHUB_WORKSPACE", '.github', 'workflows', 'rsaprivkey.der')
            
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
        It "With PEM and SHA256" {
            $encryption = [jwtTypes+encryption]::SHA256
            $algorithm = [jwtTypes+algorithm]::PSS
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $key -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With DER and SHA256" {
            $encryption = [jwtTypes+encryption]::SHA256
            $algorithm = [jwtTypes+algorithm]::PSS
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $keyDer -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With String and SHA256" {
            $content = (Get-Content -Path $key) -join ""
            $encryption = [jwtTypes+encryption]::SHA256
            $algorithm = [jwtTypes+algorithm]::PSS
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Secret $content -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With PEM and SHA384" {
            $encryption = [jwtTypes+encryption]::SHA384
            $algorithm = [jwtTypes+algorithm]::PSS
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $key -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With DER and SHA384" {
            $encryption = [jwtTypes+encryption]::SHA384
            $algorithm = [jwtTypes+algorithm]::PSS
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $keyDer -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With String and SHA384" {
            $content = (Get-Content -Path $key) -join ""
            $encryption = [jwtTypes+encryption]::SHA384
            $algorithm = [jwtTypes+algorithm]::PSS
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Secret $content -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With PEM and SHA512" {
            $encryption = [jwtTypes+encryption]::SHA512
            $algorithm = [jwtTypes+algorithm]::PSS
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $key -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With DER and SHA512" {
            $encryption = [jwtTypes+encryption]::SHA512
            $algorithm = [jwtTypes+algorithm]::PSS
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $keyDer -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With String and SHA512" {
            $content = (Get-Content -Path $key) -join ""
            $encryption = [jwtTypes+encryption]::SHA512
            $algorithm = [jwtTypes+algorithm]::PSS
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Secret $content -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
    }
}