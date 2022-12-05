Describe "New-JWT" {
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
            if ($IsLinux -or $IsMacOS) {
                $keyPem = "$env:GITHUB_WORKSPACE/.github/workflows/privkey.pem"
                $keyDer = "$env:GITHUB_WORKSPACE/.github/workflows/rsaprivkey.der"
            }
            elseif ($IsWindows) {
                $keyPem = "$env:GITHUB_WORKSPACE\.github\workflows\privkey.pem"
                $keyDer = "$env:GITHUB_WORKSPACE\.github\workflows\rsaprivkey.der"
            }
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
            if ($IsLinux -or $IsMacOS) {
                $key_256 = "$env:GITHUB_WORKSPACE/.github/workflows/private_es256.pem"
                $key_384 = "$env:GITHUB_WORKSPACE/.github/workflows/private_es384.pem"
                $key_512 = "$env:GITHUB_WORKSPACE/.github/workflows/private_es512.pem"
            }
            elseif ($IsWindows) {
                $key_256 = "$env:GITHUB_WORKSPACE\.github\workflows\private_es256.pem"
                $key_384 = "$env:GITHUB_WORKSPACE\.github\workflows\private_es384.pem"
                $key_512 = "$env:GITHUB_WORKSPACE\.github\workflows\private_es512.pem"
            }
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
            if ($IsLinux -or $IsMacOS) {
                $key = "$env:GITHUB_WORKSPACE/.github/workflows/privkey.pem"
            }
            elseif ($IsWindows) {
                $key = "$env:GITHUB_WORKSPACE\.github\workflows\privkey.pem"
            }
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
        It "With String and SHA256" {
            $content = (Get-Content -Path $key) -join ""
            $encryption = [jwtTypes+encryption]::SHA512
            $algorithm = [jwtTypes+algorithm]::PSS
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -Secret $content -Algorithm $alg -Payload $claim
            $jwt | Should -Match -RegularExpression '(^[\w-]+\.[\w-]+\.[\w-]+$)'
        }
        It "With SHA384" {
            $encryption = [jwtTypes+encryption]::SHA384
            $algorithm = [jwtTypes+algorithm]::PSS
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $key -Algorithm $alg -Payload $claim
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
        It "With SHA512" {
            $encryption = [jwtTypes+encryption]::SHA512
            $algorithm = [jwtTypes+algorithm]::PSS
            $alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
            $jwt = New-JWT -FilePath $key -Algorithm $alg -Payload $claim
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