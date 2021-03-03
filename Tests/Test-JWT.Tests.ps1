Describe "Test-JWT" {
    BeforeAll {
        Import-Module -Name D:\a\jwtPS\jwtPS\jwtPS.psd1
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
            $key = "-----BEGIN PRIVATE KEY-----`r`nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC4yIC+wJeDpeBr`r`n/RuXyCNuAZPj/qSCaBIV9qr0yjNV6VJsH2ULdvv9qSWTvcja2wMCzcYNUCtlwFLn`r`nwCIahP7rKiB8jMsrONhub1qX175Z1XjTxNurIRHt5v5nuuOxO8AmcptKrtJGbvb8`r`nQPQ6+BCJdc+M/3kRYDAPiju0iUmWCveK5DwTnorkevyexEVRUsoIkMhBVzD6LZy/`r`nbOucp4oC7sXJ/HHaJ8/3/i6HekiPPe90w7QzJ5Un/zxlwbCd0T5Pm33BwS/Mnj/e`r`nxZbew5ojY8Mjn92VrF7YjP139mY8qU+04h9kI//FbVKz/Po5n89BzQw1gWPUowFq`r`nW3rCaUTxAgMBAAECggEAdchoOC6u5V1gVbU6V19dJgufZx6zYeRQUuuuQOZ6HnLg`r`n9MZ2M/6d1SxyJWA9nTMpEipz6ZyGbQ9QSSSxGFJZ4zAxEPL1thE/8/TKvCrqzHxD`r`nzkiW9NfZg9lPpHL+G8TIUDmRPuN8aSTmDhihFM12TQhpSai2VRsIx38HW6Z+30H8`r`nsqv91Xx7vWVbEakmDn74Qxk/9nbEII9bKTHhRAYcq05W0FbavrX9YcjM2L1JgpN+`r`nsVFgmE3Ge0xTZztYw9OIlLmwlC5MfhzlG4imUVuGGUFAfuzdTA4hbmg6wLTRcdUv`r`nTcMZF7KTCtB68M9KpP+PjioKxB/rJPZh4m7GlmmPgQKBgQDk0TDjgAvYSIKnAEns`r`nly4JzQe8rEVFSfglkg4F+uglpCaoxwi0fdVmvGa5vqQZ7fmxZzp8qlayA3Pv/efx`r`nnuYLUXM0AT8cLaz539eqPTI3G16s8UW3wZDTj9mVX9JjcVH/3StPbLxgoHz+Y513`r`nqdB9Jz2Ue5yHX34E9rxvW4IG2QKBgQDOvCXLHbBTgysotIznkNIjUCdUm5xHo+HO`r`nDCMbeZMqqIW+eTqJ1len/9QC5o7DLb5bj7YKCmBbMBjU1a0CmFSjhHlR0Ugi6hQA`r`nKxc93d7ZzbhTg7bXffkR5J3tHq0Mkik1YA1Zijn/qtr+Dr0N7YVvgjQHboZnxWDB`r`na3EzAejP2QKBgGc009BJWQ5c5lFdF/rW1bUl/W9kZHo0OvD3R8v6t+sCd015OLvw`r`nZejI4ay2CF6JsC4MWZ0RV7lDRW/iHlQlT62bN1MlnMmg8HxkMmpe399rQPDQgpm3`r`nfRNvtrxhVAv2eP3nTDmu2ejbeoVjeQsYVSmeIXBvsNJ+h+DFSYkQxT1BAoGAMfHg`r`ni46zn6lrzty3weYJ7oAZ0GX7vo8IKXhjLusTM9Yc4aR2EQDYknzK4pyC1wKBH6u7`r`nhfd1yfH3vcuVja/xmsORb8PI0q6MgHHonoiwoxwBMSP8E1max8jcooGruwLAs+Vt`r`ntDkhw/OqDoDPCcNdXlAtc7IvBHj55CCp63HFphkCgYEA3eHDbrPLKZToKvcJ7TI4`r`n4azujEBqfq2Vc7vDn5T7fjPcUq8ZthdZADs6uL4EDdmCvjTmP68ndoJRWQiXfFQV`r`nddtmbgQcESw40/0fvd2NRABSZ/xbrKCFRiG6od0y9WSw1Kl0chMLlWhN1osbqbXZ`r`n5h9Ey+dTqd9d5+lIRxlBjoQ=`r`n-----END PRIVATE KEY-----`r`n"
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
            $jwt = New-JWT -PrivateKey $key -Algorithm RS256 -Payload $claim
            $result = Test-JWT -JWT $jwt -PublicKey D:\a\jwtPS\jwtPS\.github\workflows\public2048.pem
            $result | Should -Match "OK"
        }
        It "with SHA 384" {
            $jwt = New-JWT -PrivateKey $key -Algorithm RS384 -Payload $claim
            $result = Test-JWT -JWT $jwt -PublicKey D:\a\jwtPS\jwtPS\.github\workflows\public2048.pem
            $result | Should -Match "OK"
        }
        It "with SHA 512" {
            $jwt = New-JWT -PrivateKey $key -Algorithm RS512 -Payload $claim
            $result = Test-JWT -JWT $jwt -PublicKey D:\a\jwtPS\jwtPS\.github\workflows\public2048.pem
            $result | Should -Match "OK"
        }
    }
    Context "ECDSA encryption" {
        BeforeEach {
            $key_256 = "-----BEGIN EC PRIVATE KEY-----`r`nMHcCAQEEIO9Xgf50T8VO6GkncN1Q2oF0kq3IBrbkI+SSphg98VE2oAoGCCqGSM49`r`nAwEHoUQDQgAEN9S07l/929SmRhf0yTvTykjwJd/QJXARITRQ5B8e00aSKR7uuguy`r`nfeGQEbNDmL21aAhy7RqmQBhx3ZcO71apFA==`r`n-----END EC PRIVATE KEY-----`r`n"
            $key_384 = "-----BEGIN EC PRIVATE KEY-----`r`nMIGkAgEBBDDIBWp8sZe1ff5kmLHS3RFd1pHxOimPnO1vfrydzlm8UlYNBFnj0lrI`r`nCoTPd1tg8HugBwYFK4EEACKhZANiAARtMhih0x3xd4OaZKXw64GApFQv2tPylyao`r`n3gpcxbq62o6o0sk734KOwJTKkOVBElOJlAWRtkplBc9UkS7wQv7zo5cBwDO0v+nt`r`nEzDFGAoqOg1lfMW22hDoyMCGywxdGhs=`r`n-----END EC PRIVATE KEY-----`r`n"
            $key_512 = "-----BEGIN EC PRIVATE KEY-----`r`nMIHcAgEBBEIB383k8S7qBj3/wbufXKbnuXKVLhlZ+Rpzeox3Dc9phmLaKHKggePA`r`nSivMyCaR7MZMWsYJ5UdG/covRbXxuQaenQqgBwYFK4EEACOhgYkDgYYABAFBKL3L`r`nsMgI9Xc443ef8I63bS5hz703VtroGvOBQv4zuY2V8y3amqdgjas7FQlI4ZNQBohs`r`nLHIRTaJy/uqpi3T3JAHLriR1QzEQ5S/WUiKx0iPUcM6ItuMaByaZGb11YMw/ygIy`r`n+mpcE0LEEtuVsSuzuSSc5nnvgreD6h+mhHzKNxVOog==`r`n-----END EC PRIVATE KEY-----`r`n"
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
        It "with SHA 256" {
            $jwt = New-JWT -PrivateKey $key_256 -Algorithm RS256 -Payload $claim
            $result = Test-JWT -JWT $jwt -PublicKey D:\a\jwtPS\jwtPS\.github\workflows\public2048.pem
            $result | Should -Match "OK"
        }
        It "with SHA 384" {
            $jwt = New-JWT -PrivateKey $key_384 -Algorithm ES384 -Payload $claim
            $result = Test-JWT -JWT $jwt -PublicKey D:\a\jwtPS\jwtPS\.github\workflows\public2048.pem
            $result | Should -Match "OK"
        }
        It "with SHA 512" {
            $jwt = New-JWT -PrivateKey $key_512 -Algorithm ES512 -Payload $claim
            $result = Test-JWT -JWT $jwt -PublicKey D:\a\jwtPS\jwtPS\.github\workflows\public2048.pem
            $result | Should -Match "OK"
        }
    }
}
