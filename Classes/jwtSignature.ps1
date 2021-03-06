class jwtSignature : jwtBase {
    [string]$PrivateKey
    [string]$Data

    jwtSignature ([string]$key, [string]$data, [Algorithm]$alg) {
        $this.PrivateKey = $key
        $this.Data = $data
        $this.Algorithm = $alg
    }

    [string]Create() {
        $rsa_Base64 = [string]::Empty
        try {
            Set-Content -Path $env:TEMP\key.pem -Value $this.PrivateKey
            Set-Content -Path $env:TEMP\data.txt -Value $this.Data -NoNewline

            switch ($this.Algorithm) { #-replace "[A-Z]") {
                { $_ -in @('RS256', 'ES256') } {
                    openssl dgst -sha256 -sign "$env:TEMP\key.pem" -out "$env:TEMP\sig.txt" "$env:TEMP\data.txt"
                }
                { $_ -in @('RS384', 'ES384') } {
                    openssl dgst -sha384 -sign "$env:TEMP\key.pem" -out "$env:TEMP\sig.txt" "$env:TEMP\data.txt"
                }
                { $_ -in @('RS512', 'ES512') } {
                    openssl dgst -sha512 -sign "$env:TEMP\key.pem" -out "$env:TEMP\sig.txt" "$env:TEMP\data.txt"
                }
                "HS256" {
                    openssl dgst -sha256 -mac HMAC -macopt key:$this.PrivateKey -out "$env:TEMP\sig.txt" "$env:TEMP\data.txt"
                }
                "HS384" {
                    openssl dgst -sha384 -mac HMAC -macopt key:$this.PrivateKey -out "$env:TEMP\sig.txt" "$env:TEMP\data.txt"
                }
                "HS512" {
                    openssl dgst -sha512 -mac HMAC -macopt key:$this.PrivateKey -out "$env:TEMP\sig.txt" "$env:TEMP\data.txt"
                }
                Default {
                    throw [System.ArgumentException]::new("Unavailable Algorithm length.")
                }
            }

            if ($this.Algorithm -match '[ER]S') {
                $rsa_signature = [System.IO.File]::ReadAllBytes("$env:TEMP\sig.txt")
                $rsa_Base64 = [Convert]::ToBase64String($rsa_signature)
            }
            elseif ($this.Algorithm -replace "[1-9]" -eq "HS") {
                Get-Content -Path $env:TEMP\sig.txt | Where-Object { $_ -match '(?<=\= )\w*$' }
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($Matches[0])
                $rsa_Base64 = [System.Convert]::ToBase64String($bytes)
            }
        }
        catch {
            throw [System.IO.IOException]::new($_.Exception.Message)
        }
        finally {
            Remove-Item -Path $env:TEMP\key.pem
            Remove-Item -Path $env:TEMP\data.txt
            Remove-Item -Path $env:TEMP\sig.txt
        }
        return "$($this.Data).$rsa_Base64" -replace '\+','-' -replace '/','_' -replace '='
    }
}