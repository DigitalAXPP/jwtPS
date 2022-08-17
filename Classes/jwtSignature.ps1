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
        # Get Os temporary files location
        $tmpPath = [IO.Path]::GetTempPath()
        $FullPathToData = $tmpPath + "data.txt"
        $FullPathToSig  = $tmpPath + "sig.txt"
        $FullPathToKey  = $tmpPath + "key.pem"

        try {
            (Get-Content -Path $this.PrivateKey) | Set-Content -Path $FullPathToKey
            Set-Content -Path $FullPathToData -Value $this.Data -NoNewline

            switch ($this.Algorithm) { #-replace "[A-Z]") {
                { $_ -in @('RS256', 'ES256') } {
                    openssl dgst -sha256 -sign $FullPathToKey -out $FullPathToSig $FullPathToData
                }
                { $_ -in @('RS384', 'ES384') } {
                    openssl dgst -sha384 -sign $FullPathToKey -out $FullPathToSig $FullPathToData
                }
                { $_ -in @('RS512', 'ES512') } {
                    openssl dgst -sha512 -sign $FullPathToKey -out $FullPathToSig $FullPathToData
                }
                "HS256" {
                    openssl dgst -sha256 -mac HMAC -macopt key:$this.PrivateKey -out $FullPathToSig $FullPathToData
                }
                "HS384" {
                    openssl dgst -sha384 -mac HMAC -macopt key:$this.PrivateKey -out $FullPathToSig $FullPathToData
                }
                "HS512" {
                    openssl dgst -sha512 -mac HMAC -macopt key:$this.PrivateKey -out $FullPathToSig $FullPathToData
                }
                Default {
                    throw [System.ArgumentException]::new("Unavailable Algorithm length.")
                }
            }

            if ($this.Algorithm -match '[ER]S') {
                $rsa_signature = [System.IO.File]::ReadAllBytes($FullPathToSig)
                $rsa_Base64 = [Convert]::ToBase64String($rsa_signature)
            }
            elseif ($this.Algorithm -replace "[1-9]" -eq "HS") {
                Get-Content -Path $FullPathToSig | Where-Object { $_ -match '(?<=\= )\w*$' }
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($Matches[0])
                $rsa_Base64 = [System.Convert]::ToBase64String($bytes)
            }
        }
        catch {
            throw [System.IO.IOException]::new($_.Exception.Message)
        }
        finally {
            Remove-Item -Path $FullPathToKey
            Remove-Item -Path $FullPathToData
            Remove-Item -Path $FullPathToSig
        }
        return "$($this.Data).$rsa_Base64" -replace '\+','-' -replace '/','_' -replace '='
    }
}
