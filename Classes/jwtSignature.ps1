class jwtSignature {
    [string]$PrivateKey
    [string]$Data

    jwtSignature ([string]$key, [string]$data) {
        $this.PrivateKey = $key
        $this.Data = $data
    }
    
    [string]Create() {
        $rsa_Base64 = [string]::Empty
        try {
            Set-Content -Path $env:TEMP\key.pem -Value $this.PrivateKey
            Set-Content -Path $env:TEMP\data.txt -Value $this.Data -NoNewline

            openssl dgst -sha256 -sign "$env:TEMP\key.pem" -out "$env:TEMP\sig.txt" "$env:TEMP\data.txt"

            $rsa_signature = [System.IO.File]::ReadAllBytes("$env:TEMP\sig.txt")
            $rsa_Base64 = [Convert]::ToBase64String($rsa_signature)
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