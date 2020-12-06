class jwtHeader {
    [string]$Algorithm = "HS256"
    [string]$TokenType = "JWT"

    [void]SetEncryptionAlgorithm([string]$alg) {
        $this.Algorithm = $alg
    }

    [string]CreateHeader(){
        $headerContent = "{ 'alg' = $($this.Algorithm), 'typ' = $($this.TokenType)}" | ConvertTo-Json
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerContent))
        return $base64 -replace "="
    }
}