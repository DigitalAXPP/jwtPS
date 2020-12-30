class jwtHeader {
    [Algorithm]$Algorithm
    [string]$TokenType = "JWT"

    [string]Create(){
        $headerContent = @{ 
            'alg'= $($this.Algorithm)
            'typ'= $($this.TokenType)
        } | ConvertTo-Json
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerContent))
        return $base64
    }
}