class jwtHeader : jwtBase {
    [string]$TokenType = "JWT"

    [string]Create(){
        $headerContent = @{ 
            'alg'= $this.Algorithm
            'typ'= $this.TokenType
        } | ConvertTo-Json -EnumsAsStrings
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerContent)) -replace '\+','-' -replace '/','_' -replace '='
        return $base64
    }
}