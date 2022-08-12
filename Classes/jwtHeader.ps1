class jwtHeader : jwtBase {
    [string]$TokenType = "JWT"

    [string]Create(){
        $headerContent = @{
            'typ'= $this.TokenType
            'alg'= $this.Algorithm
        } | ConvertTo-Json -EnumsAsStrings -Compress
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerContent)) -replace '\+','-' -replace '/','_' -replace '='
        return $base64
    }
}
