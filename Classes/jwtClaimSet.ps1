class jwtClaimSet {
    [string]Create([Hashtable]$payload) {
        $pay = $payload | ConvertTo-Json -Compress
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($pay)) -replace '\+','-' -replace '/','_' -replace '='
        return $base64
    }
}