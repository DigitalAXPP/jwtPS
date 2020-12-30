class jwtClaimSet {
    [string]Create([Hashtable]$payload) {
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $payload)))
        return $base64
    }
}