class jwtClaimSet {
    [System.Collections.ArrayList]VerifyPayload([hashtable]$payload) {
        $missingKeys = [System.Collections.ArrayList]@()
        $keys = @('iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti')
        $keys | ForEach-Object {
            if (-Not ($payload.ContainsKey($_))) {
                $missingKeys.Add($_)
            }
        }
        return $missingKeys
    }

    [string]Create([Hashtable]$payload) {
        $pay = $payload | ConvertTo-Json -Compress
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($pay)) -replace '\+','-' -replace '/','_' -replace '='
        return $base64
    }
}