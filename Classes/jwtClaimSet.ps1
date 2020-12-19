class jwtClaimSet {
    [string]$issuer
    [string]$subject
    [string]$audience
    [string]$expiration
    [string]$notBefore
    [string]$issuedAt
    [string]$jwtId

    SetProperties([hashtable]$properties) {
        $this.issuer = $properties["issuer"]
        $this.subject = $properties["subject"]
        $this.audience = $properties["audience"]
        $this.expiration = $properties["expiration"]
        $this.notBefore = $properties["notBefore"]
        $this.issuedAt = $properties["issuedAt"]
        $this.jwtId = $properties["jwtId"]
    }

    [string]Create() {
        $set = @{
            'iss'= $this.issuer
            'sub'= $this.subject
            'aud'= $this.audience
            'exp'= $this.expiration
            'nbf'= $this.notBefore
            'iat'= $this.issuedAt
            'jti'= $this.jwtId
        } | ConvertTo-Json
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($set))
        return $base64 -replace "="
    }
}