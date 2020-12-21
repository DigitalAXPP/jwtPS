class jwtClaimSet {
    [string]$issuer
    [string]$subject
    [string]$audience
    [string]$expiration
    [string]$notBefore
    [string]$issuedAt
    [string]$jwtId

    SetProperties([JsonWebToken]$properties) {
        $this.issuer = $properties.iss
        $this.subject = $properties.sub
        $this.audience = $properties.aud
        $this.expiration = $properties.exp
        $this.notBefore = $properties.nbf
        $this.issuedAt = $properties.iat
        $this.jwtId = $properties.jti
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