function New-JWT {
    [CmdletBinding()]
    param (
        [Parameter(
            HelpMessage='The private key to sign the JWT.'
        )]
        [string]$PrivateKey,
        
        [Parameter(
            HelpMessage='Setting the encryption algorithm.'
        )]
        [Algorithm]$Algorithm
    )
    
    begin {
        
    }
    
    process {
        $header = [jwtHeader]::new()
        $header.Algorithm = $Algorithm
        $claimSet = [jwtClaimSet]::new()
        $hh = [JsonWebToken]::new()
        $hh.iss = "Alex"
        $hh.aud = "Piepe"
        $claimSet.SetProperties($hh)
        $signature = [jwtSignature]::new($PrivateKey, "$($header.Create()).$($claimSet.Create())")
    }
    
    end {
        Write-Output -InputObject $signature.Create()
    }
}