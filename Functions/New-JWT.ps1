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
        [Algorithm]$Algorithm,

        [Parameter(
            HelpMessage='Provide the payload for the JWT'
        )]
        [Hashtable]$Payload
    )
    
    begin {
        
    }
    
    process {
        $header = [jwtHeader]::new()
        $header.Algorithm = $Algorithm
        $claimSet = [jwtClaimSet]::new().SetProperties((ConvertTo-Json -InputObject $Payload))
        $signature = [jwtSignature]::new($PrivateKey, "$($header.Create()).$($claimSet.Create())")
    }
    
    end {
        Write-Output -InputObject $signature.Create()
    }
}