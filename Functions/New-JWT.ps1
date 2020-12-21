function New-JWT {
    [CmdletBinding()]
    param (
        [Parameter(
            HelpMessage='The private key to sign the JWT.'
        )]
        [string]$PrivateKey
    )
    
    begin {
        
    }
    
    process {
        $header = [jwtHeader]::new().Create()
        $claimSet = [jwtClaimSet]::new()
        $hh = @{
        'issuer' = "Alex"
        'audience' = "Piepe"
        }
        $claimSet.SetProperties($hh)
        $signature = [jwtSignature]::new($PrivateKey, "$header.$($claimSet.Create())")
    }
    
    end {
        Write-Output -InputObject $signature.Create()
    }
}