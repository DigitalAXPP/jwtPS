function New-JWT {
    [CmdletBinding()]
    param (
        [Parameter(
            HelpMessage='Path to the private key.'
        )]
        [System.IO.FileInfo]$Path
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
    }
    
    end {
        Write-Output -InputObject "$header.$($claimSet.Create())"
    }
}