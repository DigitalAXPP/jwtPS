function Test-JWT {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory,
            HelpMessage='Enter the JWT.'
        )]
        [string]$JWT,
        
        [Parameter(
            Mandatory,
            HelpMessage='Enter the public key'
        )]
        [string]$PublicKey
    )
    
    begin {
        
    }
    
    process {
        $header, $payload, $signature = $JWT.Split(".")
        $bytes = [System.Convert]::FromBase64String($signature.Insert($signature.Length), "==")

        #region Verify signature
        openssl dgst -verify pubkey.pem -signature sigfile datafile
        #endregion
    }
    
    end {
        Write-Output -InputObject $bytes
    }
}