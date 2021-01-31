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
            HelpMessage='Enter the path of the public key'
        )]
        [System.IO.FileInfo]$PublicKey
    )
    
    begin {
        
    }
    
    process {
        $header, $payload, $signature = $JWT.Split(".")
        $preparedSignature = $signature.Insert(($signature.Length), "==").Replace('-', '+').Replace('_', '/')
        $bytes = [System.Convert]::FromBase64String($preparedSignature)

        New-Item -Path $env:TEMP -Name data.txt -Value "$header.$payload" -ItemType File
        # New-Item -Path $env:TEMP -Name sig.txt -Value $bytes -ItemType File
        Set-Content -Path $env:TEMP\sig.txt -Value $bytes -AsByteStream
        # [System.IO.FileInfo]::WriteAllBytes()

        #region Verify signature
        openssl dgst -verify $PublicKey -signature $env:TEMP\sig.txt $env:TEMP\data.txt
        #endregion
    }
    
    end {
        Write-Output -InputObject $bytes
    }
}