function Test-JWT {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(
            Mandatory,
            HelpMessage='Enter the JWT.'
        )]
        [ValidatePattern('(^[\w-]*\.[\w-]*\.[\w-]*$)')]
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
        try {
            #region Reversing and splitting the JWT
            $header, $payload, $signature = $JWT.Split(".")
            $preparedSignature = $signature.Insert(($signature.Length), "==").Replace('-', '+').Replace('_', '/')
            $bytes = [System.Convert]::FromBase64String($preparedSignature)
            $headerDecoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($header)) | ConvertFrom-Json
            #endregion
            Set-Content -Path $env:TEMP\data.txt -Value "$header.$payload" -NoNewline
            Set-Content -Path $env:TEMP\sig.txt -Value $bytes -AsByteStream
    
            #region Verify signature
            switch ($headerDecoded.alg) {
                'RS256' {  
                    $result = openssl dgst -sha256 -verify $PublicKey -signature $env:TEMP\sig.txt $env:TEMP\data.txt
                }
                'RS384' {  
                    $result = openssl dgst -sha384 -verify $PublicKey -signature $env:TEMP\sig.txt $env:TEMP\data.txt
                }
                'RS512' {  
                    $result = openssl dgst -sha512 -verify $PublicKey -signature $env:TEMP\sig.txt $env:TEMP\data.txt
                }
                Default {
                    throw [System.ArgumentOutOfRangeException]::new("The JWT uses an unsupported algorithm.")
                }
            }            
            #endregion            
        }
        catch [System.Management.Automation.MethodException] {
            throw [System.Management.Automation.MethodException]::new($_.Exception.Message)
        }
        finally {
            Remove-Item -Path $env:TEMP\data.txt -Force
            Remove-Item -Path $env:TEMP\sig.txt -Force
        }
    }
    
    end {
        Write-Output -InputObject $result
    }
}