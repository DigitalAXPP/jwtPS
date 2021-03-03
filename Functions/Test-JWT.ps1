function Test-JWT {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(
            Mandatory,
            ParameterSetName='HMAC',
            HelpMessage='Enter the JWT.'
        )]
        [Parameter(
            Mandatory,
            ParameterSetName='RSA',
            HelpMessage='Enter the JWT.'
        )]
        [ValidatePattern('(^[\w-]*\.[\w-]*\.[\w-]*$)')]
        [string]$JWT,

        [Parameter(
            Mandatory,
            ParameterSetName='RSA',
            HelpMessage='Enter the path of the public key'
        )]
        [System.IO.FileInfo]$PublicKey,

        [Parameter(
            Mandatory,
            ParameterSetName='HMAC',
            HelpMessage='Enter the HMAC secret'
        )]
        [string]$Secret
    )

    begin {
    }

    process {
        try {
            #region Reversing and splitting the JWT
            $header, $payload, $signature = $JWT.Split(".")
            $bytes = ConvertFrom-Base64 -Base64 $signature -Byte
            $headerDecoded = ConvertFrom-Base64 -Base64 $header
            #endregion
            Set-Content -Path $env:TEMP\data.txt -Value "$header.$payload" -NoNewline
            Set-Content -Path $env:TEMP\sig.txt -Value $bytes -AsByteStream

            #region Verify signature
            switch ($headerDecoded.alg) {
                { $_ -in @('RS256', 'ES256') } {
                    $result = openssl dgst -sha256 -verify $PublicKey -signature $env:TEMP\sig.txt $env:TEMP\data.txt
                }
                { $_ -in @('RS384', 'ES384') } {
                    $result = openssl dgst -sha384 -verify $PublicKey -signature $env:TEMP\sig.txt $env:TEMP\data.txt
                }
                { $_ -in @('RS512', 'ES512') } {
                    $result = openssl dgst -sha512 -verify $PublicKey -signature $env:TEMP\sig.txt $env:TEMP\data.txt
                }
                'HS256' {
                    Remove-Item -Path $env:TEMP\sig.txt -Force
                    $result = openssl dgst -sha256 -mac HMAC -macopt key:$Secret -out "$env:TEMP\sig.txt" "$env:TEMP\data.txt"
                }
                'HS384' {
                    Remove-Item -Path $env:TEMP\sig.txt -Force
                    $result = openssl dgst -sha384 -mac HMAC -macopt key:$Secret -out "$env:TEMP\sig.txt" "$env:TEMP\data.txt"
                }
                'HS512' {
                    Remove-Item -Path $env:TEMP\sig.txt -Force
                    $result = openssl dgst -sha512 -mac HMAC -macopt key:$Secret -out "$env:TEMP\sig.txt" "$env:TEMP\data.txt"
                }
                Default {
                    throw [System.ArgumentOutOfRangeException]::new("The JWT uses an unsupported algorithm.")
                }
            }
            #endregion
            if ($PSBoundParameters.ContainsKey('Secret')) {
                Get-Content -Path $env:TEMP\sig.txt | Where-Object { $_ -match '(?<=\= )\w*$' }
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($Matches[0])
                $rsa_Base64 = [System.Convert]::ToBase64String($bytes)
                $result = $preparedSignature -eq $rsa_Base64
            }
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