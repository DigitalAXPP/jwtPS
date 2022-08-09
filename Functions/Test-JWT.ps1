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
        $tmpPath = [IO.Path]::GetTempPath()
        $FullPathToData = $tmpPath + "data.txt"
        $FullPathToSig  = $tmpPath + "sig.txt"
        $PublicKey = [System.IO.Path]::GetFullPath("$PublicKey")

        try {
            #region Reversing and splitting the JWT
            $header, $payload, $signature = $JWT.Split(".")

            $bytes = ConvertFrom-Base64 -Base64 $signature -Byte
            $headerDecoded = ConvertFrom-Base64 -Base64 $header
            #endregion

            Set-Content -Path $FullPathToData -Value "$header.$payload" -NoNewline
            Set-Content -Path $FullPathToSig -Value $bytes -AsByteStream

            #region Verify signature
            switch ($headerDecoded.alg) {
                { $_ -in @('RS256', 'ES256') } {
                    $result = openssl dgst -sha256 -verify $PublicKey -signature $FullPathToSig $FullPathToData
                }
                { $_ -in @('RS384', 'ES384') } {
                    $result = openssl dgst -sha384 -verify $PublicKey -signature $FullPathToSig $FullPathToData
                }
                { $_ -in @('RS512', 'ES512') } {
                    $result = openssl dgst -sha512 -verify $PublicKey -signature $FullPathToSig $FullPathToData
                }
                'HS256' {
                    Remove-Item -Path $FullPathToSig -Force
                    $result = openssl dgst -sha256 -mac HMAC -macopt key:$Secret -out $FullPathToSig $FullPathToData
                }
                'HS384' {
                    Remove-Item -Path $FullPathToSig -Force
                    $result = openssl dgst -sha384 -mac HMAC -macopt key:$Secret -out $FullPathToSig $FullPathToData
                }
                'HS512' {
                    Remove-Item -Path $FullPathToSig -Force
                    $result = openssl dgst -sha512 -mac HMAC -macopt key:$Secret -out $FullPathToSig $FullPathToData
                }
                Default {
                    throw [System.ArgumentOutOfRangeException]::new("The JWT uses an unsupported algorithm.")
                }
            }
            #endregion
            if ($PSBoundParameters.ContainsKey('Secret')) {
                Get-Content -Path $FullPathToSig | Where-Object { $_ -match '(?<=\= )\w*$' }
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($Matches[0])
                $rsa_Base64 = [System.Convert]::ToBase64String($bytes)
                $result = $preparedSignature -eq $rsa_Base64
            }

            # Is Token Expired
            $jwtDatas = ConvertFrom-JWT($JWT)
            $PayloadExpirationDate = Get-Date -AsUTC -UnixTimeSeconds $jwtDatas.Payload.exp
            #$now = (Get-Date).ToUniversalTime()
            $now = Get-Date -AsUTC
            if ($now -gt $PayloadExpirationDate) {
                $result = "Expired"
            }

        }
        catch [System.Management.Automation.MethodException] {
            throw [System.Management.Automation.MethodException]::new($_.Exception.Message)
        }
        finally {
            Remove-Item -Path $FullPathToData -Force
            Remove-Item -Path $FullPathToSig -Force
        }
    }

    end {
        Write-Output -InputObject $result
    }
}
