function New-JWT {
    [CmdletBinding(
        SupportsShouldProcess,
        ConfirmImpact='Low'
    )]
    [OutputType([string])]
    param (
        [Parameter(
            Mandatory,
            HelpMessage='The private key to sign the JWT. This also includes the secret for HS algorithms.'
        )]
        [string]$PrivateKey,

        [Parameter(
            HelpMessage='Setting the encryption algorithm.'
        )]
        [Algorithm]$Algorithm = [Algorithm]::new(),

        [Parameter(
            Mandatory,
            HelpMessage='Provide the payload for the JWT'
        )]
        [Hashtable]$Payload,

        [Parameter(
            HelpMessage='Use this switch if you want to check for the standard JWT payload input.'
        )]
        [switch]$VerifyPayload
    )

    begin {
    }

    process {
        if ($PSCmdlet.ShouldProcess("JWT", "Create a new token.")) {
            $header = [jwtHeader]::new()
            $header.Algorithm = $Algorithm
            $claimSet = [jwtClaimSet]::new()
            if ($VerifyPayload) {
                $verification = $claimSet.VerifyPayload($Payload)
                Write-Output -InputObject $verification
            }
            $signature = [jwtSignature]::new($PrivateKey, "$($header.Create()).$($claimSet.Create($Payload))", $Algorithm)
        }
    }

    end {
        Write-Output -InputObject ($signature.Create())
    }
}