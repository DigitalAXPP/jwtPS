function ConvertFrom-JWT {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            HelpMessage='Enter the JWT you want to convert to human readable text.'
        )]
        [ValidatePattern('(^[\w-]*\.[\w-]*\.[\w-]*$)')]
        [string]$JWT
    )

    begin {
    }

    process {
        $header, $payload, $signature = $JWT.Split('.') -replace '-','+' -replace '_','/'
        $reversedJWT = [PSCustomObject]@{
            'Header' = (ConvertFrom-Base64 -Base64 $header)
            'Payload' = (ConvertFrom-Base64 -Base64 $payload)
        }
    }

    end {
        Write-Output -InputObject $reversedJWT
    }
}