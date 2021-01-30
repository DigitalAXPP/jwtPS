function Test-JWT {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory,
            HelpMessage='Enter the JWT.'
        )]
        [string]$JWT
    )
    
    begin {
        
    }
    
    process {
        $header, $payload, $signature = $JWT.Split(".")
        $bytes = [System.Convert]::FromBase64String($signature)
        $string = [System.Text.Encoding]::UTF8.GetBytes($bytes)
    }
    
    end {
        Write-Output -InputObject $string
    }
}