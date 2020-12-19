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
        $header = [jwtHeader]::new()
    }
    
    end {
        Write-Output -InputObject $header
    }
}