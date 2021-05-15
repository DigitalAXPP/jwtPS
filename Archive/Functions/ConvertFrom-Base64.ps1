function ConvertFrom-Base64 {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            HelpMessage='Enter the Base64 string.'
        )][string]$Base64,

        [Parameter(
            HelpMessage='Use switch if the input is in bytes.'
        )]
        [switch]$Byte
    )

    begin {
    }

    process {
        $string = $Base64.Replace('-','+').Replace('_','/')
        switch ($string.Length % 4) {
            1 { $string = $string.Substring(0, $string.Length -1) }
            2 { $string += "==" }
            3 { $string += "=" }
            Default {
                continue
            }
        }
    }

    end {
        if ($PSBoundParameters.ContainsKey('Byte')) {
            return [System.Convert]::FromBase64String($string)
        }
        else {
            return ConvertFrom-Json -InputObject ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($string)))
        }
    }
}