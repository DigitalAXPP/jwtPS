---
external help file: jwtPS-help.xml
Module Name: jwtPS
online version:
schema: 2.0.0
---

# ConvertFrom-JWT

## SYNOPSIS
This function accepts a JWT and converts the base64 encryption back to human readable form.

## SYNTAX

```
ConvertFrom-JWT [-JWT] <String> [<CommonParameters>]
```

## DESCRIPTION
The entered JWT will be split into three parts. The header, plus the payload will be returned as PSCustomObject.

## EXAMPLES

### Example 1
```powershell
PS C:\> ConvertFrom-JWT -JWT $jwt
```

## PARAMETERS

### -JWT
Enter the JWT you want to convert to human readable text.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

## OUTPUTS

### System.Management.Automation.PSObject

## NOTES

## RELATED LINKS
