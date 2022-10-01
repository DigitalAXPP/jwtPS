---
external help file: jwtPS.dll-Help.xml
Module Name: jwtPS
online version:
schema: 2.0.0
---

# ConvertFrom-Jwt

## SYNOPSIS
This function accepts a string in the format of a Json Web Token (JWT) and returns a hashtable with of the header and claimset converted from Base 64.

## SYNTAX

```
ConvertFrom-Jwt -Jwt <String> [<CommonParameters>]
```

## DESCRIPTION
The string must be a valid JWT. The function will split the string into the three parts of a JWT and convert the first two parts back into the human-readable format. The header and the claimset will be returned as a hashtable.

## EXAMPLES

### Example 1
```powershell
PS C:\> ConvertFrom-Jwt -Jwt "eyJ0eXAi[...]I1NiJ9.eyJpYXQiOjEyMzQ1Njc[...]IsImV4cCI6OTg3NjU0MzIxfQ.K741[...]Yf2aE68CHY"
```

## PARAMETERS

### -Jwt
Expects string in valid JWT format.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

## OUTPUTS

### System.Object
## NOTES

## RELATED LINKS
