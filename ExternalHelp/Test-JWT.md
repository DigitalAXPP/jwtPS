---
external help file: jwtPS-help.xml
Module Name: jwtPS
online version:
schema: 2.0.0
---

# Test-JWT

## SYNOPSIS
This function verifies the JWT RSA signature. It does not verify an HMAC signature.

## SYNTAX

### RSA
```
Test-JWT [-JWT] <String> [-PublicKey] <FileInfo> [<CommonParameters>]
```

### HMAC
```
Test-JWT [-JWT] <String> -Secret <String> [<CommonParameters>]
```

## DESCRIPTION
With the public key, the signature of the JWT will be verified. The process compares the content of the header and the claimset of the JWT with the signature. The signature is in fact the encrypted version of the header and the claimset. in case either of them have been modified, the verification will fail.

## EXAMPLES

### Example 1
```powershell
PS C:\> Test-JWT -JWT $jwt -PublicKey C:\Users\....\pubkey.pem
```

## PARAMETERS

### -JWT
Enter the JWT.

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

### -PublicKey
Enter the path of the public key

```yaml
Type: FileInfo
Parameter Sets: RSA
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Secret
Enter the HMAC secret

```yaml
Type: String
Parameter Sets: HMAC
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

### System.String

## NOTES

## RELATED LINKS
