---
external help file: jwtPS.dll-Help.xml
Module Name: jwtPS
online version:
schema: 2.0.0
---

# New-Jwt

## SYNOPSIS
The function creates a Json Web Token (JWT).

## SYNTAX

```
New-Jwt -Payload <Hashtable> -Algorithm <cryptographyType> -Secret <String> [<CommonParameters>]
```

## DESCRIPTION
Three parts are required to create a JWT: the algorithm which decides how the body of the JWT will be encrypted, the claimset which carries the message and the secret (Password for HMAC encryption or private key for RSA or ECDsa). The private keys must be in PEM format.

## EXAMPLES

### Example 1
```powershell
PS C:\> $algorithm = [jwtFunction+algorithm]::HMAC
PS C:\> $encryption = [jwtFunction+encryption]::SHA256
PS C:\> $cryptoType = [jwtFunction+cryptographyType]::new($algorithm, $encryption)
PS C:\> New-Jwt -Payload @{'iat'=123456789} -Algorithm $cryptoType -Secret P@ssw0rd
```

This function returns a JWT with HMAC encryption.

### Example 2
```powershell
PS C:\> $algorithm = [jwtFunction+algorithm]::RSA
PS C:\> $encryption = [jwtFunction+encryption]::SHA384
PS C:\> $cryptoType = [jwtFunction+cryptographyType]::new($algorithm, $encryption)
PS C:\> New-Jwt -Payload @{'iat'=123456789} -Algorithm $cryptoType -Secret Path\To\File.pem
```

This function returns a JWT with RSA encryption and SHA386.

### Example 3
```powershell
PS C:\> $algorithm = [jwtFunction+algorithm]::ECDsa
PS C:\> $encryption = [jwtFunction+encryption]::SHA512
PS C:\> $cryptoType = [jwtFunction+cryptographyType]::new($algorithm, $encryption)
PS C:\> New-Jwt -Payload @{'iat'=123456789} -Algorithm $cryptoType -Secret Path\To\File.pem
```

This function returns a JWT with ECDsa encryption and SHA512.

## PARAMETERS

### -Algorithm
Set the encryption algorithm.

```yaml
Type: cryptographyType
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Payload
Provide the claimset.

```yaml
Type: Hashtable
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Secret
The secret is a password for HMAC encryption and a private key for RSA or ECDsa algorithms.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
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
