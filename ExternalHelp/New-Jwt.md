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

### Key
```
New-Jwt -Payload <Hashtable> -Algorithm <cryptographyType> [-Header <Hashtable>] -Secret <String>
 [-CheckClaimset] [<CommonParameters>]
```

### FilePath
```
New-Jwt -Payload <Hashtable> -Algorithm <cryptographyType> [-Header <Hashtable>] -FilePath <FileInfo>
 [-CheckClaimset] [<CommonParameters>]
```

## DESCRIPTION
Three parts are required to create a JWT: the algorithm which decides how the body of the JWT will be encrypted, the claimset which carries the message, and the secret (Password for HMAC encryption or private key for RSA, ECDsa or Pss).

## EXAMPLES

### Example 1
```powershell
PS C:\> $algorithm = [jwtTypes+algorithm]::HMAC
PS C:\> $encryption = [jwtTypes+encryption]::SHA256
PS C:\> $cryptoType = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
PS C:\> New-Jwt -Payload @{'iat'=123456789} -Algorithm $cryptoType -Secret P@ssw0rd
```

This function returns a JWT with HMAC encryption.

### Example 2
```powershell
PS C:\> $algorithm = [jwtTypes+algorithm]::RSA
PS C:\> $encryption = [jwtTypes+encryption]::SHA384
PS C:\> $cryptoType = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
PS C:\> $customJwtHeader = @{"enc" = "A128CBC-HS256"}
PS C:\> New-Jwt -Payload @{'iat'=123456789} -Algorithm $cryptoType -FilePath Path\To\File.pem -Header $customJwtHeader
```

This function returns a JWT with RSA encryption and SHA386 and a custom header.

### Example 3
```powershell
PS C:\> $algorithm = [jwtTypes+algorithm]::ECDsa
PS C:\> $encryption = [jwtTypes+encryption]::SHA512
PS C:\> $cryptoType = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
PS C:\> New-Jwt -Payload @{'iat'=123456789} -Algorithm $cryptoType -FilePath Path\To\File.pem -CheckClaimset -Verbose
```

This function returns a VERBOSE message listing: aud, iss, sub, nbf, exp, jti.
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
The secret is a password for HMAC encryption and a private key for RSA, ECDsa or Pss algorithms.

```yaml
Type: String
Parameter Sets: Key
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -FilePath
Provide the path to the key.

```yaml
Type: FileInfo
Parameter Sets: FilePath
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Header
Here you can provide a hashtable with additional parameters for the JWT header.

```yaml
Type: Hashtable
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -CheckClaimset
Verbose message listing which registered claimset keys are missing.
This paramter must be used with -Verbose.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
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
