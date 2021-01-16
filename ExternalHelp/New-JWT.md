---
external help file: jwtPS-help.xml
Module Name: jwtPS
online version:
schema: 2.0.0
---

# New-JWT

## SYNOPSIS
The function returns a JSON Web Token.

## SYNTAX

```
New-JWT [-PrivateKey] <String> [[-Algorithm] <Algorithm>] [-Payload] <Hashtable> [<CommonParameters>]
```

## DESCRIPTION
This function uses the OpenSSL project to smoothly create JWTs.

## EXAMPLES

### Example 1
```powershell
PS C:\> New-JWT -PrivateKey $privatekey -Algorithm ES256 -Payload $payload
```

The OpenSSL module signs the JWT based on the selected algorithm and in combination of the content of your private key. The payload should be a hashtable with the required JWT content.

## PARAMETERS

### -Algorithm
Setting the encryption algorithm.

```yaml
Type: Algorithm
Parameter Sets: (All)
Aliases:
Accepted values: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Payload
Provide the payload for the JWT

```yaml
Type: Hashtable
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PrivateKey
The private key to sign the JWT.

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

### System.String

## NOTES

## RELATED LINKS
