# jwtPS
The primary objective of this module is to generate a JSON Web Token. You can find more information about JWT on the [official website](https://jwt.io).

## Prerequisite
It uses the [OpenSSL](https://www.openssl.org) project to offer a wider range of encryption algorithms. To install OpenSSL for PowerShell you can follow this [link](https://adamtheautomator.com/install-openssl-powershell/).
To test whether OpenSSL is installed and available in your terminal, please enter:
```PowerShell
PS > openssl version
OpenSSL 1.1.1  11 Sep 2018
```
The command should return the current version of OpenSSL.

## Introduction
You can easily install jwtPS from the PSGallery and import the module.
```PowerShell
Install-Module -Name jwtPS
Import-Module -Name jwtPS
```
Once installed and imported, you got two more commands at your disposal. With `New-JWT` you create a new JSON Web Token. `ConvertFrom-JWT` is a function which returns the human-readable content of the provided JWT. It returns the content of the header as well as the payload. Finally, `Test-JWT` confirms whether the signature of the JWT is valid. Currently, the verification only works for RSA algorithms.

## Create a JWT
To create a JWT with an RSA signature, you need first, a private key and secondly, a payload. 
```PowerShell
$key = "-----BEGIN PRIVATE KEY-----\r\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuMiAvsCXg6Xga/0bl8gj\r\n[...]\r\n-----END PRIVATE KEY-----\r\n"
$payload = @{
    aud = "jwtPS"        
    iss = "DigitalAXPP-$(Get-Random -Maximum 10000)"        
    sub = "HS256 Test"        
    nbf = "0"        
    exp = ([System.DateTimeOffset]::Now.AddHours(3)).ToUnixTimeSeconds()
    iat = ([System.DateTimeOffset]::Now).ToUnixTimeSeconds()
    jti = [guid]::NewGuid()
}
$jwt = New-JWT -PrivateKey $key -Algorithm RS256 -Payload $payload
```
**Attention**, do not just copy-paste the private key into a string. PowerShell might interprete it as string array and it will throw an error. It is important to add `\r\n` as line breaks. `New-JWT` also has `-VerifyPayload` which will check the payload input and add every missing entry of the standard seven keys to the output.
