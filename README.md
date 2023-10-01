# jwtPS
The primary objective of this module is to generate a JSON Web Token. You can find more information about JWT on the [official website](https://jwt.io).

## Prerequisite
The new module version doesn't use OpenSSL anymore for the creation or validation of the JWT, instead it uses the internal library *System.Security.Cryptography*. 
[OpenSSL](https://www.openssl.org) can still be used to generate the private/public key pair to create RSA or ECDsa tokens. To install OpenSSL for PowerShell you can follow this [link](https://adamtheautomator.com/install-openssl-powershell/). Alternatively, OpenSSL is included in Git. If you have Git installed, you can open 'Git Bash' and run `openssl` there.
To test whether OpenSSL is installed and available in your PowerShell terminal, please enter:
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
Once installed and imported, you have two commands at your disposal. With `New-JWT` you create a new JSON Web Token and `ConvertFrom-JWT` is a function which returns the human-readable content of the provided JWT. It returns the content of the header as well as the payload.

## Create a JWT
To create a JWT you need three things: 
1. You need to have the path of your private key
2. You need to provide the payload as a hashtable
3. You need to select the algorithm. 
The algorithm in the new version is a bit cumbersome to set up. The algorithm consists out of two discriminating unions. `encryption` sets the encryption level of the algorithm and `algorithm` sets up the algorithm. Finally, both types make up `cryptographyType`. The classes written in F# look like that:
```fsharp
type encryption = SHA256 | SHA384 | SHA512
type algorithm =
    | HMAC of encryption
    | RSA of encryption
    | ECDsa of encryption
    | PSS of encryption
type cryptographyType = 
{
    Algorithm: algorithm
    Encryption: encryption
}
```
To create this class in PowerShell you need to cast them like this:
```PowerShell
$encryption = [jwtTypes+encryption]::SHA256
$algorithm = [jwtTypes+algorithm]::HMAC
$alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
```
Finally, you can see below the code to create a JWT using RSA encryption with SHA384.
```PowerShell
$key = "C:\Users\Path\To\Private\Key.pem"
# The content must be joined otherwise you would have a string array.
$keyContent = (Get-Content -Path $key) -join ""
$payload = @{
    aud = "jwtPS"        
    iss = "DigitalAXPP-$(Get-Random -Maximum 10000)"        
    sub = "RS384 Test"        
    nbf = "0"        
    exp = ([System.DateTimeOffset]::Now.AddHours(3)).ToUnixTimeSeconds()
    iat = ([System.DateTimeOffset]::Now).ToUnixTimeSeconds()
    jti = [guid]::NewGuid()
}
$encryption = [jwtTypes+encryption]::SHA384
$algorithm = [jwtTypes+algorithm]::RSA
$alg = [jwtTypes+cryptographyType]::new($algorithm, $encryption)
$jwt = New-JWT -Payload $payload -Algorithm $alg -FilePath $key
$jwt = New-JWT -Payload $payload -Algorithm $alg -Secret $keyContent
```
**Attention**, `New-Jwt` accepts the secret now either in **PEM** or **PKCS#8** format.

> [!IMPORTANT]  
> You can use now the `Header` property to provide a hashtable with custom keys for your JWT header.
> The hashtable you provide is accepted **as-is**. The function searches for `alg` and `typ`.
> If the keys are included in your hashtable, the values will not be overriden. If they are missing,
> `alg` will be added with the value from your `alg.Id` and `typ` gets added with `JWT`. <br>
> Nevertheless, _the content will be encrypted with the algorithm you set in `-Algorithm`_!