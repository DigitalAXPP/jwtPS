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
Once installed and imported, you got two more commands at your disposal. With `New-JWT` you create a new JSON Web Token. `ConvertFrom-JWT` is a function which returns the human-readable content of the provided JWT. It returns the content of the header as well as the payload.
