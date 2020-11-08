# Isopoh.Cryptography.Argon2

## GitHub Repository

[https://github.com/mheyman/Isopoh.Cryptography.Argon2](https://github.com/mheyman/Isopoh.Cryptography.Argon2)

## Nuget Repositories

| Library | Nuget Repository | Depends on
|-----|-----|
|[Argon2](https://www.nuget.org/packages/Isopoh.Cryptography.Argon2/)|https://www.nuget.org/packages/Isopoh.Cryptography.Argon2/| [Blake2b](https://www.nuget.org/packages/Isopoh.Cryptography.Blake2b/), [SecureArray](https://www.nuget.org/packages/Isopoh.Cryptography.SecureArray/)
|[Blake2b](https://www.nuget.org/packages/Isopoh.Cryptography.Blake2b/)|https://www.nuget.org/packages/Isopoh.Cryptography.Blake2b/| [SecureArray](https://www.nuget.org/packages/Isopoh.Cryptography.SecureArray/)
|[SecureArray](https://www.nuget.org/packages/Isopoh.Cryptography.SecureArray/)|https://www.nuget.org/packages/Isopoh.Cryptography.SecureArray/

To use Argon2 in your project, you can
```powershell
Install-Package Isopoh.Cryptography.Argon2
```
or
```bash
dotnet add package Isopoh.Cryptography.Argon2
```
or
```bash
paket add Isopoh.Cryptography.Argon2
```
This project uses [SourceLink](https://github.com/dotnet/sourcelink/blob/master/README.md)
so you should be able to step into the source code for debugging even when just
adding the NuGet package as a dependency.

## Argon2 Package Introduction

Fully managed .Net implementation of the
[Argon2](https://en.wikipedia.org/wiki/Argon2)
([reference implementation](https://github.com/P-H-C/phc-winner-argon2))
hashing algorithm designed to be a good choice for hashing passwords for
credential storage or key derivation because of its resistance to many attacks.

### Typical Usage

Hash with:

> **var hash = [Argon2.Hash("my password")](
api/Isopoh.Cryptography.Argon2.Argon2.html#Isopoh_Cryptography_Argon2_Argon2_Hash_System_String_System_Int32_System_Int32_System_Int32_Isopoh_Cryptography_Argon2_Argon2Type_System_Int32_Isopoh_Cryptography_SecureArray_SecureArrayCall_);**


Verify with:

> **if ([Argon2.Verify(hash, "my password")](
api/Isopoh.Cryptography.Argon2.Argon2.html#Isopoh_Cryptography_Argon2_Argon2_Verify_System_String_System_String_Isopoh_Cryptography_SecureArray_SecureArrayCall_))<br/>
> \{<br/>
> &nbsp;&nbsp;&nbsp;&nbsp;// ...<br/>
> }**<br/>

or

> **if ([Argon2.Verify(hash, "my password", Environment.ProcessorCount)](
api/Isopoh.Cryptography.Argon2.Argon2.html#Isopoh_Cryptography_Argon2_Argon2_Verify_System_String_System_String_System_Int32_Isopoh_Cryptography_SecureArray_SecureArrayCall_))<br/>
> \{<br/>
> &nbsp;&nbsp;&nbsp;&nbsp;// ...<br/>
> }**<br/>

Note, using something like `(1 + Environment.ProcessorCount)/2` for the
`threads` parameter can keep the hash calculation from hammering the system if
it is performing a lot of hashes. Also, until it is working, _don't use a
value other than `1` for the `threads` parameter_ when performing Argon2 hashes
in a web page.

### SecureArray

This library includes an implementation of a [SecureArray](api/Isopoh.Cryptography.SecureArray.SecureArray-1.html)
which is designed to hold sensitive information. Depending on policy, data
in a `SecureArray` will not be moved or swapped to disk and will always be
zeroed when disposed. WebAssembly doesn't allow for move or swap prevention
so, when running in a web page, only zero-upon-disposal protection exists.

### Blake2b

This library also contains a [Blake2b](api/Isopoh.Cryptography.Blake2b.Blake2B.html) hash based on the C# reference
implementation [found here](https://github.com/BLAKE2/BLAKE2) but modified to
use `SecureArray` where appropriate.

### Running In A Web Page

This library can be used to run in a web page via [Blazor](https://dotnet.microsoft.com/apps/aspnet/web-apps/blazor)
or [Uno Platform](https://platform.uno/).

A quick introduction to that is at [Argon2 in WebAssembly](articles/index.html).
