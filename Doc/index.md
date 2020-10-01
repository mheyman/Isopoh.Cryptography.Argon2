# Isopoh.Cryptography.Argon2

## GitHub Repository

[https://github.com/mheyman/Isopoh.Cryptography.Argon2](https://github.com/mheyman/Isopoh.Cryptography.Argon2)

## Introduction

Fully managed .Net implementation of the
[Argon2](https://en.wikipedia.org/wiki/Argon2)
([reference implementation](https://github.com/P-H-C/phc-winner-argon2))
hashing algorithm designed to be a good choice for hashing passwords for
credential storage or key derivation because of its resistance to many attacks.

### SecureArray

This library includes an implementation of a [SecureArray](api/Isopoh.Cryptography.SecureArray.SecureArray-1.html)
which is designed to hold sensitive information. Depending on policy, data
in a `SecureArray` will not be moved or swapped to disk and will always be
zeroed when disposed.

### Blake2b

This library also contains a [Blake2b](api/Isopoh.Cryptography.Blake2b.Blake2B.html) hash based on the C# reference
implementation [found here](https://github.com/BLAKE2/BLAKE2) but modified to
use `SecureArray` where appropriate.

### Running In A Web Page

This library can be used to run in a web page via [Blazor](https://dotnet.microsoft.com/apps/aspnet/web-apps/blazor).

A quick introduction to that is at [Argon2 Blazor](articles/blazor.html).
