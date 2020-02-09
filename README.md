# Fully Managed .Net Core Argon2 implementation

Argon2 is a hash generator optimized to produce hashes suitable for
credential storage, key derivation, or other situations requiring a
cryptographically secure password hash. Argon2 was the winner of the
2015 [Password Hashing Competition](https://password-hashing.net/).

This fully managed implementation of Argon2 runs in .NET Core or .NET
Framework applications.

## Getting Started

### NuGet

The recommended way to get started is by use the NuGet package:

```shell
Install-Package Isopoh.Cryptography.Argon2
```

from [https://www.nuget.org/packages/Isopoh.Cryptography.Argon2](https://www.nuget.org/packages/Isopoh.Cryptography.Argon2).

This project uses [SourceLink](https://github.com/dotnet/sourcelink/blob/master/README.md)
so you should be able to step into the source code for debugging even when
just adding the NuGet package as a dependency.

### Clone

You can also, of course, go old-school and clone the repository and link use
the .csproj files directly:

```shell
git clone https://github.com/mheyman/Isopoh.Cryptography.Argon2.git
```

then add the `ProjectReference` lines to your .csproj to reference
...`Isopoh.Cryptography.SecureArray\Isopoh.Cryptography.SecureArray.csproj`,
...`Isopoh.Cryptography.Blake2b\Isopoh.Cryptography.Blake2b.csproj`, and
...`Isopoh.Cryptography.Argon2\Isopoh.Cryptography.Argon2.csproj`. For example:
```xml
<ItemGroup>
    <ProjectReference Include="..\..\..\Isopoh.Cryptography.Argon2\Isopoh.Cryptography.SecureArray\Isopoh.Cryptography.SecureArray.csproj" />
</ItemGroup>
```

## Details

### Blake2b Pedigree

Argon2 uses Blake2b as a cryptographic building block. This code uses the
C# implementation of Blake2 modified from https://github.com/BLAKE2.
The main modification is that the Blake2 here uses SecureArray to protect
potentially sensitive data. Most other modifications are strictly cosmetic.

### Argon2 Pedigree

The Argon2 comes from a highly modified port of the C-based Argon2 from
https://github.com/P-H-C/phc-winner-argon2.

### API Documentation

The API Documentation at [https://mheyman.github.io/Isopoh.Cryptography.Argon2](https://mheyman.github.io/Isopoh.Cryptography.Argon2)
gets generated automatically upon build. This happens via a dummy C# "Doc"
project that uses the [*docfx*](https://github.com/dotnet/docfx) NuGet
dependency to produce the API documentation.

## Example Usage

Using the defaults:

```csharp
var password = "password1";
var passwordHash = Argon2.Hash(password);
if (Argon2.Verify(passwordHash, password))
{
    // do stuff
}
```

Setting everything:

```csharp
var password = "password1";
byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
byte[] salt = new byte[16];

// somewhere in the class definition:
//   private static readonly RandomNumberGenerator Rng =
//       System.Security.Cryptography.RandomNumberGenerator.Create();
Rng.GetBytes(salt);

var config = new Argon2Config
{
    Type = Argon2Type.DataIndependentAddressing,
    Version = Argon2Version.Nineteen,
    TimeCost = 10,
    MemoryCost = 32768,
    Lanes = 5,
    Threads = Environment.ProcessorCount,
    Password = passwordBytes,
    Salt = salt, // >= 8 bytes if not null
    Secret = secret, // from somewhere
    AssociatedData = associatedData, // from somewhere
    HashLength = 20 // >= 4
};
var argon2A = new Argon2(config);
string hashString;
using(SecureArray<byte> hashA = argon2A.Hash())
{
    hashString = config.EncodeString(hashA.Buffer);
}

//
// Now pretend "passwordBytes" is what just came in and that it must be
// verified against the known "hashString".
//
// Note setting "Threads" to different values doesn't effect the result,
// just the time it takes to get the result.
//
var configOfPasswordToVerify = new Argon2Config { Password = passwordBytes, Threads = 1 };
SecureArray<byte> hashB = null;
try
{
    if (configOfPasswordToVerify.DecodeString(hashString, out hashB) && hashB != null)
    {
        var argon2ToVerify = new Argon2(configOfPasswordToVerify);
        using(var hashToVerify = argon2ToVerify.Hash())
        {
            if (!hashB.Buffer.Where((b, i) => b != hashToVerify[i]).Any())
            {
                // verified
            }
        }
    }
}
finally
{
    hashB?.Dispose();
}

//
// Or, more simply (but this doesn't allow setting "Threads")
//
if (Argon2.Verify(hashString, passwordBytes))
{
    // verified
}

```

## Just What is This "SecureArray" Used By Argon2?

You can think of the `SecureArray` sort of like you would think of
[`SecureString`](https://docs.microsoft.com/en-us/dotnet/api/system.security.securestring)
except that `SecureString` (usually) does crypto to protect its sensitive
data and has windows of vulnerability when it decrypts the string for use.
`SecureArray` protects its data by locking the data into RAM to keep it from
swapping to disk and also zeroing the buffer when disposed. So, unlike
`SecureString`, any process with access to your process's memory will be able
to read the data in your `SecureArray`, but you do not have to worry about
your data persisting anywhere or multiple copies of your data floating
around RAM due to C#'s memory management.

Because it locks the memory into RAM (and at a
non-movable-by-the-garbage-collector location), you need to use it
as infrequently as possible and for as short a time as possible. RAM secured
this way puts stress on the computer as a whole by denying physical
RAM for other processes and puts stress on your particular executable by
denying freedom to the garbage collector to reduce fragmentation as needed
for best performance.

***Always*** dispose of your `SecureArray`s.
