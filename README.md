![Isopoh](https://raw.githubusercontent.com/mheyman/Isopoh.Cryptography.Argon2/master/.github/images/isopoh144.png)

# FULLY MANAGED .NET CORE ARGON2 IMPLEMENTATION
[d]: #project
**[INSTALL][i] | [USAGE][u] | [API][a] | [AUTHOR][auth] | [LICENSE][cpl]**

> Argon2 is a hash generator optimized to produce hashes suitable for
> credential storage, key derivation, or other situations requiring a
> cryptographically secure password hash. Argon2 was the winner of the
> 2015 [Password Hashing Competition](https://password-hashing.net/).
>
> This fully managed implementation of Argon2 runs in ***.NET Core***, ***.NET
> Framework***, or ***WebAssembly*** (via [Blazor](https://dotnet.microsoft.com/apps/aspnet/web-apps/blazor)
> or [Uno Platform](https://platform.uno/)).

Standard Argon2 Hashing:
```csharp
var password = "password1";
var passwordHash = Argon2.Hash(password);
```
Argon2 Verification:
```csharp
if (Argon2.Verify(passwordHash, password))
{
    // do stuff
}
```

All Argon2 options available for your hashing needs...

## MOTIVATION
[mo]: #motivation 'Why C# Argon2'

The Argon2 reference implementation is available from https://github.com/p-h-c/phc-winner-argon2
and, indeed, the C# code in this repository was based upon that implementation
but that implementation is in C. Building a C# wrapper around the C
implementation is possible but adds complexity.

This 100% managed-code library allows you to use the Argon2 hash in any
.NET (including Blazor) application without added complexity.

## GETTING STARTED
[gt]: #getting-started 'Getting started guide'

This requires a .NET environment and runs on Windows, Linux, MacOS, and WebAssembly (via Blazor).

### INSTALLATION
[i]: #installation 'Installation guide'

#### NUGET
[nuget]: #nuget 'Install via NuGet'

The recommended way to get started is by use the NuGet package:

```shell
Install-Package Isopoh.Cryptography.Argon2
```

from [https://www.nuget.org/packages/Isopoh.Cryptography.Argon2](https://www.nuget.org/packages/Isopoh.Cryptography.Argon2).

This project uses [SourceLink](https://github.com/dotnet/sourcelink/blob/master/README.md)
so you should be able to step into the source code for debugging even when
just adding the NuGet package as a dependency.

#### CLONE
[clone]: #clone 'Install via clone'

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

### USAGE
[u]: #usage 'Product usage'

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
    Threads = Environment.ProcessorCount, // higher than "Lanes" doesn't help (or hurt)
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
            if (Argon2.FixedTimeEquals(hashB, hashToVerify))
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
// Or, more simply (setting "Threads" to "5")
//
if (Argon2.Verify(hashString, passwordBytes, 5))
{
    // verified
}

```

## API
[a]: #api 'Argon2\'s API description'

The full API is at
[https://mheyman.github.io/Isopoh.Cryptography.Argon2](https://mheyman.github.io/Isopoh.Cryptography.Argon2).

In particular, the various options for Argon2 hashing can be found in
[Argon2Config](https://mheyman.github.io/Isopoh.Cryptography.Argon2/api/Isopoh.Cryptography.Argon2.Argon2Config.html#properties)
and used with [Argon2.Hash()](https://mheyman.github.io/Isopoh.Cryptography.Argon2/api/Isopoh.Cryptography.Argon2.Argon2.html#Isopoh_Cryptography_Argon2_Argon2_Hash_Isopoh_Cryptography_Argon2_Argon2Config_).
There are other `Argon2.Hash()` convenience calls available there as well.

If you are only interested in Blake2b, the underlying hash used in Argon2, you
can go to the [Blake2b.ComputeHash()](https://mheyman.github.io/Isopoh.Cryptography.Argon2/api/Isopoh.Cryptography.Blake2b.Blake2B.html#Isopoh_Cryptography_Blake2b_Blake2B_ComputeHash_System_Byte___Isopoh_Cryptography_Blake2b_Blake2BConfig_Isopoh_Cryptography_SecureArray_SecureArrayCall_)
calls.

Also, there is [SecureArray&lt;T>](https://mheyman.github.io/Isopoh.Cryptography.Argon2/api/Isopoh.Cryptography.SecureArray.SecureArray-1.html). The `SecureArray` takes a [SecureArrayCall](https://mheyman.github.io/Isopoh.Cryptography.Argon2/api/Isopoh.Cryptography.SecureArray.SecureArrayCall.html)
which is a class that has three `Func<>` properties, one to
[LockMemory](https://mheyman.github.io/Isopoh.Cryptography.Argon2/api/Isopoh.Cryptography.SecureArray.SecureArrayCall.html#Isopoh_Cryptography_SecureArray_SecureArrayCall_LockMemory),
one to
[UnlockMemory](https://mheyman.github.io/Isopoh.Cryptography.Argon2/api/Isopoh.Cryptography.SecureArray.SecureArrayCall.html#Isopoh_Cryptography_SecureArray_SecureArrayCall_UnlockMemory),
and one to [ZeroMemory](https://mheyman.github.io/Isopoh.Cryptography.Argon2/api/Isopoh.Cryptography.SecureArray.SecureArrayCall.html#Isopoh_Cryptography_SecureArray_SecureArrayCall_ZeroMemory).
You can easily create your own `SecureArrayCall` to lock/unlock/zero or perhaps
to log secure memory actions.

### JUST WHAT IS THIS "SecureArray"?
[seca]: #securearry 'SecureArray description'

You can think of the `SecureArray` sort of like you would think of
[`SecureString`](https://docs.microsoft.com/en-us/dotnet/api/system.security.securestring)
except that `SecureString` does crypto (usually -
[encryption isn't supported everywhere](https://github.com/dotnet/platform-compat/blob/master/docs/DE0001.md))
to protect its sensitive data and has windows of vulnerability when it
decrypts the string for use. `SecureArray` protects its data by locking the
data into RAM to keep it from swapping to disk and also zeroing the buffer when
disposed. So, unlike `SecureString`, any process with access to your process's
memory will be able to read the data in your `SecureArray`, but you do not
have to worry about your data persisting anywhere or multiple copies of your
data floating around RAM due to C#'s memory management.

Because it locks the memory into RAM (and at a
non-movable-by-the-garbage-collector location), you need to use it
as infrequently as possible and for as short a time as possible. RAM secured
this way puts stress on the computer as a whole by denying physical
RAM for other processes and puts stress on your particular executable by
denying freedom to the garbage collector to reduce fragmentation as needed
for best performance.

Note: when using SecureArray in the browser (for example, under Blazor or UnoPlatform),
the memory cannot be locked into RAM so SecureArray does its best effort to protect the
data by zeroing the buffer when it is disposed.

Note similarly: when using SecureArray in a Universal Windows Platform (UWP)
application, I have yet to figure out how to use the supposedly available
`VirtualAllocFromApp()` system call to lock memory into RAM so SecureArray does
its best effort to protect the data by zeroing the buffer when it is disposed.

***Always*** dispose of your `SecureArray`s.

### BLAKE2B PEDIGREE
[blake2]: #blake2 'Blake2b Pedigree'

Argon2 uses Blake2b as a cryptographic building block. This code uses the
C# implementation of Blake2 modified from https://github.com/BLAKE2.
The main modification is that the Blake2 here uses [SecureArray&lt;T>](https://mheyman.github.io/Isopoh.Cryptography.Argon2/api/Isopoh.Cryptography.SecureArray.SecureArray-1.html). The `SecureArray` takes a [SecureArrayCall](https://mheyman.github.io/Isopoh.Cryptography.Argon2/api/Isopoh.Cryptography.SecureArray.SecureArrayCall.html)
to protect potentially sensitive data. Most other modifications are
strictly cosmetic.

As part of this Blake2b port, an effort was made to speed Blake2b by using
techniques like unrolling and using raw buffers in unsafe code. It turns out
the CLR optimizes plain code better than unrolled/unsafe code and the original
always ran faster. At some point I may try a port to [System.Numerics.Vector&lt;T>](https://docs.microsoft.com/en-us/dotnet/api/system.numerics.vector-1)...

### API GENERATION
[apigen]: #apigen 'API Generation'

The API Documentation at [https://mheyman.github.io/Isopoh.Cryptography.Argon2](https://mheyman.github.io/Isopoh.Cryptography.Argon2)
gets generated automatically upon build. This happens via a dummy C# "Doc"
project that uses the [*DocFx*](https://github.com/dotnet/docfx) NuGet
package to produce the API documentation.

## AUTHOR
[auth]: #author 'Credits & author\'s contacts info'
[Michael Heyman](https://github.com/mheyman)

## ACKNOWLEDGMENTS
[acc]: acknowledgments

List of people and project that inspired creation of this one:

- The many contributers of the [Argon2 repository](https://github.com/p-h-c/phc-winner-argon2)
- and the cryptographers responsible for creating and testing that algorithm
- @CodesInChaos for the fully managed Blake2b implementation [here](https://github.com/BLAKE2/BLAKE2)
- @PurpleBooth for his readme template posted [here](https://gist.github.com/PurpleBooth/109311bb0361f32d87a2)

## LICENSE
[cpl]:#license 'License info'

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br /><span xmlns:dct="http://purl.org/dc/terms/" property="dct:title">Isopoh.Cryptography.Argon2</span> by <a xmlns:cc="http://creativecommons.org/ns#" href="https://github.com/mheyman/Isopoh.Cryptography.Argon2" property="cc:attributionName" rel="cc:attributionURL">Michael Heyman</a> is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
## PRODUCTION STATUS & SUPPORT
[ps]: #production-status--support 'Production use disclaimer & support info'

You should be aware that this project is supported solely by me and provided as is.

Go back to the **[project description][d]**

