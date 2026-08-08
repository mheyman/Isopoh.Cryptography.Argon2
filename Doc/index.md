# Isopoh.Cryptography.Argon2 2.x

Isopoh.Cryptography.Argon2 is a fully managed .NET implementation of the Argon2
password-hashing and key-derivation algorithm. It runs on Windows, Linux, macOS,
Native AOT, and browser WebAssembly without a native Argon2 dependency.

```shell
dotnet add package Isopoh.Cryptography.Argon2
```

```csharp
using Isopoh.Cryptography.Argon2;

string encodedHash = Argon2.Hash(password);
bool valid = Argon2.Verify(encodedHash, password);
```

## Version 2.0

Version 2.0 adds reusable Argon2 working memory for allocation-sensitive server
workloads, explicit memory-lock policies, clearer browser behavior, and .NET 10 Native
AOT compatibility.

- Existing `Argon2.Hash` and `Argon2.Verify` calls remain the simplest API.
- [`Argon2Memory`](articles/reusable-memory.md) allows sequential operations to reuse
  large working buffers.
- [`SecureArray`](articles/secure-memory.md) reports whether memory was actually locked
  or whether a platform uses the pinned, zero-on-disposal fallback.
- [Native AOT and browser WebAssembly](articles/aot-and-wasm.md) have different security
  capabilities and are documented separately.

Applications upgrading from 1.x should begin with the
[porting guide](articles/porting.md). Server applications should also review
[server sizing and concurrency](articles/server-sizing.md).

## Packages

| Package | Purpose |
| --- | --- |
| [Isopoh.Cryptography.Argon2](https://www.nuget.org/packages/Isopoh.Cryptography.Argon2/) | Argon2 hashing and verification |
| [Isopoh.Cryptography.Blake2b](https://www.nuget.org/packages/Isopoh.Cryptography.Blake2b/) | Blake2b implementation used by Argon2 |
| [Isopoh.Cryptography.SecureArray](https://www.nuget.org/packages/Isopoh.Cryptography.SecureArray/) | Zeroed, pinned, and optionally OS-locked buffers |

See the [API reference](api/index.md), the
[GitHub repository](https://github.com/mheyman/Isopoh.Cryptography.Argon2), and the
[latest release](https://github.com/mheyman/Isopoh.Cryptography.Argon2/releases/latest).
