# Native AOT and browser WebAssembly

Native AOT and browser WebAssembly are different deployment environments even though
both compile code ahead of time.

## Native AOT

.NET Native AOT produces a platform-native executable for a specific runtime identifier,
such as `linux-x64`, `win-x64`, `osx-x64`, or `osx-arm64`. Normal operating-system APIs
remain available, including the native calls used by `SecureArray` for zeroing and
memory locking.

Version 2.0 enables the .NET AOT and trimming analyzers for .NET 10. The repository's
smoke test publishes and executes Native AOT binaries on Windows, Linux, and macOS. On
macOS it also requires a real `mlock` operation to succeed.

## Browser WebAssembly

Browser WebAssembly executes inside the browser sandbox. It cannot call desktop
operating-system memory-lock APIs. Version 2.0 therefore selects a browser-specific
`SecureArrayCall` that clearly reports memory locking as unsupported.

With `LockMemoryPolicy.BestEffort`, buffers are pinned while in use and zeroed when
disposed. With `Enforce`, construction fails. This distinction lets shared code choose
between portable best effort and a fail-closed policy.

## Choosing a target

| Requirement | Native AOT | Browser WebAssembly |
| --- | --- | --- |
| Standalone native executable | Yes | No |
| Browser sandbox execution | No | Yes |
| OS-backed memory locking | Yes, subject to OS policy | No |
| Zero-on-disposal `SecureArray` | Yes | Yes |
| Argon2 hashing and verification | Yes | Yes |

Browser hashing does not remove the need for TLS. Carefully define whether the server
receives the password, a derived credential, or both; a reusable derived value can
itself become the credential an attacker needs.
