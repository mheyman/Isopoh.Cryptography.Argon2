# Secure memory by platform

`SecureArray<T>` zeroes its buffer on disposal and can ask supported operating systems
to keep its pages resident in memory. The exact guarantee depends on the platform and
the selected `LockMemoryPolicy`.

| Environment | Zero on disposal | Pinned while in use | OS memory locking |
| --- | --- | --- | --- |
| Windows | Yes | Yes | Supported through the native Windows API |
| macOS | Yes | Yes | Supported through `mlock` |
| Linux | Yes | Yes | Supported through `mlock`, subject to process limits |
| Browser WebAssembly | Yes | Yes | Not available |

## Lock policies

- `BestEffort` attempts OS locking and falls back to zeroed, pinned memory if locking is
  unsupported or refused.
- `Enforce` throws `LockFailException` instead of operating without an OS lock.
- `None` skips the lock attempt but retains pinning and zero-on-disposal behavior.
- Passing `null` as the `Argon2Memory` lock policy uses ordinary managed working buffers.

Portable applications normally use `BestEffort`. Applications whose threat model
requires non-swappable pages should use `Enforce`, fail closed, and test deployment
limits before accepting traffic.

```csharp
using SecureArray<byte> secret = SecureArray<byte>.Create(
    4096,
    SecureArray.DefaultCall,
    LockMemoryPolicy.Enforce);

if (secret.ProtectionType != SecureArrayType.ZeroedPinnedAndNoSwap)
{
    throw new InvalidOperationException("The buffer was not locked.");
}
```

`SecureArray.DefaultCall.IsMemoryLockSupported` reports whether the environment has a
locking implementation. `ProtectionType` reports what a particular buffer actually
received.

## Operational cautions

- Linux commonly limits the number of bytes a process may lock. Configure and monitor
  that limit when using `Enforce` or large pools.
- Reusable pools retain their locked pages for the pool lifetime. This is intentional,
  but the pool must be bounded.
- Pinning and zeroing reduce specific risks; they do not isolate memory from malicious
  script, browser extensions, process compromise, crash dumps, or a debugger.
- Immutable .NET strings cannot be reliably erased. Prefer mutable byte buffers when
  controlling the password lifetime matters.
