# Porting from version 1.x to 2.0

This guide covers the important application-facing differences between the version on
the 1.x release line and version 2.0. Existing calls such as
`Argon2.Hash(password)` and `Argon2.Verify(encodedHash, password)` continue to be the
simplest choice and generally require no changes.

## Why reuse Argon2 memory?

Argon2 intentionally allocates a large working area—64 MiB with the default
`MemoryCost`. Version 1.x allocates and releases that area for each operation.
On a server that hashes or verifies passwords continuously, this creates repeated large
allocations, garbage-collection pressure, pinned-memory churn, and repeated operating
system memory-lock calls.

`Argon2Memory` owns those buffers separately from an individual `Argon2` operation. It
can therefore be reset and reused across sequential operations. This can provide:

- fewer large-object allocations and less garbage-collector work;
- less heap fragmentation and more predictable request latency;
- fewer pin, lock, and unlock operations for protected memory; and
- reuse of capacity when requests use the same or smaller memory settings.

Reuse does not make the Argon2 calculation itself cheaper. Its configured memory and
time costs still apply on every operation. It reduces memory-management overhead around
the calculation.

## Minimal migration

No migration is required if allocation frequency is unimportant:

```csharp
string hash = Argon2.Hash(password);
bool valid = Argon2.Verify(hash, password);
```

For repeated sequential hashing, create and dispose one `Argon2Memory`, resetting it
before each operation:

```csharp
using Isopoh.Cryptography.Argon2;
using Isopoh.Cryptography.SecureArray;

var initialConfig = new Argon2Config
{
    Password = firstPasswordBytes,
    Salt = firstSalt,
    MemoryCost = 65_536,
    TimeCost = 3,
    Lanes = 4,
    Threads = 4,
};

using var memory = new Argon2Memory(
    initialConfig,
    Argon2MemoryPolicy.NoShrink,
    LockMemoryPolicy.BestEffort);

string firstHash = Argon2.Hash(memory);

memory.Reset(new Argon2Config
{
    Password = nextPasswordBytes,
    Salt = nextSalt,
    MemoryCost = 65_536,
    TimeCost = 3,
    Lanes = 4,
    Threads = 4,
});

string nextHash = Argon2.Hash(memory);
```

For repeated verification, put the candidate password into the reusable memory and then
verify the encoded hash:

```csharp
memory.Reset(encodedHash, new Argon2Password(candidatePasswordBytes));
bool valid = Argon2.Verify(encodedHash, memory);
```

Verification retains the large working buffers. It makes only a small temporary copy of
the expected hash for the constant-time comparison and zeroes that copy immediately.

## Server lifetime and concurrency

An `Argon2Memory` instance is mutable and must not be used by concurrent operations.
Do not register one instance as an application-wide singleton and share it among
requests.

Use one instance per concurrent worker, or maintain a bounded pool:

1. Rent one `Argon2Memory` exclusively for a request.
2. Reset and use it sequentially.
3. Return it only after hashing or verification finishes.
4. Dispose every pooled instance during server shutdown.

Bound the pool according to the server's memory budget. With the default 64 MiB memory
cost, a pool of 16 instances retains roughly 1 GiB just for Argon2 block memory, plus
working buffers and normal process overhead. A bounded pool also limits simultaneous
password hashes, which helps prevent authentication traffic from exhausting RAM.

## Capacity policy

`Argon2MemoryPolicy.NoShrink` retains the largest capacity required so far. It is usually
best for a steady server workload with consistent parameters because subsequent
operations avoid reallocating when their requirements fit that capacity.

`Argon2MemoryPolicy.Shrink` releases excess capacity when a reset needs less memory. It
reduces retained RAM for highly variable or infrequent workloads, but can reintroduce
allocation churn if request sizes alternate.

Memory always grows when a reset requires more capacity, regardless of the policy.

## Memory protection policy

The `LockMemoryPolicy` enum now lives in
`Isopoh.Cryptography.SecureArray`. Its choices are:

- `BestEffort`: request locked, non-swappable memory and fall back to memory that is
  pinned and zeroed when locking is unavailable;
- `Enforce`: fail rather than operate without locked memory;
- `None`: do not request OS memory locking, but still use the zeroed-and-pinned
  `SecureArray` behavior; and
- `null` in the `Argon2Memory` constructor: use ordinary managed buffers without
  `SecureArray` protection.

Browsers and WebAssembly cannot lock memory against swapping. Check
`SecureArray.DefaultCall.IsMemoryLockSupported` when this distinction matters. In those
environments, `BestEffort` accurately reports and uses the zeroed-and-pinned fallback.

Keeping a server pool alive also keeps its buffers pinned—and possibly OS-locked—for the
pool's lifetime. Size the pool deliberately and always dispose it.

## Other API differences

- `new Argon2(config).Hash()` now returns a `Span<byte>` backed by its `Argon2Memory`,
  instead of returning a newly allocated `SecureArray<byte>`. Consume or copy the span
  before another hash, reset, or disposal. Do not dispose the returned span.
- `Argon2.Hash(Argon2Memory)` and `Argon2.Verify(string, Argon2Memory)` are the reusable
  convenience overloads.
- `Argon2Config.WorkingBufferLength` reports the auxiliary working-buffer requirement.
- `Argon2Config.KeyIdentifier` is available in addition to associated data.
- Blake2b exposes `Memory<byte>`/`Span<byte>`-oriented overloads and can accept a reusable
  working buffer. Code explicitly typed as `byte[]` may need `.ToArray()`; avoid that copy
  when the consumer can accept `Memory<byte>` or `Span<byte>`.
- `SecureArray<T>.Create` accepts a `LockMemoryPolicy`, and
  `SecureArrayCall.IsMemoryLockSupported` distinguishes actual memory-lock capability
  from best-effort zeroing and pinning.

## Security checklist

- Dispose `Argon2Memory` when its worker or pool is retired.
- Do not reuse one instance concurrently.
- Reset passwords and salts for every new operation; never accidentally reuse a prior
  password with `Argon2Password.Keep`.
- Set `ClearPassword` and `ClearSecret` according to the required lifetime of those
  values. If enabled, reset them before the next operation.
- Prefer mutable byte buffers over immutable strings when the caller needs control over
  password lifetime.
- Treat browser/Wasm protection as best-effort zeroing, not protected or non-swappable
  secret storage.
