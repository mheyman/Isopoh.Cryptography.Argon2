# Reusing Argon2 memory

Argon2 deliberately uses a large working area. Reallocating that area for every login
or key-derivation request can create large-object allocation pressure, heap
fragmentation, repeated pinning, and repeated operating-system lock calls.

Version 2.0 introduces `Argon2Memory`, which owns the working buffers independently of
one hash operation. Reusing it does not reduce the configured Argon2 time or memory
cost; it reduces the memory-management work around repeated operations.

## Repeated hashing

```csharp
using Isopoh.Cryptography.Argon2;
using Isopoh.Cryptography.SecureArray;

var config = new Argon2Config
{
    Password = passwordBytes,
    Salt = saltBytes,
    MemoryCost = 65_536,
    TimeCost = 3,
    Lanes = 4,
    Threads = 4,
};

using var memory = new Argon2Memory(
    config,
    Argon2MemoryPolicy.NoShrink,
    LockMemoryPolicy.BestEffort);

string encodedHash = Argon2.Hash(memory);

memory.Reset(new Argon2Config
{
    Password = nextPasswordBytes,
    Salt = nextSaltBytes,
    MemoryCost = 65_536,
    TimeCost = 3,
    Lanes = 4,
    Threads = 4,
});

string nextEncodedHash = Argon2.Hash(memory);
```

## Repeated verification

```csharp
memory.Reset(encodedHash, new Argon2Password(candidatePasswordBytes));
bool valid = Argon2.Verify(encodedHash, memory);
```

The large working buffers remain available between operations. The expected hash used
for constant-time comparison is copied only briefly and then zeroed.

## Lifetime rules

- One `Argon2Memory` instance is mutable and is not safe for simultaneous operations.
- Give each concurrent worker exclusive ownership or rent instances from a bounded pool.
- Always call `Reset` with the next operation's password, salt, and parameters.
- Dispose instances when workers retire or the pool shuts down.
- Never return an instance to a pool while hashing or verification is still running.

`Argon2MemoryPolicy.NoShrink` retains the largest capacity requested so far and is best
for steady workloads. `Shrink` releases excess capacity after a smaller reset, trading
lower retained memory for potentially more allocation churn.

See [Server sizing and concurrency](server-sizing.md) before choosing a pool size, and
[Porting from version 1.x to 2.0](porting.md) for all application-facing changes.
