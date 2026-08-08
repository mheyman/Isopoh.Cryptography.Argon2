# Argon2 in WebAssembly

Isopoh.Cryptography.Argon2 is fully managed and can run in browser WebAssembly
applications. Version 2.0 makes the browser security boundary explicit: browser
WebAssembly cannot ask the operating system to keep a buffer out of swap, so
`SecureArray` pins and zeroes sensitive buffers but does not claim that they are
OS-locked.

Start with [Native AOT and browser WebAssembly](aot-and-wasm.md) for the distinction
between the two deployment models and [Secure memory by platform](secure-memory.md)
for the guarantees available in each environment.

## Browser guidance

- Benchmark on the devices you support. Argon2 is deliberately CPU- and
  memory-intensive, and mobile devices may be much slower than development machines.
- Keep memory cost and concurrency bounded so a page cannot exhaust the browser tab's
  memory.
- Perform hashing away from latency-sensitive UI work where the application model
  permits it.
- Do not treat client-side hashing as a replacement for TLS or for server-side password
  hashing. If a browser-derived value is accepted as a credential, that value effectively
  becomes the password from the server's perspective.
- Use `LockMemoryPolicy.BestEffort` in portable code. In a browser it falls back to
  pinned, zero-on-disposal memory; `Enforce` fails because memory locking is unavailable.

The repository contains examples for [Blazor WebAssembly](blazor.md) and the
[Uno Platform](unoplatform.md). They are demonstrations rather than performance or
security prescriptions for every application.
