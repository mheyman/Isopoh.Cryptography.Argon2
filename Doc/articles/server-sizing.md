# Server sizing and concurrency

Argon2's memory cost applies to every operation running at the same time. Reusable
memory makes allocations more predictable, but it does not reduce that cryptographic
cost.

As a first approximation:

```text
retained Argon2 memory ≈ worker count × memory cost per worker
```

For example, 16 workers retaining 64 MiB each require about 1 GiB for Argon2 block
memory alone. Add auxiliary buffers, the managed runtime, application data, and safety
headroom before selecting the worker count.

## Recommended server shape

1. Create a bounded pool with at most one `Argon2Memory` instance per permitted
   concurrent operation.
2. Rent an instance exclusively for one hash or verification.
3. Reset it with the request's complete inputs.
4. Return it only after the operation completes.
5. Apply queueing or backpressure when the pool is exhausted.
6. Dispose the pool during graceful shutdown.

This simultaneously bounds retained memory and active CPU-intensive work. An unbounded
pool, or allocating a new instance whenever the pool is empty, defeats that protection.

## Selecting policies

- Prefer `Argon2MemoryPolicy.NoShrink` for consistent authentication parameters and
  predictable steady-state latency.
- Consider `Shrink` for infrequent workloads whose memory requirements vary widely.
- Use `LockMemoryPolicy.BestEffort` when availability is more important than failing on
  OS lock limits.
- Use `Enforce` when non-swappable memory is a hard security requirement, and provision
  the operating-system limits for the entire pool.

Benchmark the complete service under realistic concurrency. Tune time, memory, lanes,
threads, queue depth, and pool size together; optimizing a single hash in isolation does
not establish safe production capacity.
