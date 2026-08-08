// <copyright file="Program.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

using System;
using System.Runtime.InteropServices;
using Isopoh.Cryptography.Argon2;
using Isopoh.Cryptography.SecureArray;

const string password = "native-aot-smoke-test";
string hash = Argon2.Hash(password, timeCost: 1, memoryCost: 1024, parallelism: 1);

if (!Argon2.Verify(hash, password))
{
    throw new InvalidOperationException("Native AOT Argon2 verification failed.");
}

var reusableConfig = new Argon2Config
{
    Password = "initial"u8.ToArray(),
    Salt = new byte[16],
    TimeCost = 1,
    MemoryCost = 1024,
    Lanes = 1,
    Threads = 1,
};
using var reusableMemory = new Argon2Memory(
    reusableConfig,
    Argon2MemoryPolicy.NoShrink,
    LockMemoryPolicy.BestEffort);

reusableMemory.Reset(hash, new Argon2Password("native-aot-smoke-test"u8.ToArray()));
if (!Argon2.Verify(hash, reusableMemory))
{
    throw new InvalidOperationException("Reusable-memory verification rejected the correct password.");
}

reusableMemory.Reset(hash, new Argon2Password("wrong-password"u8.ToArray()));
if (Argon2.Verify(hash, reusableMemory))
{
    throw new InvalidOperationException("Reusable-memory verification accepted an incorrect password.");
}

var browserLikeCall = new SecureArrayCall(
    (pointer, length) => Marshal.Copy(new byte[(int)length], 0, pointer, (int)length),
    (pointer, length) => "Memory locking is unavailable",
    (pointer, length) => { },
    "WebAssembly smoke test",
    false);

using SecureArray<byte> buffer = SecureArray<byte>.Create(32, browserLikeCall);
if (browserLikeCall.IsMemoryLockSupported || buffer.ProtectionType != SecureArrayType.ZeroedAndPinned)
{
    throw new InvalidOperationException("Unsupported memory locking did not use the pinned fallback.");
}

Console.WriteLine("Native AOT Argon2 smoke test passed.");
