// <copyright file="MemoryNoAlloc.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace TestLib;

using System.Text;
using Isopoh.Cryptography.Argon2;
using Isopoh.Cryptography.SecureArray;
using Xunit.Abstractions;

/// <summary>
/// Look for leaks.
/// </summary>
public static class MemoryNoAlloc
{
    /// <summary>
    /// Look for leaks.
    /// </summary>
    /// <param name="output">Used to write output.</param>
    /// <returns>String with pass/fail message.</returns>
    public static (bool Passed, string Message) Test(ITestOutputHelper output)
    {
        var countLock = new object();
        var lockCount = 0;
        var secureArrayCall = new SecureArrayCall(
            SecureArray.DefaultCall.ZeroMemory,
            (m, l) =>
            {
                string? ret = SecureArray.DefaultCall.LockMemory(m, l);
                lock (countLock)
                {
                    ++lockCount;
                }

                return ret;
            },
            (m, l) =>
            {
                SecureArray.DefaultCall.UnlockMemory(m, l);
            },
            $"Wrapped {SecureArray.DefaultCall.Os}");

        const string password = "b";
        var config = new Argon2Config
        {
            Password = Encoding.UTF8.GetBytes(password),
            SecureArrayCall = secureArrayCall,
        };
        const int maxIteration = 10;
        var memory = new Argon2Memory(config, Argon2MemoryPolicy.NoShrink, LockMemoryPolicy.BestEffort);
        Argon2.Hash(memory);
        int firstLockCount = lockCount;
        for (var i = 0; i < maxIteration; i++)
        {
            output.WriteLine($"TestMemoryNoAlloc: Iteration {i + 1} of {maxIteration}");
            Argon2.Hash(memory);
        }

        return lockCount > firstLockCount
            ? (false, $"Memory No Alloc: FAILED: Got {lockCount - firstLockCount} allocations in {maxIteration} iterations")
            : (true, "Memory No Alloc: Passed");
    }
}