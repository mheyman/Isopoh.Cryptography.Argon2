// <copyright file="LeakInVerify.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace TestLib;
using Isopoh.Cryptography.Argon2;
using Isopoh.Cryptography.SecureArray;
using System.Collections.Generic;
using System.Linq;
using Xunit.Abstractions;

/// <summary>
/// Look for leaks.
/// </summary>
public static class LeakInVerify
{
    /// <summary>
    /// Look for leaks.
    /// </summary>
    /// <param name="output">Used to write output.</param>
    /// <returns>String with pass/fail message.</returns>
    public static (bool, string) Test(ITestOutputHelper output)
    {
        var locks = new Dictionary<IntPtr, int>();
        var lockCount = 0;
        var badLocks = new List<int>();
        var badUnlockCount = 0;
        var secureArrayCall = new SecureArrayCall(
            SecureArray.DefaultCall.ZeroMemory,
            (m, l) =>
            {
                string? ret = SecureArray.DefaultCall.LockMemory(m, l);
                if (ret == null)
                {
                    lock (locks)
                    {
                        ++lockCount;
                        if (locks.ContainsKey(m))
                        {
                            badLocks.Add(lockCount);
                        }
                        else
                        {
                            locks.Add(m, lockCount);
                        }
                    }
                }

                return ret;
            },
            (m, l) =>
            {
                lock (locks)
                {
                    if (locks.ContainsKey(m))
                    {
                        locks.Remove(m);
                        SecureArray.DefaultCall.UnlockMemory(m, l);
                    }
                    else
                    {
                        ++badUnlockCount;
                    }
                }
            },
            $"Wrapped {SecureArray.DefaultCall.Os}");

        const string hashString = "$argon2i$v=19$m=65536,t=3,p=1$M2f6+jnVc4dyL3BfMQRzoA==$jO/fOrgqxX90XDVhiYZgIVJJcw0lzIXtRFRCEggXYV8=";
        const string password = "b";
        const int maxIteration = 10;
        var memoryDiff = new long[maxIteration];
        for (var i = 0; i < maxIteration; i++)
        {
            output.WriteLine($"TestLeaks: Iteration {i + 1} of {maxIteration}");
            long prevTotalMemory = GC.GetTotalMemory(true);
            Argon2.Verify(hashString, password, secureArrayCall);
            long postTotalMemory = GC.GetTotalMemory(true);
            memoryDiff[i] = postTotalMemory - prevTotalMemory;
        }

        var errs = new List<string>();
        if (memoryDiff.All(v => v > 0))
        {
            errs.Add($"Leaked {memoryDiff.Min()} bytes. [{string.Join(", ", memoryDiff.Select(v => $"{v}"))}]");
        }

        if (badLocks.Any())
        {
            errs.Add($"{badLocks.Count} bad locks: [{string.Join(", ", badLocks.Select(l => $"{l}"))}].");
        }

        if (badUnlockCount > 0)
        {
            errs.Add($"{badUnlockCount} bad unlocks.");
        }

        if (locks.Any())
        {
            errs.Add($"Leaked {locks.Count} locks: addresses=[{string.Join(", ", locks.Keys.Select(k => $"0x{k.ToInt64():x8}"))}], lock index=[{string.Join(", ", locks.Keys.Select(k => $"{locks[k]}"))}].");
        }

        return (!errs.Any(), errs.Any() ? $"Leaks: FAILED: {string.Join(" ", errs)}" : "Leaks: Passed");
    }
}