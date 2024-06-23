// <copyright file="LeakInHash.cs" company="Isopoh">
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
public static class LeakInHash
{
    /// <summary>
    /// Look for leaks.
    /// </summary>
    /// <param name="output">Used to write output.</param>
    /// <returns>String with pass/fail message.</returns>
    public static (bool Passed, string Message) Test(ITestOutputHelper output)
    {
        var locks = new Dictionary<IntPtr, (UIntPtr, int)>(); // address to (size, index)
        var lockCount = 0;
        var failedLocks = new List<(IntPtr, UIntPtr)>(); // (address, size)
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
                        if (!locks.TryAdd(m, (l, lockCount)))
                        {
                            badLocks.Add(lockCount);
                        }
                    }
                }
                else
                {
                    lock (locks)
                    {
                        failedLocks.Add((m, l));
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

        const string password = "b";
        const int maxIteration = 10;
        var memoryDiff = new long[maxIteration];
        var config = new Argon2Config
        {
            Password = Encoding.UTF8.GetBytes(password),
            SecureArrayCall = secureArrayCall,
        };
        for (var i = 0; i < maxIteration; i++)
        {
            output.WriteLine($"TestHashLeaks: Iteration {i + 1} of {maxIteration}");
            Thread.Sleep(100);
            long prevTotalMemory = GC.GetTotalMemory(true);
            {
                Argon2.Hash(config);
            }

            Thread.Sleep(100);
            long postTotalMemory = GC.GetTotalMemory(true);
            memoryDiff[i] = postTotalMemory - prevTotalMemory;
        }

        string? failedLocksMessage = null;
        if (failedLocks.Count > 0)
        {
            string s = failedLocks.Count > 1 ? "s" : string.Empty;

            // only printed if any other failures.
            failedLocksMessage = $"{failedLocks.Count} / {lockCount} failed lock{s}, size{s}=[{string.Join(", ", failedLocks.Select(x => $"0x{x.Item1.ToInt64():x8}:{x.Item2.ToUInt64()}"))}].";
        }

        var errs = new List<string>();
        if (memoryDiff.All(v => v > 0))
        {
            errs.Add($"Leaked {memoryDiff.Min()} bytes. [{string.Join(", ", memoryDiff.Select(v => $"{v}"))}].");
        }

        if (badLocks.Any())
        {
            errs.Add($"{badLocks.Count} / {lockCount} bad locks: [{string.Join(", ", badLocks.Select(l => $"{l}"))}].");
        }

        if (badUnlockCount > 0)
        {
            errs.Add($"{badUnlockCount} bad unlocks.");
        }

        if (locks.Any())
        {
            errs.Add($"Leaked {locks.Count} / {lockCount} locks: address:size:index=[{string.Join(", ", locks.Select(kv => $"0x{kv.Key.ToInt64():x8}:{kv.Value.Item1.ToUInt64()}:{kv.Value.Item2}"))}].");
        }

        return (!errs.Any(), errs.Any() ? $"Hash leaks: FAILED: {string.Join(" ", errs)}{(failedLocksMessage == null ? string.Empty : $" {failedLocksMessage}")}" : "Leaks: Passed");
    }
}