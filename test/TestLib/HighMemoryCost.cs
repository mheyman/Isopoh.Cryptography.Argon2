// <copyright file="HighMemoryCost.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace TestLib;

using Isopoh.Cryptography.Argon2;
using Xunit.Abstractions;

/// <summary>
/// Tests that the hash will work with more RAM than C# can allocate in a single chunk.
/// </summary>
public static class HighMemoryCost
{
    /// <summary>
    /// Make sure it works with more RAM than C# can allocate in a single chunk.
    /// </summary>
    /// <param name="output">Used to write output.</param>
    /// <returns>String with pass/fail message.</returns>
    public static (bool Passed, string Message) Test(ITestOutputHelper output)
    {
        output.WriteLine("HighMemoryCost");

        // Tests chunking the Argon2 working memory because of the limits of C# array sizes.
        // this can take a long time depending on the multiplier
        output.WriteLine("HighMemoryCost:");
        const string password = "password";
        const int memoryCost = Argon2Memory.CsharpMaxBlocksPerArray + 271;
        JetBrains.Profiler.Api.MemoryProfiler.GetSnapshot();
        output.WriteLine("HighMemoryCost: Hash");
        string hash = Argon2.Hash(password, memoryCost: memoryCost, parallelism: 20, secureArrayCall: new InsecureArrayCall());
        JetBrains.Profiler.Api.MemoryProfiler.GetSnapshot();
        output.WriteLine("HighMemoryCost: Verify");
        bool ret = Argon2.Verify(hash, password);
        output.WriteLine($"HighMemoryCost: verify {(ret ? "Success" : "FAIL")}");
        JetBrains.Profiler.Api.MemoryProfiler.GetSnapshot();

        return (ret, $"HighMemoryCost: {(ret ? "Passed" : "FAILED")}");
    }
}
