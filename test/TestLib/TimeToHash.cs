// <copyright file="TimeToHash.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace TestLib;
using Isopoh.Cryptography.Argon2;
using System.Collections.Generic;
using System.Linq;
using Xunit.Abstractions;

/// <summary>
/// Has a method that tests time to hash.
/// </summary>
public static class TimeToHash
{
    /// <summary>
    /// Test-by-inspection that hash is slowest when parallelism is 1.
    /// (Depending on core count, it may go down and back up after that).
    /// </summary>
    /// <param name="output">Used to write output.</param>
    /// <returns>TestTimeToHash: Passed.</returns>
    public static (bool, string) Test(ITestOutputHelper output)
    {
        (double, string, string) Check7(int p)
        {
            const string password = "hello world";
            string ret = string.Empty;
            var res = new List<double>();
            for (int i = 0; i < 5; ++i)
            {
                var tick = DateTimeOffset.UtcNow;
                ret = Argon2.Hash(password, parallelism: p);
                res.Add((DateTimeOffset.UtcNow - tick).TotalSeconds);
            }

            res.Sort();
            var take = res.Count - 4;
            return (res.Skip(2).Take(take).Average(), password, ret);
        }

        var res = new List<string>();
        for (int parallelism = 1; parallelism <= 20; ++parallelism)
        {
            var (tick, pw, hash) = Check7(parallelism);
            res.Add($"{parallelism}:{tick:F3}");
            output.WriteLine($"Parallelism {parallelism:D2}: {tick:F3} seconds, \"{pw}\" => {hash}");
        }

        return (true, $"TestTimeToHash: Passed. {string.Join(", ", res)}");
    }
}
