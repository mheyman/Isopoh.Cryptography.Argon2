// <copyright file="RoundTrip.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace TestLib;

using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Isopoh.Cryptography.Argon2;
using Isopoh.Cryptography.SecureArray;
using Xunit.Abstractions;

/// <summary>
/// Does a round trip, hashing and verifying.
/// </summary>
public static class RoundTrip
{
    private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

    /// <summary>
    /// Test <see cref="Argon2"/>.
    /// </summary>
    /// <param name="output">Used to write output.</param>
    /// <returns>
    /// The result text.
    /// </returns>
    public static (bool Passed, string Message) Test(ITestOutputHelper output)
    {
        const string password = "password1";
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        var salt = new byte[16];
        Rng.GetBytes(salt);
        const string secret = "secret1";
        byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
        var failedResults = new List<string>();
        var passedResults = new List<string>();
        foreach (Argon2Type argon2Type in new[] { Argon2Type.DataIndependentAddressing, Argon2Type.DataDependentAddressing, Argon2Type.HybridAddressing })
        {
            string argon2Name = argon2Type switch
            {
                Argon2Type.DataIndependentAddressing => "Argon2i",
                Argon2Type.DataDependentAddressing => "Argon2d",
                _ => "Argon2id",
            };
            var config = new Argon2Config
            {
                Type = argon2Type,
                Version = Argon2Version.Nineteen,
                Password = passwordBytes,
                Salt = salt,
                Secret = secretBytes,
                TimeCost = 3,
                MemoryCost = 65536,
                Lanes = 4,
                Threads = 2,
            };
            var argon2 = new Argon2(config);
            Span<byte> hash = argon2.Hash();
            string passwordHash = config.EncodeString(hash);
            output.WriteLine($"{argon2Name} of {password} --> {passwordHash}");
            if (Argon2.Verify(passwordHash, passwordBytes, secretBytes, SecureArray.DefaultCall))
            {
                passedResults.Add(argon2Name);
                output.WriteLine($"Round Trip {argon2Name} Passed");
            }
            else
            {
                failedResults.Add(argon2Name);
                output.WriteLine($"Round Trip {argon2Name} FAILED");
                output.WriteLine($"    expected verify to work for {passwordHash} (Argon2 hash of {password})");
            }
        }

        return (!failedResults.Any(), failedResults.Any() ? $"RoundTrip FAILED: [{string.Join(", ", failedResults)}] (passed: [{string.Join(", ", passedResults)}])"
            : "RoundTrip Passed");
    }
}