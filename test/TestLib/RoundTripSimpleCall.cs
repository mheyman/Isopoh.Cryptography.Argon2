// <copyright file="RoundTripSimpleCall.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace TestLib;

using System.Collections.Generic;
using System.Linq;
using Isopoh.Cryptography.Argon2;
using Xunit.Abstractions;

/// <summary>
/// Does a round trip with the simple Argon2.Hash() call.
/// </summary>
public static class RoundTripSimpleCall
{
    /// <summary>
    /// Test <see cref="Argon2"/>.
    /// </summary>
    /// <param name="output">Used to write output.</param>
    /// <returns>
    /// Result text.
    /// </returns>
    public static (bool Passed, string Message) Test(ITestOutputHelper output)
    {
        const string password = "password1";
        const string secret = "secret1";
        var passedResults = new List<string>();
        var failedResults = new List<string>();
        foreach (Argon2Type argon2Type in new[]
            {
                Argon2Type.DataIndependentAddressing, Argon2Type.DataDependentAddressing, Argon2Type.HybridAddressing,
            })
        {
            string argon2Name = argon2Type switch
            {
                Argon2Type.DataIndependentAddressing => "Argon2i",
                Argon2Type.DataDependentAddressing => "Argon2d",
                _ => "Argon2id",
            };

            string passwordHash = Argon2.Hash(password, secret, type: argon2Type);
            output.WriteLine($"{argon2Name} of {password} --> {passwordHash}");

            if (Argon2.Verify(passwordHash, password, secret))
            {
                passedResults.Add(argon2Name);
                output.WriteLine($"RoundTrip2 {argon2Name} Passed");
            }
            else
            {
                failedResults.Add(argon2Name);
                output.WriteLine($"RoundTrip2 {argon2Name} FAILED");
                output.WriteLine($"    expected verify to work for {passwordHash} ({argon2Name} hash of {password})");
            }
        }

        return (!failedResults.Any(), failedResults.Any() ? $"RoundTrip2 FAILED: [{string.Join(", ", failedResults)}] (passed: [{string.Join(", ", passedResults)}])"
            : "RoundTrip2 Passed");
    }
}
