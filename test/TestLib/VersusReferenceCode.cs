﻿// <copyright file="VersusReferenceCode.cs" company="Isopoh">
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
/// Has a method that tests against a plethora of test vectors generated by the
/// C-language reference argon2 command line example code.
/// </summary>
public static class VersusReferenceCode
{
    /// <summary>
    /// Test <see cref="Argon2"/> against test vectors generated by the C-language reference command line example.
    /// </summary>
    /// <param name="output">Used to write output.</param>
    /// <returns>Result text.</returns>
    public static (bool, string) Test(ITestOutputHelper output)
    {
        var testVectors = new global::Argon2TestVector.Test().Argon2Vectors;
        var faileds = new List<int>();
        foreach (var (i, testVector) in testVectors.Select((a, i) => (i, a)))
        {
            if (!Argon2TestVectorTypeBasicCheck.Test(i, testVector, output))
            {
                faileds.Add(i);
            }
        }

        var res = faileds.Any() ? $"Argon2AgainstReference FAILED {faileds.Count}/{testVectors.Count} [{string.Join(", ", faileds.Select(a => $"{a}"))}]" : $"Argon2AgainstReference Passed {testVectors.Count} checks";
        return (!faileds.Any(), res);
    }
}