// <copyright file="FromDraft3.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace TestLib;

using System;
using System.Linq;
using Isopoh.Cryptography.Argon2;
using Xunit.Abstractions;

/// <summary>
/// Has a method that runs tests from draft-irtf-cfrg-argon2-03.
/// </summary>
public static class FromDraft3
{
    /// <summary>
    /// Runs some tests from draft-irtf-cfrg-argon2-03 that disappeared later.
    /// </summary>
    /// <param name="output">Used to write output.</param>
    /// <returns>Tuple with a bool indicating pass or fail and associated text detail.</returns>
    public static (bool Passed, string Message) Test(ITestOutputHelper output)
    {
        // from draft-irtf-cfrg-argon2-03
        // They have this code in version 3 of the draft, but it is gone in version 4.
        byte[]? testPwd = "pasword"u8.ToArray();
        byte[]? testSalt = "somesalt"u8.ToArray();
        const int testTimeCost = 3;
        const int testMemoryCost = 1 << 12;
        const int testParallelism = 1;
        const Argon2Version testArgon2VersionNumber = Argon2Version.Nineteen;
        bool independent = Argon2ISelfTest();
        bool dependent = Argon2DSelfTest();
        bool hybrid = Argon2IdSelfTest();
        var argon2IResult = $"draft-irtf-cfrg-argon2-03 Argon2i  - {(independent ? "Passed" : "FAIL")}";
        output.WriteLine(argon2IResult);
        var argon2DResult = $"draft-irtf-cfrg-argon2-03 Argon2d  - {(dependent ? "Passed" : "FAIL")}";
        output.WriteLine(argon2DResult);
        var argon2IdResult = $"draft-irtf-cfrg-argon2-03 Argon2id - {(hybrid ? "Passed" : "FAIL")}";
        output.WriteLine(argon2IdResult);
        return (independent && dependent && hybrid, string.Join($"{Environment.NewLine}  ", argon2IResult, argon2DResult, argon2IdResult));

        bool Argon2IdSelfTest()
        {
            byte[] expectedHash =
            {
                0xf5, 0x55, 0x35, 0xbf, 0xe9, 0x48, 0x71, 0x00,
                0x51, 0x42, 0x4c, 0x74, 0x24, 0xb1, 0x1b, 0xa9,
                0xa1, 0x3a, 0x50, 0x23, 0x9b, 0x04, 0x59, 0xf5,
                0x6c, 0xa6, 0x95, 0xea, 0x14, 0xbc, 0x19, 0x5e,
            };
            return Run(
                testPwd,
                testSalt,
                testTimeCost,
                testMemoryCost,
                testParallelism,
                Argon2Type.HybridAddressing,
                testArgon2VersionNumber,
                expectedHash);
        }

        bool Argon2DSelfTest()
        {
            byte[] expectedHash =
            {
                0x0b, 0x3f, 0x09, 0xe7, 0xb8, 0xd0, 0x36, 0xe5,
                0x8c, 0xcd, 0x08, 0xf0, 0x8c, 0xb6, 0xba, 0xbf,
                0x7e, 0x5e, 0x24, 0x63, 0xc2, 0x6b, 0xcf, 0x2a,
                0x9e, 0x4e, 0xa7, 0x0d, 0x74, 0x7c, 0x40, 0x98,
            };
            return Run(
                testPwd,
                testSalt,
                testTimeCost,
                testMemoryCost,
                testParallelism,
                Argon2Type.DataDependentAddressing,
                testArgon2VersionNumber,
                expectedHash);
        }

        bool Argon2ISelfTest()
        {
            byte[] expectedHash =
            {
                0x95, 0x7f, 0xc0, 0x72, 0x7d, 0x83, 0xf4, 0x06,
                0x0b, 0xb0, 0xf1, 0x07, 0x1e, 0xb5, 0x90, 0xa1,
                0x9a, 0x8c, 0x44, 0x8f, 0xc0, 0x20, 0x94, 0x97,
                0xee, 0x4f, 0x54, 0xca, 0x24, 0x1f, 0x3c, 0x90,
            };
            return Run(
                testPwd,
                testSalt,
                testTimeCost,
                testMemoryCost,
                testParallelism,
                Argon2Type.DataIndependentAddressing,
                testArgon2VersionNumber,
                expectedHash);
        }

        bool Run(
            byte[] pwd,
            byte[] salt,
            int timeCost,
            int memoryCost,
            int threads,
            Argon2Type argon2Type,
            Argon2Version version,
            byte[] expectedHash)
        {
            Span<byte> hash = new Argon2(
                new Argon2Config
                {
                    HashLength = expectedHash.Length,
                    TimeCost = timeCost,
                    MemoryCost = memoryCost,
                    Lanes = threads,
                    Threads = threads,
                    Password = pwd,
                    Salt = salt,
                    Version = version,
                    Type = argon2Type,
                }).Hash();
            output.WriteLine($"     Actual Hash:   {BitConverter.ToString(hash.ToArray())}");
            output.WriteLine($"     Expected Hash: {BitConverter.ToString(expectedHash)}");
            return !hash.ToArray().Where((b, i) => b != expectedHash[i]).Any();
        }
    }
}
