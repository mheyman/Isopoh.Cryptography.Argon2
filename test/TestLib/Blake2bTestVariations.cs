// <copyright file="Blake2bTestVariations.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

using Isopoh.Cryptography.SecureArray;

namespace TestLib;
using Isopoh.Cryptography.Blake2b;
using Xunit.Abstractions;
using System;

public class Blake2bTestVariations
{
    /// <summary>
    /// Make sure it works with more RAM than C# can allocate in a single chunk.
    /// </summary>
    /// <param name="output">Used to write output.</param>
    /// <returns>String with pass/fail message.</returns>
    public static (bool, string) Test(ITestOutputHelper output)
    {
        bool ret = true;
        int count = 0;
        int failCount = 0;
        var keyHashBuffer = FilledBuf(Blake2B.BufferMinimumTotalSize)!.Value;
        var noKeyHashBuffer = FilledBuf(Blake2B.NoKeyBufferMinimumTotalSize)!.Value;
        for (int dataLength = 10; dataLength < 600; dataLength += 81)
        {
            var data = FilledBuf(dataLength)!.Value;
            foreach (var keyLength in new[] { -1, 0, 7, 8, 9, 31, 32, 33, 63, 64 })
            {
                var hashBuffer = keyLength > 0 ? keyHashBuffer : noKeyHashBuffer;
                foreach (var hasSalt in new[] { false, true })
                {
                    foreach (var outputLength in new [] { 1, 2, 7, 8, 9, 31, 32, 33, 63, 64 })
                    {
                        var ec = Config(keyLength, hasSalt, outputLength, true);
                        var res = ec.Result64ByteBuffer!.Value;
                        Blake2B.ComputeHash(data.Span, ec, hashBuffer).ToArray();
                        foreach (var hasOutput in new[] { true, false })
                        {
                            var c1 = Config(keyLength, hasSalt, outputLength, hasOutput);
                            var check1 = Blake2B.ComputeHash(data.Span, c1, hashBuffer).ToArray();
                            var c2 = Config(keyLength, hasSalt, outputLength, hasOutput);
                            var check2 = Blake2B.ComputeHash(data.ToArray(), c2, SecureArray.DefaultCall).ToArray();

                            foreach (var (c, check, usedMemory) in new[] { (c1, check1, true), (c2, check2, false) })
                            {
                                if (c.Result64ByteBuffer.HasValue)
                                {
                                    ++count;
                                    if (!Verify(dataLength, keyLength, hasSalt, outputLength, usedMemory, res.Span, c.Result64ByteBuffer.Value.Span, output))
                                    {
                                        ++failCount;
                                        ret = false;
                                    }
                                }

                                ++count;
                                if (!Verify(dataLength, keyLength, hasSalt, outputLength, usedMemory, res.Span, check, output))
                                {
                                    ++failCount;
                                    ret = false;
                                }
                            }
                        }
                    }
                }
            }
        }

        return (ret, failCount == 0 ? $"SUCCESS! {count} checks" : $"Failed {failCount} of {count}");
    }

    private static string Detail(int dataLength, int keyLength, bool hasSalt, bool usedMemory, int outputLength, int ofLength) =>
        $"(d:{(dataLength >= 0 ? $"{dataLength}" : "<null>")}, k:{(keyLength >= 0 ? $"{keyLength}" : "<null>")}, {(hasSalt ? "has" : "no")} salt, {(usedMemory ? "Memory<byte>" : "SecureArray")}, o: {outputLength} of {ofLength})";

    private static bool Verify(int dataLength, int keyLength, bool hasSalt, int outputLength, bool usedMemory, ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual, ITestOutputHelper output)
    {
        if (expected.Length < actual.Length)
        {
            output.WriteLine($"Expected length <= {expected.Length}, got {actual.Length} {Detail(dataLength, keyLength, hasSalt, usedMemory, actual.Length, outputLength)}");
            return false;
        }

        for (int i = 0; i < actual.Length; ++i)
        {
            if (expected[i] != actual[i])
            {
                ////output.WriteLine($"Failed {Detail(dataLength, keyLength, hasSalt, actual.Length, outputLength)}\n  Expected {BitConverter.ToString(expected.ToArray())}\n  Actual   {BitConverter.ToString(actual.ToArray())}");
                output.WriteLine($"Failed {Detail(dataLength, keyLength, hasSalt, usedMemory, actual.Length, outputLength)}");
                return false;
            }
        }

        return true;
    }

    private static Memory<byte>? FilledBuf(int length)
    {
        if (length >= 0)
        {
            var ret = new byte[length];
            for (int i = 0; i < length; i++)
            {
                ret[i] = (byte)i;
            }

            return ret;
        }

        return null;
    }

    private static Blake2BConfig Config(int keyLength, bool hasSalt, int outputSizeInBytes, bool hasOutput)
    {
        return new Blake2BConfig()
        {
            Key = FilledBuf(keyLength),
            Salt = FilledBuf(hasSalt ? 16 : -1),
            OutputSizeInBytes = outputSizeInBytes,
            Result64ByteBuffer = hasOutput ? new Memory<byte>(new byte[64]) : (Memory<byte>?)null,
        };
    }
}
