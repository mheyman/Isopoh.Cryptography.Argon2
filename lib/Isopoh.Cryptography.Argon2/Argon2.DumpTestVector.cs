// <copyright file="Argon2.DumpTestVector.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2;

using System;
using System.IO;

/// <summary>
/// Argon2 Hashing of passwords.
/// </summary>
public sealed partial class Argon2
{
    // ReSharper disable once HeuristicUnreachableCode
#pragma warning disable CS0162
    private static readonly string VectorFileName = true ? string.Empty : "argon2-test-vectors.txt";
#pragma warning restore CS0162

    private static void InitialKat(ReadOnlySpan<byte> buffer, Argon2 hasher)
    {
        // ReSharper disable once InvertIf
        if (VectorFileName.Length != 0)
        {
            using var fileOut = new FileStream(VectorFileName, FileMode.Append);
            using var streamOut = new StreamWriter(fileOut);
            streamOut.WriteLine("=======================================");
            switch (hasher.Config.Type)
            {
                case Argon2Type.DataDependentAddressing:
                    streamOut.WriteLine($"Argon2d version number {(int)hasher.Config.Version}");
                    break;
                case Argon2Type.DataIndependentAddressing:
                    streamOut.WriteLine($"Argon2i version number {(int)hasher.Config.Version}");
                    break;
                case Argon2Type.HybridAddressing:
                    streamOut.WriteLine($"Argon2id version number {(int)hasher.Config.Version}");
                    break;
                default:
                    streamOut.WriteLine($"Argon2id(as default from unknown type {(int)hasher.Config.Type}) version number {(int)hasher.Config.Version}");
                    break;
            }

            streamOut.WriteLine("=======================================");
            streamOut.WriteLine(
                $"Memory: {hasher.Config.MemoryCost} KiB, Iterations: {hasher.Config.TimeCost}, "
                + $"Parallelism: {hasher.Config.Lanes} lanes, Tag length: " + $"{hasher.Config.HashLength} bytes");
            string pwText = hasher.Config.ClearPassword
                ? "CLEARED"
                : BitConverter.ToString(hasher.Config.Password ?? Array.Empty<byte>()).ToLowerInvariant().Replace('-', ' ');
            streamOut.WriteLine($"Password[{hasher.Config.Password?.Length ?? -1}]: {pwText} ");
            streamOut.WriteLine(
                $"Salt[{hasher.Config.Salt?.Length ?? 0}]: "
                + $"{(hasher.Config.Salt == null ? string.Empty : BitConverter.ToString(hasher.Config.Salt).ToLowerInvariant().Replace('-', ' '))} ");
            streamOut.WriteLine(
                $"Secret[{hasher.Config.Secret?.Length ?? 0}]: "
                + $"{(hasher.Config.Secret == null ? string.Empty : BitConverter.ToString(hasher.Config.Secret).ToLowerInvariant().Replace('-', ' '))} ");
            streamOut.WriteLine(
                $"Associated data[{hasher.Config.AssociatedData?.Length ?? 0}]: "
                + $"{(hasher.Config.AssociatedData == null ? string.Empty : BitConverter.ToString(hasher.Config.AssociatedData).ToLowerInvariant().Replace('-', ' '))} ");
            streamOut.WriteLine(
                $"Pre-hashing digest: {BitConverter.ToString(buffer.ToArray(), 0, PrehashDigestLength).ToLowerInvariant().Replace('-', ' ')} ");
        }
    }

    private static void InternalKat(Argon2 hasher, int passNumber)
    {
        if (VectorFileName.Length == 0)
        {
            return;
        }

        using var fileOut = new FileStream(VectorFileName, FileMode.Append);
        using var streamOut = new StreamWriter(fileOut);
        streamOut.WriteLine();
        streamOut.WriteLine($" After pass {passNumber}:");
        for (var i = 0; i < hasher.MemoryBlockCount; ++i)
        {
            int howManyWords = hasher.MemoryBlockCount > QwordsInBlock ? 1 : QwordsInBlock;

            for (var j = 0; j < howManyWords; ++j)
            {
                streamOut.WriteLine($"Block {i:D4} [{j,3}]: {hasher.Memory[i][j]:x16}");
            }
        }
    }

    private static void PrintTag(ReadOnlySpan<byte> output)
    {
        // ReSharper disable once InvertIf
        if (VectorFileName.Length != 0)
        {
            using var fileOut = new FileStream(VectorFileName, FileMode.Append);
            using var streamOut = new StreamWriter(fileOut);
            streamOut.WriteLine($"Tag: {BitConverter.ToString(output.ToArray()).ToLowerInvariant().Replace('-', ' ')} ");
        }
    }
}