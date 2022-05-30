// <copyright file="Argon2.DumpTestVector.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2
{
    using System;
    using System.IO;

    /// <summary>
    /// Argon2 Hashing of passwords.
    /// </summary>
    public sealed partial class Argon2
    {
        // ReSharper disable once HeuristicUnreachableCode
        private static readonly string? VectorFileName = true ? null : "argon2-test-vectors.txt";

        private static void InitialKat(byte[] buffer, Argon2 hasher)
        {
            if (VectorFileName != null)
            {
                using var fileOut = new FileStream(VectorFileName, FileMode.Append);
                using var streamOut = new StreamWriter(fileOut);
                streamOut.WriteLine("=======================================");
                switch (hasher.config.Type)
                {
                    case Argon2Type.DataDependentAddressing:
                        streamOut.WriteLine($"Argon2d version number {(int)hasher.config.Version}");
                        break;
                    case Argon2Type.DataIndependentAddressing:
                        streamOut.WriteLine($"Argon2i version number {(int)hasher.config.Version}");
                        break;
                    case Argon2Type.HybridAddressing:
                        streamOut.WriteLine($"Argon2id version number {(int)hasher.config.Version}");
                        break;
                }

                streamOut.WriteLine("=======================================");
                streamOut.WriteLine(
                    $"Memory: {hasher.config.MemoryCost} KiB, Iterations: {hasher.config.TimeCost}, "
                    + $"Parallelism: {hasher.config.Lanes} lanes, Tag length: " + $"{hasher.config.HashLength} bytes");
                var pwText = hasher.config.ClearPassword
                    ? "CLEARED"
                    : BitConverter.ToString(hasher.config.Password ?? Array.Empty<byte>()).ToLowerInvariant().Replace('-', ' ');
                streamOut.WriteLine($"Password[{hasher.config.Password?.Length ?? -1}]: {pwText} ");
                streamOut.WriteLine(
                    $"Salt[{hasher.config.Salt?.Length ?? 0}]: "
                    + $"{(hasher.config.Salt == null ? string.Empty : BitConverter.ToString(hasher.config.Salt).ToLowerInvariant().Replace('-', ' '))} ");
                streamOut.WriteLine(
                    $"Secret[{hasher.config.Secret?.Length ?? 0}]: "
                    + $"{(hasher.config.Secret == null ? string.Empty : BitConverter.ToString(hasher.config.Secret).ToLowerInvariant().Replace('-', ' '))} ");
                streamOut.WriteLine(
                    $"Associated data[{hasher.config.AssociatedData?.Length ?? 0}]: "
                    + $"{(hasher.config.AssociatedData == null ? string.Empty : BitConverter.ToString(hasher.config.AssociatedData).ToLowerInvariant().Replace('-', ' '))} ");
                streamOut.WriteLine(
                    $"Pre-hashing digest: {BitConverter.ToString(buffer, 0, PrehashDigestLength).ToLowerInvariant().Replace('-', ' ')} ");
            }
        }

        private static void InternalKat(Argon2 hasher, int passNumber)
        {
            if (VectorFileName != null)
            {
                using var fileOut = new FileStream(VectorFileName, FileMode.Append);
                using var streamOut = new StreamWriter(fileOut);
                streamOut.WriteLine();
                streamOut.WriteLine($" After pass {passNumber}:");
                for (int i = 0; i < hasher.MemoryBlockCount; ++i)
                {
                    int howManyWords = (hasher.MemoryBlockCount > QwordsInBlock) ? 1 : QwordsInBlock;

                    for (int j = 0; j < howManyWords; ++j)
                    {
                        streamOut.WriteLine($"Block {i:D4} [{j,3}]: {hasher.Memory[i][j]:x16}");
                    }
                }
            }
        }

        private static void PrintTag(byte[] output)
        {
            if (VectorFileName != null)
            {
                using var fileOut = new FileStream(VectorFileName, FileMode.Append);
                using var streamOut = new StreamWriter(fileOut);
                streamOut.WriteLine($"Tag: {BitConverter.ToString(output).ToLowerInvariant().Replace('-', ' ')} ");
            }
        }
    }
}