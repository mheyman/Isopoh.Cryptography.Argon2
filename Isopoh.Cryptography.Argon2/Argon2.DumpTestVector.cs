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
    /// Argon2 Hashing of passwords
    /// </summary>
    public sealed partial class Argon2
    {
        /////private static readonly string VectorFileName = "argon2-test-vectors.txt";
        private static readonly string VectorFileName = null;

        private static void InitialKat(byte[] buffer, Argon2 hasher)
        {
            if (VectorFileName != null)
            {
                using (var fout = new FileStream(VectorFileName, FileMode.Append))
                using (var sout = new StreamWriter(fout))
                {
                    sout.WriteLine("=======================================");
                    switch (hasher.Type)
                    {
                        case Argon2Type.DataDependentAddressing:
                            sout.WriteLine($"Argon2d version number {(int)hasher.Version}");
                            break;
                        case Argon2Type.DataIndependentAddressing:
                            sout.WriteLine($"Argon2i version number {(int)hasher.Version}");
                            break;
                    }

                    sout.WriteLine("=======================================");
                    sout.WriteLine(
                        $"Memory: {hasher.MemoryCost} KiB, Iterations: {hasher.TimeCost}, "
                        + $"Parallelism: {hasher.Lanes} lanes, Tag length: " + $"{hasher.HashLength} bytes");
                    var pwText = hasher.ClearPassword
                                     ? "CLEARED"
                                     : BitConverter.ToString(hasher.Password).ToLower().Replace('-', ' ');
                    sout.WriteLine($"Password[{hasher.Password.Length}]: {pwText} ");
                    sout.WriteLine(
                        $"Salt[{hasher.Salt?.Length ?? 0}]: "
                        + $"{(hasher.Salt == null ? string.Empty : BitConverter.ToString(hasher.Salt).ToLower().Replace('-', ' '))} ");
                    sout.WriteLine(
                        $"Secret[{hasher.Secret?.Length ?? 0}]: "
                        + $"{(hasher.Secret == null ? string.Empty : BitConverter.ToString(hasher.Secret).ToLower().Replace('-', ' '))} ");
                    sout.WriteLine(
                        $"Associated data[{hasher.AssociatedData?.Length ?? 0}]: "
                        + $"{(hasher.AssociatedData == null ? string.Empty : BitConverter.ToString(hasher.AssociatedData).ToLower().Replace('-', ' '))} ");
                    sout.WriteLine(
                        $"Pre-hashing digest: {BitConverter.ToString(buffer, 0, PrehashDigestLength).ToLower().Replace('-', ' ')} ");
                    sout.Flush();
                }
            }
        }

        private static void InternalKat(Argon2 hasher, int passNumber)
        {
            if (VectorFileName != null)
            {
                using (var fout = new FileStream(VectorFileName, FileMode.Append))
                using (var sout = new StreamWriter(fout))
                {
                    sout.WriteLine();
                    sout.WriteLine($" After pass {passNumber}:");
                    for (int i = 0; i < hasher.MemoryBlockCount; ++i)
                    {
                        int howManyWords = (hasher.MemoryBlockCount > QwordsInBlock) ? 1 : QwordsInBlock;

                        for (int j = 0; j < howManyWords; ++j)
                        {
                            sout.WriteLine($"Block {i:D4} [{j, 3}]: {hasher.Memory[i][j] :x16}");
                        }
                    }

                    sout.Flush();
                }
            }
        }

        private static void PrintTag(byte[] output)
        {
            if (VectorFileName != null)
            {
                using (var fout = new FileStream(VectorFileName, FileMode.Append))
                using (var sout = new StreamWriter(fout))
                {
                    sout.WriteLine($"Tag: {BitConverter.ToString(output).ToLower().Replace('-', ' ')} ");
                    sout.Flush();
                }
            }
        }
    }
}