// <copyright file="Argon2TestVectorTypeBasicCheck.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace TestLib;

using System;
using System.Text;
using Isopoh.Cryptography.Argon2;
using Isopoh.Cryptography.SecureArray;
using Xunit.Abstractions;

// ReSharper disable once GrammarMistakeInComment
/// <summary>
/// Has a method that does a basic check against an <see cref="Argon2TestVectorType"/> instance.
/// </summary>
public class Argon2TestVectorTypeBasicCheck
{
    /// <summary>
    /// Hashes the test values and compares against the test vector. Reports to standard output.
    /// </summary>
    /// <param name="checkNumber">A number used in the report.</param>
    /// <param name="argon2TestVector">The test values.</param>
    /// <param name="output">Used to write output.</param>
    /// <returns>True on success; false otherwise.</returns>
    public static bool Test(int checkNumber, Argon2TestVectorType.TestVector argon2TestVector, ITestOutputHelper output)
    {
        string nl = Environment.NewLine;
        try
        {
            var config = new Argon2Config
            {
                TimeCost = argon2TestVector.IterationCount,
                MemoryCost = argon2TestVector.MemoryKByteCount,
                Threads = argon2TestVector.Parallelism,
                Lanes = argon2TestVector.Parallelism,
                Password = Encoding.ASCII.GetBytes(argon2TestVector.Password),
                Salt = Encoding.ASCII.GetBytes(argon2TestVector.Salt),
                Secret = argon2TestVector.Secret == null ? null : Encoding.ASCII.GetBytes(argon2TestVector.Secret),
                AssociatedData = argon2TestVector.AssociatedData == null ? null : Encoding.ASCII.GetBytes(argon2TestVector.AssociatedData),
                HashLength = argon2TestVector.TagLength,
                Version = Argon2Version.Nineteen,
                Type = argon2TestVector.Type,
                SecureArrayCall = SecureArray.DefaultCall,
            };

            string text = Argon2.Hash(config);
            if (string.CompareOrdinal(text, argon2TestVector.EncodedTag) == 0)
            {
                output.WriteLine(
                    $"Test {checkNumber} passed:{nl}"
                    + $"             Version 0x{(int)argon2TestVector.Version:X} ({(int)argon2TestVector.Version}){nl}"
                    + $"                Type {argon2TestVector.Type}{nl}"
                    + $"          Iterations {argon2TestVector.IterationCount}{nl}"
                    + $"       Memory KBytes {argon2TestVector.MemoryKByteCount}{nl}"
                    + $"         Parallelism {argon2TestVector.Parallelism}{nl}"
                    + $"            Password {argon2TestVector.Password}{nl}"
                    + $"                Salt {argon2TestVector.Salt}{nl}"
                    + $"              Secret {argon2TestVector.Secret}{nl}"
                    + $"      AssociatedData {argon2TestVector.AssociatedData}{nl}"
                    + $"             encoded {text}");
            }
            else
            {
                Console.WriteLine(
                    $"Test {checkNumber}: Got{nl}" +
                    $"  {text}{nl}" +
                    $"expected{nl}" +
                    $"  {argon2TestVector.EncodedTag}");
                return false;
            }
        }

        // ReSharper disable once CatchAllClause
        catch (Exception e)
        {
            output.WriteLine($"Test x: {e.Message} ({e.GetType()})");
        }

        return true;
    }
}
