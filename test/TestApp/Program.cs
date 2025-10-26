// <copyright file="Program.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>
// <summary>
// Tests because unit tests seem to be hard to get running.
// </summary>

namespace TestApp;

using System;
using System.Collections.Generic;
using System.Linq;
using TestLib;
using Xunit.Abstractions;

/// <summary>
/// The test program.
/// </summary>
public class Program
{
    /// <summary>
    /// Program entry.
    /// </summary>
    /// <param name="args">Command line arguments - unused.</param>
    public static void Main(string[] args)
    {
        var output = new Output();
        Console.WriteLine("Testing Isopoh.Cryptography.Argon2");
        var results = new List<(bool Passed, string Message)>
        {
            LeakInVerify.Test(output),
            LeakInHash.Test(output),
            MemoryNoAlloc.Test(output),
            SecureArraySizing.Test(output),
            RoundTrip.Test(output),
            RoundTripSimpleCall.Test(output),
            ThreadsDontMatter.Test(output),
            PublishedVector.Test(output),
            VersusReferenceCode.Test(output),
            FromDraft3.Test(output),
            HighMemoryCost.Test(output),
            TimeToHash.Test(output),
            Blake2bTestVector.Test(output),
            Blake2BTestVariations.Test(output),
        };

        Console.WriteLine($"Tests complete:{Environment.NewLine}  {string.Join($"{Environment.NewLine}  ", results.Select(r => r.Message))}");
        Console.WriteLine($"Passed {results.Count(r => r.Passed)} / {results.Count}");
    }

    private class Output : ITestOutputHelper
    {
        public void WriteLine(string message)
        {
            Console.WriteLine(message);
        }

        public void WriteLine(string format, params object[] args)
        {
            Console.Write(format, args);
        }
    }
}