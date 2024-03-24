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
        var resultTexts = new List<string>
        {
            LeakInVerify.Test(output).Message,
            SecureArraySizing.Test(output).Message,
            RoundTrip.Test(output).Message,
            RoundTripSimpleCall.Test(output).Message,
            ThreadsDontMatter.Test(output).Message,
            PublishedVector.Test(output).Message,
            VersusReferenceCode.Test(output).Message,
            FromDraft3.Test(output).Message,
            HighMemoryCost.Test(output).Message,
            TimeToHash.Test(output).Message,
            Blake2bTestVector.Test(output).Message,
            Blake2BTestVariations.Test(output).Message,
        };
        Console.WriteLine($"Tests complete:{Environment.NewLine}  {string.Join($"{Environment.NewLine}  ", resultTexts)}");
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