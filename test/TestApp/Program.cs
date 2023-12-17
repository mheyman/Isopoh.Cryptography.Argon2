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
            ////LeakInVerify.Test(output).Item2,
            ////SecureArraySizing.Test(output).Item2,
            ////RoundTrip.Test(output).Item2,
            ////RoundTripSimpleCall.Test(output).Item2,
            ////ThreadsDontMatter.Test(output).Item2,
            PublishedVector.Test(output).Item2,
            ////VersusReferenceCode.Test(output).Item2,
            ////FromDraft3.Test(output).Item2,
            ////HighMemoryCost.Test(output).Item2,
            ////TimeToHash.Test(output).Item2,
            Blake2bTestVector.Test(output).Item2,
            ////Blake2BTestVariations.Test(output).Item2,
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