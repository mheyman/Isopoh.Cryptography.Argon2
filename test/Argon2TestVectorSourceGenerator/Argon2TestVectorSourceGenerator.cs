﻿// <copyright file="Argon2TestVectorSourceGenerator.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Argon2TestVectorSourceGenerator
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Runtime.CompilerServices;
    using System.Text;
    using Argon2TestVectorType;
    using Isopoh.Cryptography.Argon2;
    using Microsoft.CodeAnalysis;
    using Microsoft.CodeAnalysis.Text;

    /// <summary>
    /// Generate source code.
    /// </summary>
    [Generator(LanguageNames.CSharp)]
    public class Argon2TestVectorSourceGenerator : IIncrementalGenerator
    {
        private static readonly List<OfficialTestVector> OfficialTestVectors = new()
        {
            new(
                Argon2Type.DataDependentAddressing,
                Argon2Version.Nineteen,
                3,
                32,
                4,
                new string((char)1, 32),
                new string((char)2, 16),
                new string((char)3, 8),
                new string((char)4, 12),
                "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"),
            new(
                Argon2Type.DataIndependentAddressing,
                Argon2Version.Nineteen,
                3,
                32,
                4,
                new string((char)1, 32),
                new string((char)2, 16),
                new string((char)3, 8),
                new string((char)4, 12),
                "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"),
            new(
                Argon2Type.HybridAddressing,
                Argon2Version.Nineteen,
                3,
                32,
                4,
                new string((char)1, 32),
                new string((char)2, 16),
                new string((char)3, 8),
                new string((char)4, 12),
                "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"),
        };

        /// <summary>
        /// Called to initialize the generator and register generation steps via callbacks
        /// on the <paramref name="context"/>.
        /// </summary>
        /// <param name="context">The <see cref="IncrementalGeneratorInitializationContext"/> to register callbacks on.</param>
        public void Initialize(IncrementalGeneratorInitializationContext context)
        {
            ////if (!Debugger.IsAttached)
            ////{
            ////    Debugger.Launch();
            ////}

            var compilationProvider = context.CompilationProvider;
            var solutionDir = compilationProvider.Select((_, _) => GetSolutionDir());
            var argon2 = compilationProvider.Combine(solutionDir)
                .Select(
                    (x, _) => Directory.GetFiles(x.Right, "argon2.exe", SearchOption.AllDirectories)
                            .FirstOrDefault() ??
                        throw new Exception($"argon2.exe not found in {x.Right}"));
            var validatedArgon2 = compilationProvider.Combine(argon2).Select((x, _) =>
            {
                Validate(x.Right);
                return x.Right;
            });

            var textNewTestVectorList = compilationProvider.Combine(validatedArgon2)
                .Select((x, _) => Argon2Parameters().Select(parameters => TextNewTestVector(x.Right, parameters)));

            try
            {
                context.RegisterSourceOutput(textNewTestVectorList, static (c, textNewVectors) => c.AddSource("Test.g.cs", GenerateSource(textNewVectors)));
            }
            catch (Exception e)
            {
                var msg = e.Message;
                Console.WriteLine(msg);
                throw;
            }
        }

        private static SourceText GenerateSource(IEnumerable<string> textNewTestVectors)
        {
            string source = $@"// <auto-generated/>
// <copyright file=""Test.g.cs"" company=""Isopoh"">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Argon2TestVector
{{
    using System.Collections.Generic;
    using Argon2TestVectorType;
    using Isopoh.Cryptography.Argon2;

    /// <content/>
    public partial class Test
    {{
        /// <summary>
        /// Argon2 vectors generated at compile time from C-language reference argon2 command line example code.
        /// </summary>
        private List<TestVector> generatedVectors = new List<TestVector>
        {{
            {string.Join(",\r\n            ", textNewTestVectors)},
        }};
    }}
}}";
            ////if (!Debugger.IsAttached)
            ////{
            ////    Debugger.Launch();
            ////}

            return SourceText.From(source, Encoding.ASCII);
        }

        private static List<(Argon2Type Type, string Password, string Salt, int IterationCount, string? Secret, string? AssociatedData, int MemoryKByteFactor, int Parallelism, int TagLength)> Argon2Parameters()
        {
            const string salt = "test salt";
            var types = new List<Argon2Type>
            {
                Argon2Type.DataIndependentAddressing, Argon2Type.DataDependentAddressing, Argon2Type.HybridAddressing,
            };
            const string password = "test password";
            var iterationCounts = new List<int>() { 3, 17 };
            var secrets = new List<string?> { null, "test secret" };
            var associatedDatas = new List<string?> { null, "test associated data" };
            var memoryKByteFactors = new List<int> { 1, 2 };
            var parallelisms = new List<int> { 1, 4 };
            var tagLengths = new List<int> { 63, 64, 65, 511, 512, 513 };
            List<(Argon2Type Type, string Password, string Salt, int IterationCount, string? Secret, string? AssociatedData, int
                MemoryKByteFactor, int Parallelism, int TagLength)> runArgs = types
                .SelectMany(_ => iterationCounts, (type, iterationCount) => new { type, iterationCount })
                .SelectMany(_ => secrets, (a, secret) => new { a.type, a.iterationCount, secret })
                .SelectMany(
                    _ => associatedDatas,
                    (a, associatedData) => new { a.type, a.iterationCount, a.secret, associatedData })
                .SelectMany(
                    _ => memoryKByteFactors,
                    (a, memoryKByteFactor) => new
                    {
                        a.type, a.iterationCount, a.secret, a.associatedData, memoryKByteFactor,
                    })
                .SelectMany(
                    _ => parallelisms,
                    (a, parallelism) => new
                    {
                        a.type, a.iterationCount, a.secret, a.associatedData, a.memoryKByteFactor, parallelism,
                    })
                .SelectMany(
                    _ => tagLengths,
                    (a, tagLength) =>
                        (a.type, password, salt, a.iterationCount, a.secret, a.associatedData, a.memoryKByteFactor,
                            a.parallelism, tagLength))
                .ToList();

            // put on the "official" test vectors. These are already known to work because of their use in the Validate() call.
            runArgs.AddRange(
                OfficialTestVectors.Select(
                    a => (a.Type, a.Password, a.Salt, a.IterationCount, (string?)a.Secret, (string?)a.AssociatedData,
                        a.MemoryKByteCount / 8 / a.Parallelism, a.Parallelism, a.Tag.Length / 2)));
            return runArgs;
        }

        private static string TextNewTestVector(string argon2, (Argon2Type Type, string Password, string Salt, int IterationCount, string? Secret, string? AssociatedData, int MemoryKByteFactor, int Parallelism, int TagLength) args)
        {
            static string Arg(string? a)
            {
                return a == null ? "null" : $"\"{a}\"";
            }

            return $"new TestVector(Argon2Type.{args.Type}, Argon2Version.Nineteen, {args.IterationCount}, {args.MemoryKByteFactor * 8 * args.Parallelism}, {args.Parallelism}, {Arg(args.Password)}, {Arg(args.Salt)}, {Arg(args.Secret)}, {Arg(args.AssociatedData)}, {args.TagLength}, {Arg(RunArgon2(argon2, args.Salt, args.Type, args.Password, args.IterationCount, args.Secret, args.AssociatedData, args.MemoryKByteFactor * 8 * args.Parallelism, args.Parallelism, args.TagLength, Argon2Output.Encoded))})";
        }

        /// <summary>
        /// Use Roslyn to get the path to this file and go up one to get the solution directory.
        /// </summary>
        /// <param name="path">Roslyn sets to the path of the current file.</param>
        /// <returns>The path to the solution directory.</returns>
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
        private static string GetSolutionDir([CallerFilePath] string path = null)
#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.
        {
            return Path.GetDirectoryName(
                    Path.GetDirectoryName(
                        Path.GetDirectoryName(
                            path ?? throw new Exception("Got null path to this source file (from Roslyn)"))
                        ?? throw new Exception($"Directory of \"{path}\" (from Roslyn) was null"))
                    ?? throw new Exception($"Directory of \"{path}\" (from Roslyn) was null"))
                ?? throw new Exception($"Parent directory of \"{path}\" (from Roslyn) was null");
        }

        private static void Validate(string argon2)
        {
            foreach (var tv in OfficialTestVectors)
            {
                var res = RunArgon2(
                    argon2,
                    tv.Salt,
                    tv.Type,
                    tv.Password,
                    tv.IterationCount,
                    tv.Secret,
                    tv.AssociatedData,
                    tv.MemoryKByteCount,
                    tv.Parallelism,
                    tv.Tag.Length / 2,
                    Argon2Output.Raw);
                if (string.CompareOrdinal(res, tv.Tag) != 0)
                {
                    throw new Exception(
                        $"Expected \"{tv.Tag}\", got \"{res}\" when validating official {tv.Type} argon2 test vector");
                }
            }
        }

        private static string RunArgon2(
            string argon2,
            string salt,
            Argon2Type type,
            string password,
            int iterations,
            string? secret,
            string? associatedData,
            int memoryKBytes,
            int parallelism,
            int tagLength,
            Argon2Output output)
        {
            var startInfo = new ProcessStartInfo
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                FileName = argon2,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                //// RedirectStandardError = true,
                Arguments = BuildCommandLineFromArgs(
                    salt,
                    type == Argon2Type.DataIndependentAddressing ? "-i" : type == Argon2Type.DataDependentAddressing ? "-d" : "-id",
                    "-x",
                    password,
                    "-t",
                    $"{iterations}",
                    secret == null ? null : "-s",
                    secret,
                    associatedData == null ? null : "-a",
                    associatedData,
                    "-k",
                    $"{memoryKBytes}",
                    "-p",
                    $"{parallelism}",
                    "-l",
                    $"{tagLength}",
                    output == Argon2Output.Raw ? "-r" : output == Argon2Output.Encoded ? "-e" : null),
            };
            using var p = Process.Start(startInfo) ?? throw new Exception($"Failed to start {startInfo.FileName}");
            var res = p.StandardOutput.ReadToEnd().TrimEnd('\r', '\n');
            //// var resError = p.StandardError.ReadToEnd().TrimEnd(new char[] { '\r', '\n' });
            p.WaitForExit();
            return res;
        }

        /// <summary>
        /// From https://stackoverflow.com/a/10489920.
        /// </summary>
        /// <param name="args">Command line arguments.</param>
        /// <returns>Single string of escaped command line arguments.</returns>
        private static string BuildCommandLineFromArgs(params string?[] args)
        {
            string result = string.Empty;

            if (Environment.OSVersion.Platform == PlatformID.Unix
                ||
                Environment.OSVersion.Platform == PlatformID.MacOSX)
            {
                foreach (string arg in args.Where(s => s != null).Cast<string>())
                {
                    result += (result.Length > 0 ? " " : string.Empty)
                        + arg
                            .Replace(@" ", @"\ ")
                            .Replace("\t", "\\\t")
                            .Replace(@"\", @"\\")
                            .Replace(@"""", @"\""")
                            .Replace(@"<", @"\<")
                            .Replace(@">", @"\>")
                            .Replace(@"|", @"\|")
                            .Replace(@"@", @"\@")
                            .Replace(@"&", @"\&");
                }
            }
            else
            {
                // Windows family
                foreach (string arg in args.Where(s => s != null).Cast<string>())
                {
                    var enclosedInApo = arg.LastIndexOfAny(
                        new[] { ' ', '\t', '|', '@', '^', '<', '>', '&' }) >= 0;
                    var wasApo = enclosedInApo;
                    var subResult = string.Empty;
                    for (int i = arg.Length - 1; i >= 0; i--)
                    {
                        switch (arg[i])
                        {
                            case '"':
                                subResult = @"\""" + subResult;
                                wasApo = true;
                                break;
                            case '\\':
                                subResult = (wasApo ? @"\\" : @"\") + subResult;
                                break;
                            default:
                                subResult = arg[i] + subResult;
                                wasApo = false;
                                break;
                        }
                    }

                    result += (result.Length > 0 ? " " : string.Empty)
                        + (enclosedInApo ? "\"" + subResult + "\"" : subResult);
                }
            }

            return result;
        }
    }
}