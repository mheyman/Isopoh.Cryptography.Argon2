// <copyright file="Argon2TestVectorSourceGenerator.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

#pragma warning disable SA1402
namespace Argon2TestVectorSourceGenerator;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

#pragma warning disable SA1602
/// <summary>
/// Minimal local types used only by the source generator at compile-time.
/// These mirror the consumer types (names / member names) but live inside the
/// generator assembly so the generator does not depend on the consumer assembly.
/// The generator emits source that references the real consumer types.
/// </summary>
internal enum Argon2TypeLocal
{
    DataDependentAddressing = 0,
    DataIndependentAddressing = 1,
    HybridAddressing = 2,
}

#pragma warning disable SA1600
internal enum Argon2VersionLocal
{
    Sixteen = 0x10,
    Nineteen = 0x13,
}

internal enum Argon2OutputLocal
{
    Raw,
    Encoded,
    Full,
}
#pragma warning restore SA1600
#pragma warning restore SA1602

/// <summary>
/// Generate source code.
/// </summary>
[Generator]
public class Argon2TestVectorSourceGenerator : IIncrementalGenerator
{
    private static readonly DiagnosticDescriptor LogMessage = new(
#pragma warning disable RS2008
        id: "A2TVSG001",
#pragma warning restore RS2008
        title: "Generator Log",
        messageFormat: "{0}",
        category: "Argon2TestVectorSourceGenerator",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true);

    /// <summary>
    /// Called to initialize the generator and register generation steps via callbacks
    /// on the <paramref name="context"/>.
    /// </summary>
    /// <param name="context">The <see cref="IncrementalGeneratorInitializationContext"/> to register callbacks on.</param>
    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        /////if (!Debugger.IsAttached)
        /////{
        /////    Debugger.Launch();
        /////}

        IncrementalValueProvider<Compilation> compilationProvider = context.CompilationProvider;

        // Refactor: collect generator log messages during the Select steps and report them once
        // from a single RegisterSourceOutput. This avoids registering a new source output per message.
        IncrementalValueProvider<string> solutionDir = compilationProvider.Select((_, _) => GetSolutionDir());
        IncrementalValueProvider<string> argon2 = compilationProvider.Combine(solutionDir)
            .Select(
                (x, _) => Directory.GetFiles(x.Right, "argon2.exe", SearchOption.AllDirectories)
                        .FirstOrDefault() ??
                    throw new Exception($"argon2.exe not found in {x.Right}"));

        // validatedArgon2 now produces the found path plus a mutable List<string> that collects logs
        IncrementalValueProvider<(string Path, List<string> Logs)> validatedArgon2 =
            compilationProvider.Combine(argon2).Select((x, _) =>
            {
                var logs = new List<string>();

                // pass a local reporter that appends to the logs list
                Validate(msg => logs.Add(msg), x.Right);
                return (x.Right, logs);
            });

        // Create vectors while appending any runtime messages to the logs list created above.
        IncrementalValueProvider<(IEnumerable<string> Vectors, List<string> Logs)> textNewTestVectorList =
            compilationProvider.Combine(validatedArgon2)
                .Select((x, _) =>
                {
                    var argon2Path = x.Right.Path;
                    var logs = x.Right.Logs;
                    Action<string> report = s => logs.Add(s);

                    var vectors = Argon2Parameters().Select(parameters =>
                        TextNewTestVector(report, argon2Path, parameters));

                    return (Vectors: vectors, Logs: logs);
                });

        // Single output: add the generated source and report all collected diagnostics for this run.
        context.RegisterSourceOutput(textNewTestVectorList, (productionContext, value) =>
        {
            // Report collected logs as diagnostics
            foreach (var msg in value.Logs)
            {
                var diagnostic = Diagnostic.Create(LogMessage, location: null, msg);
                productionContext.ReportDiagnostic(diagnostic);
            }

            // Add generated source
            productionContext.AddSource("Test.g.cs", GenerateSource(value.Vectors));
        });
    }

    // Move the "official" vectors out of static initialization to avoid type/load-time exceptions
    // when the generator assembly is loaded by the compiler host.
    private static List<OfficialTestVectorLocal> GetOfficialTestVectors()
    {
        return new List<OfficialTestVectorLocal>
        {
            new(
                Argon2TypeLocal.DataDependentAddressing,
                Argon2VersionLocal.Nineteen,
                3,
                32,
                4,
                new string((char)1, 32),
                new string((char)2, 16),
                new string((char)3, 8),
                new string((char)4, 12),
                "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"),

            new(
                Argon2TypeLocal.DataIndependentAddressing,
                Argon2VersionLocal.Nineteen,
                3,
                32,
                4,
                new string((char)1, 32),
                new string((char)2, 16),
                new string((char)3, 8),
                new string((char)4, 12),
                "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"),

            new(
                Argon2TypeLocal.HybridAddressing,
                Argon2VersionLocal.Nineteen,
                3,
                32,
                4,
                new string((char)1, 32),
                new string((char)2, 16),
                new string((char)3, 8),
                new string((char)4, 12),
                "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"),
        };
    }

    private static SourceText GenerateSource(IEnumerable<string> textNewTestVectors)
    {
        var source = $$"""
                       // <auto-generated/>
                       // <copyright file="Test.g.cs" company="Isopoh">
                       // To the extent possible under law, the author(s) have dedicated all copyright
                       // and related and neighboring rights to this software to the public domain
                       // worldwide. This software is distributed without any warranty.
                       // </copyright>

                       namespace Argon2TestVector
                       {
                           using System.Collections.Generic;
                           using Argon2TestVectorType;
                           using Isopoh.Cryptography.Argon2;
                       
                           /// <content/>
                           public partial class Test
                           {
                               /// <summary>
                               /// Argon2 vectors generated at compile time from C-language reference argon2 command line example code.
                               /// </summary>
                               private List<TestVector> generatedVectors = new List<TestVector>
                               {
                                   {{string.Join(",\r\n            ", textNewTestVectors)}},
                               };
                           }
                       }
                       """;
        ////if (!Debugger.IsAttached)
        ////{
        ////    Debugger.Launch();
        ////}

        return SourceText.From(source, Encoding.ASCII);
    }

    private static IEnumerable<(
        Argon2TypeLocal Type,
        string Password,
        string Salt,
        int IterationCount,
        string? Secret,
        string? AssociatedData,
        int MemoryKByteFactor,
        int Parallelism,
        int TagLength)> Argon2Parameters()
    {
        const string salt = "test salt";
        var types = new List<Argon2TypeLocal>
        {
            Argon2TypeLocal.DataIndependentAddressing, Argon2TypeLocal.DataDependentAddressing, Argon2TypeLocal.HybridAddressing,
        };
        const string password = "test password";
        var iterationCounts = new List<int> { 3, 17 };
        var secrets = new List<string?> { null, "test secret" };
        var associatedDatas = new List<string?> { null, "test associated data" };
        var memoryKByteFactors = new List<int> { 1, 2 };
        var parallelisms = new List<int> { 1, 4 };
        var tagLengths = new List<int> { 63, 64, 65, 511, 512, 513 };
        List<(Argon2TypeLocal Type, string Password, string Salt, int IterationCount, string? Secret, string? AssociatedData, int
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
                    a.type,
                    a.iterationCount,
                    a.secret,
                    a.associatedData,
                    memoryKByteFactor,
                })
            .SelectMany(
                _ => parallelisms,
                (a, parallelism) => new
                {
                    a.type,
                    a.iterationCount,
                    a.secret,
                    a.associatedData,
                    a.memoryKByteFactor,
                    parallelism,
                })
            .SelectMany(
                _ => tagLengths,
                (a, tagLength) =>
                    (a.type, password, salt, a.iterationCount, a.secret, a.associatedData, a.memoryKByteFactor,
                        a.parallelism, tagLength))
            .ToList();

        // put on the "official" test vectors. These are already known to work because of their use in the Validate() call.
        runArgs.AddRange(
            GetOfficialTestVectors().Select(
                a => (a.Type, a.Password, a.Salt, a.IterationCount, (string?)a.Secret, (string?)a.AssociatedData,
                    a.MemoryKByteCount / 8 / a.Parallelism, a.Parallelism, a.Tag.Length / 2)));
        return runArgs;
    }

    private static string TextNewTestVector(
        Action<string> reportDiagnostic,
        string argon2,
        (Argon2TypeLocal Type, string Password, string Salt, int IterationCount, string? Secret, string? AssociatedData, int MemoryKByteFactor, int Parallelism, int TagLength) args)
    {
        // Note: args.Type.ToString() will produce the enum member name such as "DataIndependentAddressing".
        // The generated source intentionally writes `Argon2Type.{name}` so the consumer's Argon2TestVectorType
        // enums are referenced at compile-time there.
        return $"new TestVector(Argon2Type.{args.Type}, Argon2Version.Nineteen, {args.IterationCount}, {args.MemoryKByteFactor * 8 * args.Parallelism}, {args.Parallelism}, {Arg(args.Password)}, {Arg(args.Salt)}, {Arg(args.Secret)}, {Arg(args.AssociatedData)}, {args.TagLength}, {Arg(RunArgon2(reportDiagnostic, argon2, args.Salt, args.Type, args.Password, args.IterationCount, args.Secret, args.AssociatedData, args.MemoryKByteFactor * 8 * args.Parallelism, args.Parallelism, args.TagLength, Argon2OutputLocal.Encoded))})";

        static string Arg(string? a)
        {
            return a == null ? "null" : $"\"{a}\"";
        }
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

    private static void Validate(
        Action<string> reportDiagnostic,
        string argon2)
    {
        foreach (OfficialTestVectorLocal? tv in GetOfficialTestVectors())
        {
            string res = RunArgon2(
                reportDiagnostic,
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
                Argon2OutputLocal.Raw);
            if (string.CompareOrdinal(res, tv.Tag) != 0)
            {
                throw new Exception(
                    $"Expected \"{tv.Tag}\", got \"{res}\" when validating official {tv.Type} argon2 test vector");
            }
        }
    }

    private static string RunArgon2(
        Action<string> reportDiagnostic,
        string argon2,
        string salt,
        Argon2TypeLocal type,
        string password,
        int iterations,
        string? secret,
        string? associatedData,
        int memoryKBytes,
        int parallelism,
        int tagLength,
        Argon2OutputLocal output)
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
                type switch { Argon2TypeLocal.DataIndependentAddressing => "-i", Argon2TypeLocal.DataDependentAddressing => "-d", _ => "-id" },
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
                output switch { Argon2OutputLocal.Raw => "-r", Argon2OutputLocal.Encoded => "-e", _ => null }),
        };
        using Process p = Process.Start(startInfo) ?? throw new Exception($"Failed to start {startInfo.FileName}");
        string res = p.StandardOutput.ReadToEnd().TrimEnd('\r', '\n');
        //// var resError = p.StandardError.ReadToEnd().TrimEnd(new char[] { '\r', '\n' });
        p.WaitForExit();
        reportDiagnostic($"Ran: {startInfo.FileName} {startInfo.Arguments}, got: {res}");
        return res;
    }

    /// <summary>
    /// From https://stackoverflow.com/a/10489920.
    /// </summary>
    /// <param name="args">Command line arguments.</param>
    /// <returns>Single string of escaped command line arguments.</returns>
    private static string BuildCommandLineFromArgs(params string?[] args)
    {
        var result = string.Empty;

        if (Environment.OSVersion.Platform == PlatformID.Unix
            ||
            Environment.OSVersion.Platform == PlatformID.MacOSX)
        {
            result = args.Where(s => s != null)
                .Cast<string>()
                .Aggregate(
                    result,
                    (current, arg) => current + ((current.Length > 0 ? " " : string.Empty) + arg.Replace(" ", @"\ ")
                        .Replace("\t", "\\\t")
                        .Replace(@"\", @"\\")
                        .Replace(@"""", @"\""")
                        .Replace("<", @"\<")
                        .Replace(">", @"\>")
                        .Replace("|", @"\|")
                        .Replace("@", @"\@")
                        .Replace("&", @"\&")));
        }
        else
        {
            // Windows family
            foreach (string arg in args.Where(s => s != null).Cast<string>())
            {
                bool enclosedInApo = arg.LastIndexOfAny(
                    [' ', '\t', '|', '@', '^', '<', '>', '&']) >= 0;
                bool wasApo = enclosedInApo;
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

#pragma warning disable SA1516
#pragma warning disable SA1600
#pragma warning disable SA1649
internal sealed class OfficialTestVectorLocal(
    Argon2TypeLocal type,
    Argon2VersionLocal version,
    int iterationCount,
    int memoryKByteCount,
    int parallelism,
    string password,
    string salt,
    string secret,
    string associatedData,
    string tag)
{
    public Argon2TypeLocal Type { get; set; } = type;
    public Argon2VersionLocal Version { get; set; } = version;
    public int IterationCount { get; set; } = iterationCount;
    public int MemoryKByteCount { get; set; } = memoryKByteCount;
    public int Parallelism { get; set; } = parallelism;
    public string Password { get; set; } = password;
    public string Salt { get; set; } = salt;
    public string Secret { get; set; } = secret;
    public string AssociatedData { get; set; } = associatedData;
    public string Tag { get; set; } = tag;
}
#pragma warning restore SA1649
#pragma warning restore SA1600
#pragma warning restore SA1516
