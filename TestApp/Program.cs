// <copyright file="Program.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>
// <summary>
// Tests because unit tests seem to be hard to get running.
// </summary>

namespace TestApp
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;

    using Isopoh.Cryptography.Argon2;
    using Isopoh.Cryptography.SecureArray;

    /// <summary>
    /// The test program.
    /// </summary>
    public class Program
    {
        /// <summary>
        /// Test vectors for Argon2. From https://github.com/P-H-C/phc-winner-argon2/tree/master/kats.
        /// </summary>
        private static readonly Argon2TestVector[] Argon2TestVectors =
            {
                new Argon2TestVector(
                    "Data dependent",
                    Argon2Type.DataDependentAddressing,
                    Argon2Version.Nineteen,
                    3,
                    32,
                    4,
                    32,
                    "01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01",
                    "02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02",
                    "03 03 03 03 03 03 03 03",
                    "04 04 04 04 04 04 04 04 04 04 04 04",
                    "51 2b 39 1b 6f 11 62 97 53 71 d3 09 19 73 42 94 f8 68 e3 be 39 84 f3 c1 a1 3a 4d b9 fa be 4a cb"),
                new Argon2TestVector(
                    "Data independent",
                    Argon2Type.DataIndependentAddressing,
                    Argon2Version.Nineteen,
                    3,
                    32,
                    4,
                    32,
                    "01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01",
                    "02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02",
                    "03 03 03 03 03 03 03 03",
                    "04 04 04 04 04 04 04 04 04 04 04 04",
                    "c8 14 d9 d1 dc 7f 37 aa 13 f0 d7 7f 24 94 bd a1 c8 de 6b 01 6d d3 88 d2 99 52 a4 c4 67 2b 6c e8"),
                new Argon2TestVector(
                    "Hybrid",
                    Argon2Type.HybridAddressing,
                    Argon2Version.Nineteen,
                    3,
                    32,
                    4,
                    32,
                    "01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01",
                    "02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02",
                    "03 03 03 03 03 03 03 03",
                    "04 04 04 04 04 04 04 04 04 04 04 04",
                    "0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9 d0 1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59"),
            };

        private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

        /// <summary>
        /// Test <see cref="Argon2"/>.
        /// </summary>
        /// <returns>
        /// The result text.
        /// </returns>
        public static string TestArgon2RoundTrip()
        {
            var password = "password1";
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] salt = new byte[16];
            Rng.GetBytes(salt);
            var secret = "secret1";
            byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
            var failedResults = new List<string>();
            var passedResults = new List<string>();
            foreach (var argon2Type in new[] { Argon2Type.DataIndependentAddressing, Argon2Type.DataDependentAddressing, Argon2Type.HybridAddressing })
            {
                var argon2Name = argon2Type == Argon2Type.DataIndependentAddressing ? "Argon2i" :
                    argon2Type == Argon2Type.DataDependentAddressing ? "Argon2d" : "Argon2id";
                var config = new Argon2Config
                {
                    Type = argon2Type,
                    Version = Argon2Version.Nineteen,
                    Password = passwordBytes,
                    Salt = salt,
                    Secret = secretBytes,
                    TimeCost = 3,
                    MemoryCost = 65536,
                    Lanes = 4,
                    Threads = 2,
                };
                var argon2 = new Argon2(config);
                SecureArray<byte> hash = argon2.Hash();
                var passwordHash = config.EncodeString(hash.Buffer);
                Console.WriteLine($"{argon2Name} of {password} --> {passwordHash}");
                if (Argon2.Verify(passwordHash, passwordBytes, secretBytes, SecureArray.DefaultCall))
                {
                    passedResults.Add(argon2Name);
                    Console.WriteLine($"Round Trip {argon2Name} Passed");
                }
                else
                {
                    failedResults.Add(argon2Name);
                    Console.WriteLine($"Round Trip {argon2Name} FAILED");
                    Console.WriteLine($"    expected verify to work for {passwordHash} (Argon2 hash of {password})");
                }
            }

            return failedResults.Any() ? $"RoundTrip FAILED: [{string.Join(", ", failedResults)}] (passed: [{string.Join(", ", passedResults)}])"
                : "RoundTrip Passed";
        }

        /// <summary>
        /// Test <see cref="Argon2"/>.
        /// </summary>
        /// <returns>
        /// Result text.
        /// </returns>
        public static string TestArgon2RoundTrip2()
        {
            var password = "password1";
            var secret = "secret1";
            var passedResults = new List<string>();
            var failedResults = new List<string>();
            foreach (var argon2Type in new[]
            {
                Argon2Type.DataIndependentAddressing, Argon2Type.DataDependentAddressing, Argon2Type.HybridAddressing,
            })
            {
                var argon2Name = argon2Type == Argon2Type.DataIndependentAddressing ? "Argon2i" :
                    argon2Type == Argon2Type.DataDependentAddressing ? "Argon2d" : "Argon2id";

                var passwordHash = Argon2.Hash(password, secret, type: argon2Type);
                Console.WriteLine($"{argon2Name} of {password} --> {passwordHash}");

                if (Argon2.Verify(passwordHash, password, secret))
                {
                    passedResults.Add(argon2Name);
                    Console.WriteLine($"RoundTrip2 {argon2Name} Passed");
                }
                else
                {
                    failedResults.Add(argon2Name);
                    Console.WriteLine($"RoundTrip2 {argon2Name} FAILED");
                    Console.WriteLine($"    expected verify to work for {passwordHash} ({argon2Name} hash of {password})");
                }
            }

            return failedResults.Any() ? $"RoundTrip2 FAILED: [{string.Join(", ", failedResults)}] (passed: [{string.Join(", ", passedResults)}])"
                : "RoundTrip2 Passed";
        }

        /// <summary>
        /// Test <see cref="Argon2"/>.
        /// </summary>
        /// <returns>
        /// The result text.
        /// </returns>
        public static string TestArgon2ThreadsDontMatter()
        {
            var password = "password1";
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            var configA = new Argon2Config
            {
                Type = Argon2Type.DataIndependentAddressing,
                Version = Argon2Version.Nineteen,
                Password = passwordBytes,
                TimeCost = 3,
                MemoryCost = 32,
                Lanes = 4,
                Threads = 3,
            };

            var configB = new Argon2Config
            {
                Type = Argon2Type.DataIndependentAddressing,
                Version = Argon2Version.Nineteen,
                Password = passwordBytes,
                TimeCost = 3,
                MemoryCost = 32,
                Lanes = 4,
                Threads = 1,
            };
            using var argon2A = new Argon2(configA);
            using var argon2B = new Argon2(configB);
            using var hashA = argon2A.Hash();
            using var hashB = argon2B.Hash();
            var hashTextA = configA.EncodeString(hashA.Buffer);
            var hashTextB = configB.EncodeString(hashB.Buffer);
            var res = string.Compare(hashTextA, hashTextB, StringComparison.Ordinal) == 0
                ? "ThreadsDontMatter Passed"
                : "ThreadsDontMatter FAILED";
            Console.WriteLine(res);
            return res;
        }

        /// <summary>
        /// Test <see cref="Argon2"/>.
        /// </summary>
        /// <returns>
        /// Result text.
        /// </returns>
        public static string TestArgon2()
        {
            var passed = true;
            var nl = Environment.NewLine;
            foreach (var testVector in Argon2TestVectors)
            {
                var encoded = new StringBuilder();
                try
                {
                    var config = new Argon2Config
                    {
                        Type = testVector.Type,
                        Version = testVector.Version,
                        TimeCost = testVector.Iterations,
                        MemoryCost = testVector.MemoryKBytes,
                        Lanes = testVector.Parallelism,
                        Threads = testVector.Parallelism,
                        Password = testVector.Password,
                        Salt = testVector.Salt,
                        Secret = testVector.Secret,
                        AssociatedData = testVector.AssociatedData,
                        HashLength = testVector.TagLength,
                    };
                    var argon2 = new Argon2(config);
                    SecureArray<byte> hash = argon2.Hash();
                    if (!hash.Buffer.Where((b, i) => b != testVector.Tag[i]).Any())
                    {
                        Console.WriteLine(
                            $"Test {testVector.Name} passed:{nl}"
                            + $"             Version 0x{(int)testVector.Version:X} ({(int)testVector.Version}){nl}"
                            + $"                Type {testVector.Type}{nl}"
                            + $"          Iterations {testVector.Iterations}{nl}"
                            + $"       Memory KBytes {testVector.MemoryKBytes}{nl}"
                            + $"         Parallelism {testVector.Parallelism}{nl}"
                            + $"            Password {BitConverter.ToString(testVector.Password)}{nl}"
                            + $"                Salt {BitConverter.ToString(testVector.Salt)}{nl}"
                            + $"              Secret {BitConverter.ToString(testVector.Secret)}{nl}"
                            + $"      AssociatedData {BitConverter.ToString(testVector.AssociatedData)}{nl}"
                            + $"  Gave expected hash {BitConverter.ToString(hash.Buffer)}{nl}"
                            + $"             encoded {encoded}");
                    }
                    else
                    {
                        Console.WriteLine(
                            $"Test {testVector.Name}: Got{nl}" +
                            $"  {BitConverter.ToString(hash.Buffer)}{nl}" +
                            $"expected{nl}" +
                            $"  {BitConverter.ToString(testVector.Tag)}");
                        passed = false;
                    }
                }

                // ReSharper disable once CatchAllClause
                catch (Exception e)
                {
                    Console.WriteLine($"Test {testVector.Name}: {e.Message} ({e.GetType()})");
                }
            }

            var res = passed ? "Argon2 Passed" : "Argon2 FAILED";
            Console.WriteLine(res);
            return res;
        }

        /// <summary>
        /// Test the buffer size <see cref="SecureArray"/> allows.
        /// </summary>
        /// <returns>
        /// Result string.
        /// </returns>
        /// <remarks>
        /// <see cref="SecureArray"/> does this to some extent internally when throwing its failed exception.
        /// </remarks>
        public static string TestSecureArray()
        {
            int size = 100;
            int smallestFailedSize = int.MaxValue;
            int largestSuccessfulSize = size;
            while (true)
            {
                try
                {
                    using (new SecureArray<byte>(size, SecureArray.DefaultCall))
                    {
                        Console.WriteLine($"SecureArray: Passed size={size}");
                        if (size == smallestFailedSize)
                        {
                            break;
                        }

                        largestSuccessfulSize = size;
                        long tmp = size;
                        tmp += smallestFailedSize;
                        tmp /= 2;
                        size = (int)tmp;
                    }
                }

                // ReSharper disable once CatchAllClause
                catch (Exception e)
                {
                    Console.WriteLine($"SecureArray: Failed size={size}: {e.Message}");

                    smallestFailedSize = size;
                    long tmp = largestSuccessfulSize;
                    tmp += smallestFailedSize;
                    tmp /= 2;
                    size = (int)tmp;

                    if (smallestFailedSize <= largestSuccessfulSize)
                    {
                        size = largestSuccessfulSize;
                        break;
                    }
                }
            }

            return $"Made a {size}-byte secure array";
        }

        /// <summary>
        /// Look for leaks.
        /// </summary>
        /// <returns>String with pass/fail message.</returns>
        public static string TestLeaks()
        {
            var locks = new Dictionary<IntPtr, int>();
            int lockCount = 0;
            var badLocks = new List<int>();
            int badUnlockCount = 0;
            SecureArrayCall secureArrayCall = new SecureArrayCall(
                SecureArray.DefaultCall.ZeroMemory,
                (m, l) =>
                    {
                        string ret = SecureArray.DefaultCall.LockMemory(m, l);
                        if (ret == null)
                        {
                            lock (locks)
                            {
                                ++lockCount;
                                if (locks.ContainsKey(m))
                                {
                                    badLocks.Add(lockCount);
                                }
                                else
                                {
                                    locks.Add(m, lockCount);
                                }
                            }
                        }

                        return ret;
                    },
                (m, l) =>
                    {
                        lock (locks)
                        {
                            if (locks.ContainsKey(m))
                            {
                                locks.Remove(m);
                                SecureArray.DefaultCall.UnlockMemory(m, l);
                            }
                            else
                            {
                                ++badUnlockCount;
                            }
                        }
                    });

            var hashString = "$argon2i$v=19$m=65536,t=3,p=1$M2f6+jnVc4dyL3BfMQRzoA==$jO/fOrgqxX90XDVhiYZgIVJJcw0lzIXtRFRCEggXYV8=";
            var password = "b";
            const int maxIteration = 10;
            var memoryDiff = new long[maxIteration];
            for (int i = 0; i < maxIteration; i++)
            {
                Console.WriteLine($"TestLeaks: Iteration {i + 1} of {maxIteration}");
                var prevTotalMemory = GC.GetTotalMemory(true);
                Argon2.Verify(hashString, password, secureArrayCall);
                var postTotalMemory = GC.GetTotalMemory(true);
                memoryDiff[i] = postTotalMemory - prevTotalMemory;
            }

            var errs = new List<string>();
            if (memoryDiff.All(v => v > 0))
            {
                errs.Add($"Leaked {memoryDiff.Min()} bytes");
            }

            if (badLocks.Any())
            {
                errs.Add($"{badLocks.Count} bad locks: [{string.Join(", ", badLocks.Select(l => $"{l}"))}].");
            }

            if (badUnlockCount > 0)
            {
                errs.Add($"{badUnlockCount} bad unlocks.");
            }

            if (locks.Any())
            {
                errs.Add($"Leaked {locks.Count} locks: addresses=[{string.Join(", ", locks.Keys.Select(k => $"0x{k.ToInt64():x8}"))}], lock index=[{string.Join(", ", locks.Keys.Select(k => $"{locks[k]}"))}].");
            }

            return errs.Any() ? $"Leaks: FAILED: {string.Join(" ", errs)}" : "Leaks: Passed";
        }

        public static string TestHighMemoryCost()
        {
            // Tests chunking the Argon2 working memory because of the limits of C# array sizes.
            // this can take a long time depending on the multiplier
            int multiplier = 10;
            string password = "password";
            var memoryCost = (multiplier * Argon2.CsharpMaxBlocksPerArray / Argon2.QwordsInBlock) + 271;
            JetBrains.Profiler.Api.MemoryProfiler.GetSnapshot();
            string hash = Argon2.Hash(password, memoryCost: memoryCost, parallelism: 20, secureArrayCall: new InsecureArrayCall());
            JetBrains.Profiler.Api.MemoryProfiler.GetSnapshot();
            bool ret = Argon2.Verify(hash, password);
            JetBrains.Profiler.Api.MemoryProfiler.GetSnapshot();

            return !ret ? "HighMemoryCost: FAILED" : "HighMemoryCost: Passed";
        }

        /// <summary>
        /// Program entry.
        /// </summary>
        /// <param name="args">Command line arguments - unused.</param>
        public static void Main(string[] args)
        {
            Console.WriteLine("Testing Isopoh.Cryptography.Argon2");
            var resultTexts = new List<string>
            {
                TestLeaks(),
                TestSecureArray(),
                TestArgon2RoundTrip(),
                TestArgon2RoundTrip2(),
                TestArgon2ThreadsDontMatter(),
                TestArgon2(),
                TestFromDraft(),
                TestHighMemoryCost(),
            };
            Console.WriteLine($"Tests complete:{Environment.NewLine}  {string.Join($"{Environment.NewLine}  ", resultTexts)}");
        }

        private static string TestFromDraft()
        {
            // from draft-irtf-cfrg-argon2-03
            // They have this code in version 3 of the draft but it is gone in version 4.
            var testPwd = Encoding.ASCII.GetBytes("pasword");
            var testSalt = Encoding.ASCII.GetBytes("somesalt");
            const int testTimeCost = 3;
            const int testMemoryCost = 1 << 12;
            const int testParallelism = 1;
            const Argon2Version testArgon2VersionNumber = Argon2Version.Nineteen;
            bool Run(
                byte[] pwd,
                byte[] salt,
                int timeCost,
                int memoryCost,
                int threads,
                Argon2Type argon2Type,
                Argon2Version version,
                byte[] expectedHash)
            {
                using var hash = new Argon2(
                    new Argon2Config
                    {
                        HashLength = expectedHash.Length,
                        TimeCost = timeCost,
                        MemoryCost = memoryCost,
                        Lanes = threads,
                        Threads = threads,
                        Password = pwd,
                        Salt = salt,
                        Version = version,
                        Type = argon2Type,
                    }).Hash();
                Console.WriteLine($"     Actual Hash:   {BitConverter.ToString(hash.Buffer)}");
                Console.WriteLine($"     Expected Hash: {BitConverter.ToString(expectedHash)}");
                return !hash.Buffer.Where((b, i) => b != expectedHash[i]).Any();
            }

            bool Argon2ISelfTest()
            {
                byte[] expectedHash =
                {
                    0x95, 0x7f, 0xc0, 0x72, 0x7d, 0x83, 0xf4, 0x06,
                    0x0b, 0xb0, 0xf1, 0x07, 0x1e, 0xb5, 0x90, 0xa1,
                    0x9a, 0x8c, 0x44, 0x8f, 0xc0, 0x20, 0x94, 0x97,
                    0xee, 0x4f, 0x54, 0xca, 0x24, 0x1f, 0x3c, 0x90,
                };
                return Run(
                    testPwd,
                    testSalt,
                    testTimeCost,
                    testMemoryCost,
                    testParallelism,
                    Argon2Type.DataIndependentAddressing,
                    testArgon2VersionNumber,
                    expectedHash);
            }

            bool Argon2DSelfTest()
            {
                byte[] expectedHash =
                {
                    0x0b, 0x3f, 0x09, 0xe7, 0xb8, 0xd0, 0x36, 0xe5,
                    0x8c, 0xcd, 0x08, 0xf0, 0x8c, 0xb6, 0xba, 0xbf,
                    0x7e, 0x5e, 0x24, 0x63, 0xc2, 0x6b, 0xcf, 0x2a,
                    0x9e, 0x4e, 0xa7, 0x0d, 0x74, 0x7c, 0x40, 0x98,
                };
                return Run(
                    testPwd,
                    testSalt,
                    testTimeCost,
                    testMemoryCost,
                    testParallelism,
                    Argon2Type.DataDependentAddressing,
                    testArgon2VersionNumber,
                    expectedHash);
            }

            bool Argon2IdSelfTest()
            {
                byte[] expectedHash =
                {
                    0xf5, 0x55, 0x35, 0xbf, 0xe9, 0x48, 0x71, 0x00,
                    0x51, 0x42, 0x4c, 0x74, 0x24, 0xb1, 0x1b, 0xa9,
                    0xa1, 0x3a, 0x50, 0x23, 0x9b, 0x04, 0x59, 0xf5,
                    0x6c, 0xa6, 0x95, 0xea, 0x14, 0xbc, 0x19, 0x5e,
                };
                return Run(
                    testPwd,
                    testSalt,
                    testTimeCost,
                    testMemoryCost,
                    testParallelism,
                    Argon2Type.HybridAddressing,
                    testArgon2VersionNumber,
                    expectedHash);
            }

            var argon2IResult = $"draft-irtf-cfrg-argon2-03 Argon2i  - {(Argon2ISelfTest() ? "Passed" : "FAIL")}";
            Console.WriteLine(argon2IResult);
            var argon2DResult = $"draft-irtf-cfrg-argon2-03 Argon2d  - {(Argon2DSelfTest() ? "Passed" : "FAIL")}";
            Console.WriteLine(argon2DResult);
            var argon2IdResult = $"draft-irtf-cfrg-argon2-03 Argon2id - {(Argon2IdSelfTest() ? "Passed" : "FAIL")}";
            Console.WriteLine(argon2IdResult);
            return string.Join($"{Environment.NewLine}  ", argon2IResult, argon2DResult, argon2IdResult);
        }

        /// <summary>
        /// Makes useful binary from text Argon2 test vector information.
        /// </summary>
        public sealed class Argon2TestVector
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="Argon2TestVector"/> class.
            /// </summary>
            /// <param name="name">
            /// name of the vector.
            /// </param>
            /// <param name="type">
            /// Data-driven or independent.
            /// </param>
            /// <param name="version">
            /// The Argon2 version.
            /// </param>
            /// <param name="iterations">
            /// The number of iterations.
            /// </param>
            /// <param name="memoryKBytes">
            /// The memory to use.
            /// </param>
            /// <param name="parallelism">
            /// The number of threads to use.
            /// </param>
            /// <param name="tagLength">
            /// How many bytes to output.
            /// </param>
            /// <param name="password">
            /// The password to hash.
            /// </param>
            /// <param name="salt">
            /// The salt to use in the hash. Minimum of 8 bytes. 16 recommended.
            /// </param>
            /// <param name="secret">
            /// The secret to use in the hash.
            /// </param>
            /// <param name="associatedData">
            /// The associated data to use in the hash (like a salt but can be shorter).
            /// </param>
            /// <param name="tag">
            /// The expected hash created from the above parameters.
            /// </param>
            public Argon2TestVector(
                string name,
                Argon2Type type,
                Argon2Version version,
                int iterations,
                int memoryKBytes,
                int parallelism,
                int tagLength,
                string password,
                string salt,
                string secret,
                string associatedData,
                string tag)
            {
                this.Name = name;
                this.Type = type;
                this.Version = version;
                this.Iterations = iterations;
                this.MemoryKBytes = memoryKBytes;
                this.Parallelism = parallelism;
                this.TagLength = tagLength;
                this.Password = ToBytes(password);
                this.Salt = ToBytes(salt);
                this.Secret = ToBytes(secret);
                this.AssociatedData = ToBytes(associatedData);
                this.Tag = ToBytes(tag);
            }

            /// <summary>
            /// Gets the name of the test vector.
            /// </summary>
            public string Name { get; }

            /// <summary>
            /// Gets the Argon2 type - data dependent or independent.
            /// </summary>
            public Argon2Type Type { get; }

            /// <summary>
            /// Gets the version of the Argon2 algorithm to use.
            /// </summary>
            public Argon2Version Version { get; }

            /// <summary>
            /// Gets the number of iterations to use in the Argon2 hash.
            /// </summary>
            public int Iterations { get; }

            /// <summary>
            /// Gets the amount of memory to use in the Argon2 hash.
            /// </summary>
            public int MemoryKBytes { get; }

            /// <summary>
            /// Gets the number of threads to use in the Argon2 hash.
            /// </summary>
            public int Parallelism { get; }

            /// <summary>
            /// Gets the size in bytes of the output hash value to create.
            /// </summary>
            public int TagLength { get; }

            /// <summary>
            /// Gets the password to hash.
            /// </summary>
            public byte[] Password { get; }

            /// <summary>
            /// Gets the salt to hash.
            /// </summary>
            public byte[] Salt { get; }

            /// <summary>
            /// Gets the secret to hash.
            /// </summary>
            public byte[] Secret { get; }

            /// <summary>
            /// Gets the associated data to hash.
            /// </summary>
            public byte[] AssociatedData { get; }

            /// <summary>
            /// Gets the expected result of the hash.
            /// </summary>
            public byte[] Tag { get; }

            /// <summary>
            /// Convert a hex string to bytes.
            /// </summary>
            /// <param name="s">
            /// The hex string.
            /// </param>
            /// <returns>
            /// The byte array.
            /// </returns>
            /// <exception cref="ArgumentException">
            /// Invalid hex string.
            /// </exception>
            private static byte[] ToBytes(string s)
            {
                var ret = new List<byte>();
                for (int i = 1; i < s.Length; i += 2)
                {
                    var ch = s[i - 1];
                    var cl = s[i];
                    while (char.IsWhiteSpace(ch))
                    {
                        ch = cl;
                        ++i;
                        if (i == s.Length)
                        {
                            break;
                        }

                        cl = s[i];
                    }

                    byte val;
#pragma warning disable SA1131 // Use readable conditions

                    // ReSharper disable StyleCop.SA1131
                    if ('0' <= ch && ch <= '9')
                    {
                        val = (byte)((uint)(ch - '0') << 4);
                    }
                    else if ('a' <= ch && ch <= 'f')
                    {
                        val = (byte)((uint)(ch - 'a' + 10) << 4);
                    }
                    else if ('A' <= ch && ch <= 'F')
                    {
                        val = (byte)((uint)(ch - 'A' + 10) << 4);
                    }
                    else
                    {
                        throw new ArgumentException($"Invalid character '{ch}' found in hex string");
                    }

                    if ('0' <= cl && cl <= '9')
                    {
                        val += (byte)(uint)(cl - '0');
                    }
                    else if ('a' <= cl && cl <= 'f')
                    {
                        val += (byte)(uint)(cl - 'a' + 10);
                    }
                    else if ('A' <= cl && cl <= 'F')
                    {
                        val = (byte)(uint)(cl - 'A' + 10);
                    }
                    else
                    {
                        throw new ArgumentException($"Invalid character '{cl}' found in hex string");
                    }

                    // ReSharper restore StyleCop.SA1131
#pragma warning restore SA1131 // Use readable conditions

                    ret.Add(val);
                }

                return ret.ToArray();
            }
        }

        private sealed class InsecureArrayCall : SecureArrayCall
        {
            public InsecureArrayCall()
                : base(NoZeroMemory, NoLockMemory, NoUnlockMemory)
            {
            }

            private static void NoZeroMemory(IntPtr buf, UIntPtr len) { }

            private static string NoLockMemory(IntPtr buf, UIntPtr len)
            {
                return null;
            }

            private static void NoUnlockMemory(IntPtr buf, UIntPtr len) { }
        }
    }
}
