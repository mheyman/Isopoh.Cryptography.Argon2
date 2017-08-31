// --------------------------------------------------------------------------------------------------------------------
// <copyright file="Program.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>
// <summary>
//   Test because unit tests seem to be hard to get running.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace TestApp
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    using Isopoh.Cryptography.Argon2;
    using Isopoh.Cryptography.SecureArray;

    /// <summary>
    /// Run the program.
    /// </summary>
    public class Program
    {
        /// <summary>
        /// Test vectors for Argon2. From https://github.com/P-H-C/phc-winner-argon2/tree/master/kats
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
                    "c8 14 d9 d1 dc 7f 37 aa 13 f0 d7 7f 24 94 bd a1 c8 de 6b 01 6d d3 88 d2 99 52 a4 c4 67 2b 6c e8")
            };

        /// <summary>
        /// Test <see cref="Argon2"/>.
        /// </summary>
        public static void TestArgon2RoundTrip()
        {
            var rng = new Random();
            var password = "password1";
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] salt = new byte[16];
            rng.NextBytes(salt);
            var config = new Argon2Config
                             {
                                 Type = Argon2Type.DataIndependentAddressing,
                                 Version = Argon2Version.Nineteen,
                                 Password = passwordBytes,
                                 Salt = salt,
                                 TimeCost = 3,
                                 MemoryCost = 65536,
                                 Lanes = 4,
                                 Threads = 2,
                             };
            var argon2 = new Argon2(config);
            SecureArray<byte> hash = argon2.Hash();
            var passwordHash = config.EncodeString(hash.Buffer);
            Console.WriteLine($"Argon2 of {password} --> {passwordHash}");
            if (Argon2.Verify(passwordHash, passwordBytes))
            {
                Console.WriteLine("Round Trip Passed");
            }
            else
            {
                Console.WriteLine("Round Trip FAILED");
                Console.WriteLine($"    expected verify to work for {passwordHash} (Argon2 hash of {password}");
            }
        }

        /// <summary>
        /// Test <see cref="Argon2"/>.
        /// </summary>
        public static void TestArgon2RoundTrip2()
        {
            var password = "password1";
            var passwordHash = Argon2.Hash(password);
            Console.WriteLine($"Argon2 of {password} --> {passwordHash}");

            if (Argon2.Verify(passwordHash, password))
            {
                Console.WriteLine("RoundTrip2 Passed");
            }
            else
            {
                Console.WriteLine("RoundTrip2 FAILED");
                Console.WriteLine($"    expected verify to work for {passwordHash} (Argon2 hash of {password}");
            }
        }

        /// <summary>
        /// Test <see cref="Argon2"/>.
        /// </summary>
        public static void TestArgon2ThreadsDontMatter()
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
            using (var argon2A = new Argon2(configA))
            using (var argon2B = new Argon2(configB))
            using (var hashA = argon2A.Hash())
            using (var hashB = argon2B.Hash())
            {
                var hashTextA = configA.EncodeString(hashA.Buffer);
                var hashTextB = configB.EncodeString(hashB.Buffer);
                Console.WriteLine(
                    string.Compare(hashTextA, hashTextB, StringComparison.Ordinal) == 0
                        ? "ThreadsDontMatter Passed"
                        : "ThreadsDontMatter FAILED");
            }
        }

        /// <summary>
        /// Test <see cref="Argon2"/>.
        /// </summary>
        public static void TestArgon2()
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
                                         HashLength = testVector.TagLength
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

            Console.WriteLine(passed ? "Argon2 Passed" : "Argon2 FAILED");
        }

        /// <summary>
        /// Test the buffer size <see cref="SecureArray"/> allows.
        /// </summary>
        /// <remarks>
        /// <see cref="SecureArray"/> does this to some extent internally when throwing its failed exception.
        /// </remarks>
        public static void TestSecureArray()
        {
            int size = 100;
            int max = int.MaxValue;
            int previous = size;
            while (true)
            {
                try
                {
                    using (new SecureArray<ulong>(size))
                    {
                        Console.WriteLine($"SecureArray: Passed size={size}");
                        if (size == max)
                        {
                            break;
                        }

                        previous = size;
                        long tmp = size;
                        tmp += max;
                        tmp /= 2;
                        size = (int)tmp;
                    }
                }

                // ReSharper disable once CatchAllClause
                catch (Exception e)
                {
                    Console.WriteLine($"SecureArray: Failed size={size}: {e.Message}");
                    max = size;
                    long tmp = previous;
                    tmp += max;
                    tmp /= 2;
                    size = (int)tmp;
                }
            }
        }

        /// <summary>
        /// Program entry.
        /// </summary>
        /// <param name="args">Command line arguments - unused.</param>
        public static void Main(string[] args)
        {
            Console.WriteLine("Testing Isopoh.Cryptography.Argon2");
            TestSecureArray();
            TestArgon2RoundTrip();
            TestArgon2RoundTrip2();
            TestArgon2ThreadsDontMatter();
            TestArgon2();
            Console.WriteLine("Tests complete");
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
            /// name of the vector
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
            /// Convert a hex string to bytes
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
    }
}
