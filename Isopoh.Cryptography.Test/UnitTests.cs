
namespace Test
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Text;
    using System.Linq;

    using Isopoh.Cryptography.Argon2;
    using Isopoh.Cryptography.SecureArray;
    using Xunit;
    using Xunit.Abstractions;
    using Xunit.Sdk;

    /// <summary>
    /// Unit tests for Isopoh.Cryptography.Argon2
    /// </summary>
    public class UnitTests
    {
        /// <summary>
        /// Test vectors for Argon2. From https://github.com/P-H-C/phc-winner-argon2/tree/master/kats
        /// </summary>
        private readonly Argon2TestVector[] argon2TestVectors =
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

        private readonly ITestOutputHelper output;

        /// <summary>
        /// Initialize a new instance of the <see cref="UnitTests"/> class.
        /// </summary>
        /// <param name="output">
        /// Where to send the output to (doesn't seem to work...)
        /// </param>
        public UnitTests(ITestOutputHelper output)
        {
            this.output = output;
        }

        /// <summary>
        /// Test <see cref="Argon2"/>.
        /// </summary>
        [Fact]
        public void TestArgon2RoundTrip()
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
            this.output.WriteLine($"Argon2 of {password} --> {passwordHash}");
            Assert.True(
                Argon2.Verify(passwordHash, passwordBytes),
                $"expected verify to work for {passwordHash} (Argon2 hash of {password}");
        }

        /// <summary>
        /// Test <see cref="Argon2"/>.
        /// </summary>
        [Fact]
        public void TestArgon2RoundTrip2()
        {
            var password = "password1";
            var passwordHash = Argon2.Hash(password);
            this.output.WriteLine($"Argon2 of {password} --> {passwordHash}");
            Assert.True(
                Argon2.Verify(passwordHash, password),
                $"expected verify to work for {passwordHash} (Argon2 hash of {password}");
        }

        /// <summary>
        /// Test <see cref="Argon2"/>.
        /// </summary>
        [Fact]
        public void TestArgon2ThreadsDontMatter()
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
                Assert.Equal(hashTextA, hashTextB);
            }
        }

        /// <summary>
        /// Test <see cref="Argon2"/>.
        /// </summary>
        [Fact]
        public void TestArgon2()
        {
            foreach (var testVector in this.argon2TestVectors)
            {
                var encoded = new StringBuilder();
                uint tagLength = (uint)testVector.TagLength;
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
                    Assert.False(
                        hash.Buffer.Where((b, i) => b != testVector.Tag[i]).Any(),
                        $"Test {testVector.Name}: Got{Environment.NewLine}{BitConverter.ToString(hash.Buffer)}{Environment.NewLine}expected{Environment.NewLine}{BitConverter.ToString(testVector.Tag)}");
                    this.output.WriteLine(
                        "Passed Argon2:\r\n"
                        + $"             Version 0x{(int)testVector.Version:X} ({(int)testVector.Version})\r\n"
                        + $"                Type {testVector.Type}\r\n"
                        + $"          Iterations {testVector.Iterations}\r\n"
                        + $"       Memory KBytes {testVector.MemoryKBytes}\r\n"
                        + $"         Parallelism {testVector.Parallelism}\r\n"
                        + $"            Password {BitConverter.ToString(testVector.Password)}\r\n"
                        + $"                Salt {BitConverter.ToString(testVector.Salt)}\r\n"
                        + $"              Secret {BitConverter.ToString(testVector.Secret)}\r\n"
                        + $"       AssciatedData {BitConverter.ToString(testVector.AssociatedData)}\r\n"
                        + $"  Gave expected hash {BitConverter.ToString(hash.Buffer)}\r\n"
                        + $"             encoded {encoded}");
                }
                catch (Exception e)
                {
                    Assert.False(true, e.Message);
                }
            }
        }

        ////[Fact]
        ////public void TestStore64()
        ////{
        ////    var v1 = new byte[8];
        ////    var v2 = new byte[8];

        ////    new Random().NextBytes(v1);
        ////    ulong tmp = Hasher.Load64(v1, 0);
        ////    Hasher.Store64(v2, 0, tmp);
        ////    this.output.WriteLine($"{BitConverter.ToString(v1)}");
        ////    this.output.WriteLine($"{tmp:X}");
        ////    this.output.WriteLine($"{BitConverter.ToString(v2)}");
        ////    Assert.True(false, $"{BitConverter.ToString(v1)}\r\n{tmp:X}\r\n{BitConverter.ToString(v2)}");

        ////    Assert.Equal(v1, v2);
        ////}

        [Fact]
        public void TestSecureArray()
        {
            int size = 100;
            int max = int.MaxValue;
            int prev = size;
            for (;;)
            {
                try
                {
                    using (var buf = new SecureArray<ulong>(size))
                    {
                        this.output.WriteLine($"Passed size={size}");
                        if (size == max)
                        {
                            break;
                        }

                        prev = size;
                        long tmp = size;
                        tmp += max;
                        tmp /= 2;
                        size = (int)tmp;
                    }
                }
                catch (Exception)
                {
                    this.output.WriteLine($"Failed size={size}");
                    max = size;
                    long tmp = prev;
                    tmp += max;
                    tmp /= 2;
                    size = (int)tmp;
                }
            }
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
            /// Gets the Argon2 type - data dependant or independant.
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
#pragma warning restore SA1131 // Use readable conditions

                    ret.Add(val);
                }

                return ret.ToArray();
            }
        }
    }
}