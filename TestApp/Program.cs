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
    using System.Net.Sockets;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
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
                new (
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
                new (
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
                new (
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
                new (
                    "Big honkin data independent", // From https://github.com/kmaragon/Konscious.Security.Cryptography/blob/master/Konscious.Security.Cryptography.Argon2.Test/Argon2Tests.cs (MIT license)
                    Argon2Type.DataIndependentAddressing,
                    Argon2Version.Nineteen,
                    15,
                    4096,
                    16,
                    512,
                    "5a 28 98 a3 45 c7 20 33 5d 64 39 7b 43 db fc 0e be c8 48 4c 7a 9d f9 b0 c2 bf 50 74 26 75 3b 58 c8 38 e8 a4 3f 91 c7 3f 94 3e a3 75 a6 04 f1 54 89 eb 12 30 57 bc 6d d3 47 0f 54 33 84 5a 92 b1 57 fe aa 83 cf 1c c9 0a d3 d4 7a a3 d8 bc 12 c6 b4 2c 89 a0 25 2b 7a 0f b8 5f a9 e6 70 ae c7 73 74 d3 c7 55 2b 9f 86 d8 fb ea 03 ea ba 4f 02 8d 03 c4 75 66 eb 6f 1a d1 77 25 98 84 2d d1 8e 00",
                    "f7 19 2b a7 ff b8 ca dc 67 51 ed a0 08 1d 9d 95 0b 10 e4 32 23 ef 30 07 39 c6 bc ad 36 da 08 eb 03 3b ab 98 32 06 7d 39 6f 81 72 24 ff 58 41 e6 33 5d f7 e7 56 f7 af 32 fa d8 72 78 ac 63 da d1",
                    "b4 e6 04 41 f6 2d c4 1a a0 36 9e 2a a0 bd 1c ce 93 1c 8d b7 b7 af 11 20 ba 5e 99 fc ff d6 b1 04 00 55 5b b0 35 80 43 2e bf c7 10 06 e3 04 68 e8 10 a7 95 b5 d1 02 84 49 4c 22 34 05 90 48 90 4a",
                    "4b 53 7c a5 e0 2b e4 06 ce 9e 9e a3 27 9c 6e 26",
                    "98 29 12 18 57 65 2b 98 7d 98 8b 68 2c b0 11 cd c5 c6 8a a0 e9 cb 82 f0 da d2 46 7a 6d c5 15 2c 42 54 52 94 68 12 e7 9f 6e db e0 33 53 3a 21 5f e9 97 bc 66 d0 6d 41 e4 ea 5e 05 79 97 66 71 79 75 42 7e c6 ed e1 f8 a8 ef 25 f4 b0 fd d1 55 86 df 9a 18 6a ca 7c 4a 12 9c d4 e5 c9 f5 70 a7 e5 d6 40 28 12 08 14 e0 39 65 53 0f e1 fa 0f 81 1d bc c6 43 dd ff 3a 66 2f be 93 f6 43 18 ce e8 38 82 73 80 8b 09 ae cf 90 d6 c8 63 e0 51 4f 25 bb 8d a7 06 32 48 a0 ed 3e 6e 52 5a d9 7d 43 99 09 c3 69 57 43 64 48 16 79 5d b4 05 24 08 f4 5e b7 70 a5 9a cc 8d be 46 ca a1 7f 02 a7 89 cc 56 e9 12 a1 b0 0d 41 4d 5f 32 f7 03 20 74 25 20 8a e0 f9 86 31 dc 7f d9 cc 34 af 6d 51 1b c7 2a af 15 b4 bb e5 d6 90 eb 3e ce 64 7c 1b 73 1a 17 43 3f 04 4e bf 47 8d 8d 36 0a e5 b1 39 e0 ed 7d 49 37 9b 51 44 23 45 1d 34 64 ed 43 16 56 29 91 cc 8f eb 11 a1 d1 24 58 bf 24 0a 70 82 d0 3b 9c 05 de 1b bf e2 a7 a3 cb ad 8e 3b 40 c0 db 56 ca c4 e2 06 7a 3f 21 8b 13 31 b9 aa 9f 30 02 5e 04 d5 4f 2b ca fe aa b8 46 a4 2b e6 cb 10 b7 b5 bf 0c d4 c5 17 38 0e e1 0c e9 53 13 7b f9 bd f2 33 63 2b 3d b4 ff 9e e9 7c b9 6c 2f ba 77 d3 0a f8 7a 8d 2d 76 e3 44 4b 13 1d bf e6 f7 3d 73 07 15 ca 4a 30 47 f8 ef 6d 78 27 fe ff 6b 34 b7 d0 20 2d b1 56 90 f4 6a b4 e4 16 47 f7 ea c4 70 0e 06 e6 fa 3a 97 b5 f8 91 48 b6 38 45 a8 28 26 7a 5f 0b 36 e5 ca 9d 19 af 13 4c 34 dd df 55 89 4f 9e d4 1b 2e 6d 1c a7 cd 01 d7 d1 33 bd 45 0c e8 b6 33 02 fb d2 88 5c 3c 01 6a 5e 3d 16 76 6d 04 18 51 28 f0 1d 49 3a 2f 41 cd da 94 b7 3a 6a c1 aa b1 2d d8 58 39 81 cf 74 8a c8 c4 84 d0 b5 26 cf 5e 03"),
                new (
                    "Big honkin hybrid", // From https://github.com/kmaragon/Konscious.Security.Cryptography/blob/master/Konscious.Security.Cryptography.Argon2.Test/Argon2Tests.cs (MIT license)
                    Argon2Type.HybridAddressing,
                    Argon2Version.Nineteen,
                    15,
                    4096,
                    16,
                    512,
                    "5a 28 98 a3 45 c7 20 33 5d 64 39 7b 43 db fc 0e be c8 48 4c 7a 9d f9 b0 c2 bf 50 74 26 75 3b 58 c8 38 e8 a4 3f 91 c7 3f 94 3e a3 75 a6 04 f1 54 89 eb 12 30 57 bc 6d d3 47 0f 54 33 84 5a 92 b1 57 fe aa 83 cf 1c c9 0a d3 d4 7a a3 d8 bc 12 c6 b4 2c 89 a0 25 2b 7a 0f b8 5f a9 e6 70 ae c7 73 74 d3 c7 55 2b 9f 86 d8 fb ea 03 ea ba 4f 02 8d 03 c4 75 66 eb 6f 1a d1 77 25 98 84 2d d1 8e 00",
                    "f7 19 2b a7 ff b8 ca dc 67 51 ed a0 08 1d 9d 95 0b 10 e4 32 23 ef 30 07 39 c6 bc ad 36 da 08 eb 03 3b ab 98 32 06 7d 39 6f 81 72 24 ff 58 41 e6 33 5d f7 e7 56 f7 af 32 fa d8 72 78 ac 63 da d1",
                    "b4 e6 04 41 f6 2d c4 1a a0 36 9e 2a a0 bd 1c ce 93 1c 8d b7 b7 af 11 20 ba 5e 99 fc ff d6 b1 04 00 55 5b b0 35 80 43 2e bf c7 10 06 e3 04 68 e8 10 a7 95 b5 d1 02 84 49 4c 22 34 05 90 48 90 4a",
                    "4b 53 7c a5 e0 2b e4 06 ce 9e 9e a3 27 9c 6e 26",
                    "23 95 3a 0e 1d 02 8f 25 52 0a a2 f9 6f c0 cc 9d 41 c1 8c 8d f2 15 5d 85 8a 4b 46 0b 14 cd a7 a4 7f e3 b3 16 81 9d 93 f5 7e 98 e2 58 89 17 5e 88 11 fc ac e8 67 d4 d8 77 4f 76 cf 20 46 65 47 aa 48 7e ea c4 20 e6 51 b2 14 93 de 85 b1 8a d8 ce 27 9b a1 5d 00 86 65 7d bb bc 03 86 85 f2 b4 55 cd be 47 f0 26 ed 5e 12 3b 2d f5 e8 01 0e 8e f9 fc 37 96 34 78 73 f8 27 c6 17 da 5c 90 29 e6 f3 d1 b8 17 3b 34 f5 fd de 2e 25 8d 41 d6 7d 7b 8e e0 19 14 5a 54 b4 15 ba 11 0a f1 0d 60 dd 62 6a c0 9c 24 1c af 61 94 65 e1 4d 50 35 a2 7d c4 21 85 e2 02 25 9f ce 62 fc 9e 55 1b a7 33 47 d5 e9 70 b5 5f 05 71 80 45 2b 44 74 42 b4 c6 a3 14 33 ac 35 f9 5a 5c 56 c2 66 07 e2 0c e0 6c f5 86 e6 79 45 57 9f c8 3b 52 2f 67 4b 22 0c e2 14 a0 93 05 27 25 bd 55 dd b9 a9 6b a5 4c 0e 5c 76 33 0c 0d c3 49 12 ff 4f 52 b4 b3 ec 84 ed 3c 5e 28 59 88 30 8e 1a 34 02 17 af 73 e7 3e 28 aa ef df ae 2b b1 b7 e2 ca 6b bf 14 3d da 74 38 20 8b 53 d3 65 c3 ed 8b 30 46 42 6e e0 12 78 db ed a3 f0 ca bb 29 d6 00 88 c7 c1 c6 47 0c 2b e0 6f 04 25 11 aa bf 42 fe 30 ad cd eb 52 3d 92 4e 6d b7 df e0 e6 32 fd 0d 1b e8 91 03 09 01 2c 04 8f b9 e5 d9 b7 df db bd da 0a 79 88 18 79 14 bb f6 61 4b 31 1c 4e 19 89 4e 6e f4 23 a6 f6 23 2f 08 ed a9 c6 ee 6c 23 6a 48 e7 33 59 98 fc 2c 7f 87 98 4c f9 17 30 d2 07 08 8d 44 85 d1 b0 f1 09 26 71 8a 99 29 76 65 b4 05 04 61 d3 8c 85 5e 68 ef e5 52 54 d8 da 9d f2 e6 06 77 61 ef 3e 4f a4 dd 07 4a 0f 51 71 cf fc d9 bd 92 a5 90 8c 80 0a d7 86 80 23 17 44 d5 a5 2d d2 c8 72 13 54 4c 2f 6e f1 6e 5c 49 3d 2c 35 80 0d a9 76 4c d8 cb 1b 4e ba 7e b0"),
                new (
                    "Big honkin data dependent", // From https://github.com/kmaragon/Konscious.Security.Cryptography/blob/master/Konscious.Security.Cryptography.Argon2.Test/Argon2Tests.cs (MIT license)
                    Argon2Type.DataDependentAddressing,
                    Argon2Version.Nineteen,
                    15,
                    4096,
                    16,
                    512,
                    "5a 28 98 a3 45 c7 20 33 5d 64 39 7b 43 db fc 0e be c8 48 4c 7a 9d f9 b0 c2 bf 50 74 26 75 3b 58 c8 38 e8 a4 3f 91 c7 3f 94 3e a3 75 a6 04 f1 54 89 eb 12 30 57 bc 6d d3 47 0f 54 33 84 5a 92 b1 57 fe aa 83 cf 1c c9 0a d3 d4 7a a3 d8 bc 12 c6 b4 2c 89 a0 25 2b 7a 0f b8 5f a9 e6 70 ae c7 73 74 d3 c7 55 2b 9f 86 d8 fb ea 03 ea ba 4f 02 8d 03 c4 75 66 eb 6f 1a d1 77 25 98 84 2d d1 8e 00",
                    "f7 19 2b a7 ff b8 ca dc 67 51 ed a0 08 1d 9d 95 0b 10 e4 32 23 ef 30 07 39 c6 bc ad 36 da 08 eb 03 3b ab 98 32 06 7d 39 6f 81 72 24 ff 58 41 e6 33 5d f7 e7 56 f7 af 32 fa d8 72 78 ac 63 da d1",
                    "b4 e6 04 41 f6 2d c4 1a a0 36 9e 2a a0 bd 1c ce 93 1c 8d b7 b7 af 11 20 ba 5e 99 fc ff d6 b1 04 00 55 5b b0 35 80 43 2e bf c7 10 06 e3 04 68 e8 10 a7 95 b5 d1 02 84 49 4c 22 34 05 90 48 90 4a",
                    "4b 53 7c a5 e0 2b e4 06 ce 9e 9e a3 27 9c 6e 26",
                    "58 80 ed 76 d8 ec 7d f6 db f9 33 f1 33 62 b1 fb cd ab 12 a1 5e fe cf 48 eb 2c b6 eb e0 5a 29 e8 e7 02 e8 54 90 13 31 2a 2a 50 cf 02 08 ff 2a 98 07 76 b9 4d 06 07 6b d9 83 ce 2f 12 2e 6f c3 94 f1 ac f6 04 8e 53 cc 70 9c d4 0d 29 ee 29 20 46 31 4b 01 f0 2e d2 24 f2 76 f8 14 f9 96 66 57 ec cf 73 e6 f9 6e 18 3e 0b 38 29 10 ae 58 04 44 02 c9 b3 1e 9c 4a 34 5e 98 28 38 cf df 8e 28 df e9 e7 88 ad 18 6c bb 4a c3 8b 29 04 fb 30 b1 80 4f c8 f7 4c 3b de a3 5a 25 6e 91 2c 7e a2 1c 04 72 28 e5 70 57 53 e7 68 63 5f 1c b3 49 b1 61 78 40 51 ad ee ab 5c 05 bd 2c 46 b3 07 a1 ee d3 88 9d 7f ec de 2c fc 3d 98 36 a8 2a 24 09 72 cb 73 c2 ff d7 31 a2 79 ea 13 8e de cb 46 c6 b6 04 81 7f a3 9e e8 c6 ed 69 6f 37 01 a8 a1 8e f4 0d 5b 09 68 06 e7 e8 3c fe 0e ec d0 67 6a c2 bb 82 5f 6c e2 77 20 2b 4f 4f d6 41 3f 5c 5d c2 3b 19 67 c7 17 64 69 5b 0a 56 d5 df 1d 23 85 da a3 86 8d c6 96 c4 db 23 d0 5c 69 cb fa e3 da 83 44 7f 1d 49 b1 97 40 37 f0 a9 dc f8 e1 74 c0 76 38 1e 75 cf f0 7b 5b e2 a9 e9 a2 bd c4 3c f5 71 94 77 27 b7 36 45 ed 75 ef 3a 4d bf 90 ed 3c 71 72 6e 7f 3d 41 b8 1d 53 9c 63 c0 b6 2f f7 fb 95 5f 07 0a 1f 82 ea f3 bc 67 2d f8 0f b4 0c ac 5e c7 35 84 53 9a ff 93 d1 da a0 f2 6b 41 bc 75 4d 54 86 be 95 e7 83 7f 74 8d 2f 84 06 7d d2 9d 2f 74 14 d9 f9 c0 df ee b6 b6 2e 9d 5c b9 a1 1f 20 1a e3 72 67 ce 2c 61 da 15 5b 22 e5 a6 90 84 93 38 f7 a4 a9 7e a6 ae 57 41 9f 73 f1 e0 9c 7d 14 07 c2 bb bd d6 cb 53 d3 d8 1b 41 2e 02 8b c3 1f 79 ed d1 4a 47 55 08 ad e6 0c fa de 21 63 c5 91 57 03 90 77 ac 94 5b 00 8e 91 20 de a7 c7 10 8a f7 61 bc fb"),
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

            foreach (var testVector in Argon2TestVectors)
            {
                passed = passed && TestVectorBasicCheck(testVector);
            }

            var res = passed ? "Argon2 Passed" : "Argon2 FAILED";
            Console.WriteLine(res);
            return res;
        }

        /// <summary>
        /// Test <see cref="Argon2"/> against test vectors generated by the C-language reference command line example.
        /// </summary>
        /// <returns>Result text.</returns>
        public static string TestArgon2AgainstReference()
        {
            var testVectors = new global::Argon2TestVector.Test().Argon2Vectors;
            var faileds = new List<int>();
            foreach (var (i, testVector) in testVectors.Select((a, i) => (i, a)))
            {
                if (!TestVectorBasicCheck(i, testVector))
                {
                    faileds.Add(i);
                }
            }

            var res = faileds.Any() ? $"Argon2AgainstReference FAILED {faileds.Count}/{testVectors.Count} [{string.Join(", ", faileds.Select(a => $"{a}"))}]" : "Argon2AgainstReference Passed";
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
                        if (size + 1 >= smallestFailedSize)
                        {
                            break;
                        }

                        if (size > largestSuccessfulSize)
                        {
                            largestSuccessfulSize = size;
                        }

                        size = largestSuccessfulSize + ((smallestFailedSize - largestSuccessfulSize) / 2);
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
                    },
                $"Wrapped {SecureArray.DefaultCall.Os}");

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

        /// <summary>
        /// Make sure it works with more RAM than C# can allocate in a single chunk.
        /// </summary>
        /// <returns>String with pass/fail message.</returns>
        public static string TestHighMemoryCost()
        {
            Console.WriteLine("HighMemoryCost");

            // Tests chunking the Argon2 working memory because of the limits of C# array sizes.
            // this can take a long time depending on the multiplier
            Console.WriteLine("HighMemoryCost:");
            string password = "password";
            var memoryCost = Argon2.CsharpMaxBlocksPerArray + 271;
            JetBrains.Profiler.Api.MemoryProfiler.GetSnapshot();
            Console.WriteLine("HighMemoryCost: Hash");
            string hash = Argon2.Hash(password, memoryCost: memoryCost, parallelism: 20, secureArrayCall: new InsecureArrayCall());
            JetBrains.Profiler.Api.MemoryProfiler.GetSnapshot();
            Console.WriteLine("HighMemoryCost: Verify");
            bool ret = Argon2.Verify(hash, password);
            Console.WriteLine($"HighMemoryCost: verify {(ret ? "Success" : "FAIL")}");
            JetBrains.Profiler.Api.MemoryProfiler.GetSnapshot();

            return !ret ? "HighMemoryCost: FAILED" : "HighMemoryCost: Passed";
        }

        /// <summary>
        /// Test-by-inspection that hash is slowest when parallelism is 1.
        /// (Depending on core count, it may go down and back up after that).
        /// </summary>
        /// <returns>TestTimeToHash: Passed.</returns>
        public static string TestTimeToHash()
        {
            (double, string, string) Check5(int p)
            {
                const string password = "hello world";
                string ret = string.Empty;
                var res = new List<double>();
                for (int i = 0; i < 5; ++i)
                {
                    var tick = DateTimeOffset.UtcNow;
                    ret = Argon2.Hash(password, parallelism: p);
                    res.Add((DateTimeOffset.UtcNow - tick).TotalSeconds);
                }

                double max = double.MinValue;
                double min = double.MaxValue;
                foreach (var x in res)
                {
                    if (max < x)
                    {
                        max = x;
                    }

                    if (min > x)
                    {
                        min = x;
                    }
                }

                return (res.Where(x =>

                    // ReSharper disable once CompareOfFloatsByEqualityOperator
                    x != max

                    // ReSharper disable once CompareOfFloatsByEqualityOperator
                    && x != min).Average(), password, ret);
            }

            for (int parallelism = 1; parallelism <= 20; ++parallelism)
            {
                var (tick, pw, hash) = Check5(parallelism);
                Console.WriteLine($"Parallelism {parallelism:D2}: {tick:F3} seconds, \"{pw}\" => {hash}");
            }

            return "TestTimeToHash: Passed";
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
                TestArgon2AgainstReference(),
                TestFromDraft(),
                TestHighMemoryCost(),
                TestTimeToHash(),
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

        private static bool TestVectorBasicCheck(int checkNumber, Argon2TestVectorType.TestVector argon2TestVector)
        {
            var nl = Environment.NewLine;
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

                var text = Argon2.Hash(config);
                if (string.CompareOrdinal(text, argon2TestVector.EncodedTag) == 0)
                {
                    Console.WriteLine(
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
                Console.WriteLine($"Test x: {e.Message} ({e.GetType()})");
            }

            return true;
        }

        private static bool TestVectorBasicCheck(Argon2TestVector argon2TestVector)
        {
            var nl = Environment.NewLine;
            var encoded = new StringBuilder();
            try
            {
                var argon2 = new Argon2(argon2TestVector.Config);
                SecureArray<byte> hash = argon2.Hash();
                if (!hash.Buffer.Where((b, i) => b != argon2TestVector.Tag[i]).Any())
                {
                    var text = Argon2.Hash(argon2TestVector.Config);
                    if (string.CompareOrdinal(text, argon2TestVector.TagText) == 0)
                    {
                        Console.WriteLine(
                            $"Test {argon2TestVector.Name} passed:{nl}"
                            + $"             Version 0x{(int)argon2TestVector.Version:X} ({(int)argon2TestVector.Version}){nl}"
                            + $"                Type {argon2TestVector.Type}{nl}"
                            + $"          Iterations {argon2TestVector.Iterations}{nl}"
                            + $"       Memory KBytes {argon2TestVector.MemoryKBytes}{nl}"
                            + $"         Parallelism {argon2TestVector.Parallelism}{nl}"
                            + $"            Password {BitConverter.ToString(argon2TestVector.Password)}{nl}"
                            + $"                Salt {BitConverter.ToString(argon2TestVector.Salt)}{nl}"
                            + $"              Secret {BitConverter.ToString(argon2TestVector.Secret)}{nl}"
                            + $"      AssociatedData {BitConverter.ToString(argon2TestVector.AssociatedData)}{nl}"
                            + $"  Gave expected hash {BitConverter.ToString(hash.Buffer)}{nl}"
                            + $"             encoded {text}");
                    }
                    else
                    {
                        Console.WriteLine(
                            $"Test {argon2TestVector.Name}: Got{nl}" +
                            $"  {text}{nl}" +
                            $"expected{nl}" +
                            $"  {argon2TestVector.TagText}");
                        return false;
                    }
                }
                else
                {
                    Console.WriteLine(
                        $"Test {argon2TestVector.Name}: Got{nl}" +
                        $"  {BitConverter.ToString(hash.Buffer)}{nl}" +
                        $"expected{nl}" +
                        $"  {BitConverter.ToString(argon2TestVector.Tag)}");
                    return false;
                }
            }

            // ReSharper disable once CatchAllClause
            catch (Exception e)
            {
                Console.WriteLine($"Test {argon2TestVector.Name}: {e.Message} ({e.GetType()})");
            }

            return true;
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
                this.Config = new Argon2Config
                {
                    Type = type,
                    Version = version,
                    TimeCost = iterations,
                    MemoryCost = memoryKBytes,
                    Lanes = parallelism,
                    Threads = parallelism,
                    Password = this.Password,
                    Salt = this.Salt,
                    Secret = this.Secret,
                    AssociatedData = this.AssociatedData,
                    HashLength = this.TagLength,
                };
                this.TagText = this.Config.EncodeString(this.Tag);
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
            /// Gets the config based on the fields.
            /// </summary>
            public Argon2Config Config { get; }

            /// <summary>
            /// Gets the encoded tag.
            /// </summary>
            public string TagText { get; }

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
                    if (ch is >= '0' and <= '9')
                    {
                        val = (byte)((uint)(ch - '0') << 4);
                    }
                    else if (ch is >= 'a' and <= 'f')
                    {
                        val = (byte)((uint)(ch - 'a' + 10) << 4);
                    }
                    else if (ch is >= 'A' and <= 'F')
                    {
                        val = (byte)((uint)(ch - 'A' + 10) << 4);
                    }
                    else
                    {
                        throw new ArgumentException($"Invalid character '{ch}' found in hex string");
                    }

                    if (cl is >= '0' and <= '9')
                    {
                        val += (byte)(uint)(cl - '0');
                    }
                    else if (cl is >= 'a' and <= 'f')
                    {
                        val += (byte)(uint)(cl - 'a' + 10);
                    }
                    else if (cl is >= 'A' and <= 'F')
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
                : base(NoZeroMemory, NoLockMemory, NoUnlockMemory, "No OS (insecure)")
            {
            }

            private static void NoZeroMemory(IntPtr buf, UIntPtr len)
            {
            }

            private static string NoLockMemory(IntPtr buf, UIntPtr len)
            {
                return null;
            }

            private static void NoUnlockMemory(IntPtr buf, UIntPtr len)
            {
            }
        }
    }
}
