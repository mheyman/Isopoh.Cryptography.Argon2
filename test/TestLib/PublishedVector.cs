// <copyright file="PublishedVector.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace TestLib;
using Isopoh.Cryptography.Argon2;
using Xunit.Abstractions;

/// <summary>
/// Has a test that validates the hash against published test vectors.
/// </summary>
public static class PublishedVector
{
    /// <summary>
    /// Test vectors for Argon2. From https://github.com/P-H-C/phc-winner-argon2/tree/master/kats.
    /// </summary>
    public static readonly Argon2TestVector[] Argon2TestVectors =
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

    /// <summary>
    /// Test <see cref="Argon2"/>.
    /// </summary>
    /// <param name="output">Used to write output.</param>
    /// <returns>
    /// Tuple with a bool indicating pass or fail and associated text detail.
    /// </returns>
    public static (bool, string) Test(ITestOutputHelper output)
    {
        bool passed = Argon2TestVectors.Aggregate(true, (current, testVector) => current && testVector.Validate(output));
        string res = passed ? "Argon2 Passed" : "Argon2 FAILED";
        return (passed, res);
    }
}
