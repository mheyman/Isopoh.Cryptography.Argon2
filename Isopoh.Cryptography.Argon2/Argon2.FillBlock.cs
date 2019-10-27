// <copyright file="Argon2.FillBlock.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2
{
    /// <summary>
    /// Argon2 Hashing of passwords.
    /// </summary>
    public sealed partial class Argon2
    {
        private static ulong FblaMka(ulong x, ulong y)
        {
            return x + y + (2 * (x & 0xFFFFFFFF) * (y & 0xFFFFFFFF));
        }

        private static ulong Rotr64(ulong original, int bits)
        {
            return (original >> bits) | (original << (64 - bits));
        }

        private static void G(ref ulong a, ref ulong b, ref ulong c, ref ulong d)
        {
            a = FblaMka(a, b);
            d = Rotr64(d ^ a, 32);
            c = FblaMka(c, d);
            b = Rotr64(b ^ c, 24);
            a = FblaMka(a, b);
            d = Rotr64(d ^ a, 16);
            c = FblaMka(c, d);
            b = Rotr64(b ^ c, 63);
        }

        private static void BlakeRoundNoMsg(
            ref ulong v0,
            ref ulong v1,
            ref ulong v2,
            ref ulong v3,
            ref ulong v4,
            ref ulong v5,
            ref ulong v6,
            ref ulong v7,
            ref ulong v8,
            ref ulong v9,
            ref ulong v10,
            ref ulong v11,
            ref ulong v12,
            ref ulong v13,
            ref ulong v14,
            ref ulong v15)
        {
            G(ref v0, ref v4, ref v8, ref v12);
            G(ref v1, ref v5, ref v9, ref v13);
            G(ref v2, ref v6, ref v10, ref v14);
            G(ref v3, ref v7, ref v11, ref v15);
            G(ref v0, ref v5, ref v10, ref v15);
            G(ref v1, ref v6, ref v11, ref v12);
            G(ref v2, ref v7, ref v8, ref v13);
            G(ref v3, ref v4, ref v9, ref v14);
        }

        private static void FillBlock(BlockValues prevBlock, BlockValues refBlock, BlockValues nextBlock)
        {
            // TODO: figure out and lift the code from Blake2BCore-FullyUnrolled.cs
            var buf = new ulong[QwordsInBlock * 2];
            var blockR = new BlockValues(buf, 0);
            var blockTmp = new BlockValues(buf, 1);
            blockR.Copy(refBlock);
            blockR.Xor(prevBlock);
            blockTmp.Copy(blockR);

            // apply Blake2 on columns of 64-bit words:
            //    (0,1,...,15), then
            //    (16,17,..31)... finally
            //    (112,113,...127)
            for (int i = 0; i < 8; ++i)
            {
                ulong v0 = blockR[16 * i];
                ulong v1 = blockR[(16 * i) + 1];
                ulong v2 = blockR[(16 * i) + 2];
                ulong v3 = blockR[(16 * i) + 3];
                ulong v4 = blockR[(16 * i) + 4];
                ulong v5 = blockR[(16 * i) + 5];
                ulong v6 = blockR[(16 * i) + 6];
                ulong v7 = blockR[(16 * i) + 7];
                ulong v8 = blockR[(16 * i) + 8];
                ulong v9 = blockR[(16 * i) + 9];
                ulong v10 = blockR[(16 * i) + 10];
                ulong v11 = blockR[(16 * i) + 11];
                ulong v12 = blockR[(16 * i) + 12];
                ulong v13 = blockR[(16 * i) + 13];
                ulong v14 = blockR[(16 * i) + 14];
                ulong v15 = blockR[(16 * i) + 15];
                BlakeRoundNoMsg(
                    ref v0,
                    ref v1,
                    ref v2,
                    ref v3,
                    ref v4,
                    ref v5,
                    ref v6,
                    ref v7,
                    ref v8,
                    ref v9,
                    ref v10,
                    ref v11,
                    ref v12,
                    ref v13,
                    ref v14,
                    ref v15);
                blockR[16 * i] = v0;
                blockR[(16 * i) + 1] = v1;
                blockR[(16 * i) + 2] = v2;
                blockR[(16 * i) + 3] = v3;
                blockR[(16 * i) + 4] = v4;
                blockR[(16 * i) + 5] = v5;
                blockR[(16 * i) + 6] = v6;
                blockR[(16 * i) + 7] = v7;
                blockR[(16 * i) + 8] = v8;
                blockR[(16 * i) + 9] = v9;
                blockR[(16 * i) + 10] = v10;
                blockR[(16 * i) + 11] = v11;
                blockR[(16 * i) + 12] = v12;
                blockR[(16 * i) + 13] = v13;
                blockR[(16 * i) + 14] = v14;
                blockR[(16 * i) + 15] = v15;
            }

            // Apply Blake2 on rows of 64-bit words:
            // (0,1,16,17,...112,113), then
            // (2,3,18,19,...,114,115).. finally
            // (14,15,30,31,...,126,127)
            for (int i = 0; i < 8; ++i)
            {
                ulong v0 = blockR[2 * i];
                ulong v1 = blockR[(2 * i) + 1];
                ulong v2 = blockR[(2 * i) + 16];
                ulong v3 = blockR[(2 * i) + 17];
                ulong v4 = blockR[(2 * i) + 32];
                ulong v5 = blockR[(2 * i) + 33];
                ulong v6 = blockR[(2 * i) + 48];
                ulong v7 = blockR[(2 * i) + 49];
                ulong v8 = blockR[(2 * i) + 64];
                ulong v9 = blockR[(2 * i) + 65];
                ulong v10 = blockR[(2 * i) + 80];
                ulong v11 = blockR[(2 * i) + 81];
                ulong v12 = blockR[(2 * i) + 96];
                ulong v13 = blockR[(2 * i) + 97];
                ulong v14 = blockR[(2 * i) + 112];
                ulong v15 = blockR[(2 * i) + 113];
                BlakeRoundNoMsg(
                    ref v0,
                    ref v1,
                    ref v2,
                    ref v3,
                    ref v4,
                    ref v5,
                    ref v6,
                    ref v7,
                    ref v8,
                    ref v9,
                    ref v10,
                    ref v11,
                    ref v12,
                    ref v13,
                    ref v14,
                    ref v15);
                blockR[2 * i] = v0;
                blockR[(2 * i) + 1] = v1;
                blockR[(2 * i) + 16] = v2;
                blockR[(2 * i) + 17] = v3;
                blockR[(2 * i) + 32] = v4;
                blockR[(2 * i) + 33] = v5;
                blockR[(2 * i) + 48] = v6;
                blockR[(2 * i) + 49] = v7;
                blockR[(2 * i) + 64] = v8;
                blockR[(2 * i) + 65] = v9;
                blockR[(2 * i) + 80] = v10;
                blockR[(2 * i) + 81] = v11;
                blockR[(2 * i) + 96] = v12;
                blockR[(2 * i) + 97] = v13;
                blockR[(2 * i) + 112] = v14;
                blockR[(2 * i) + 113] = v15;
            }

            nextBlock.Copy(blockTmp);
            nextBlock.Xor(blockR);
        }

        private static void FillBlockWithXor(BlockValues prevBlock, BlockValues refBlock, BlockValues nextBlock)
        {
            var buf = new ulong[QwordsInBlock * 2];
            var blockR = new BlockValues(buf, 0);
            var blockTmp = new BlockValues(buf, 1);
            blockR.Copy(refBlock);
            blockR.Xor(prevBlock);
            blockTmp.Copy(blockR);
            blockTmp.Xor(nextBlock); // saving the next block for XOR over

            // apply Blake2 on columns of 64-bit words:
            //    (0,1,...,15), then
            //    (16,17,..31)... finally
            //    (112,113,...127)
            for (int i = 0; i < 8; ++i)
            {
                ulong v0 = blockR[16 * i];
                ulong v1 = blockR[(16 * i) + 1];
                ulong v2 = blockR[(16 * i) + 2];
                ulong v3 = blockR[(16 * i) + 3];
                ulong v4 = blockR[(16 * i) + 4];
                ulong v5 = blockR[(16 * i) + 5];
                ulong v6 = blockR[(16 * i) + 6];
                ulong v7 = blockR[(16 * i) + 7];
                ulong v8 = blockR[(16 * i) + 8];
                ulong v9 = blockR[(16 * i) + 9];
                ulong v10 = blockR[(16 * i) + 10];
                ulong v11 = blockR[(16 * i) + 11];
                ulong v12 = blockR[(16 * i) + 12];
                ulong v13 = blockR[(16 * i) + 13];
                ulong v14 = blockR[(16 * i) + 14];
                ulong v15 = blockR[(16 * i) + 15];
                BlakeRoundNoMsg(
                    ref v0,
                    ref v1,
                    ref v2,
                    ref v3,
                    ref v4,
                    ref v5,
                    ref v6,
                    ref v7,
                    ref v8,
                    ref v9,
                    ref v10,
                    ref v11,
                    ref v12,
                    ref v13,
                    ref v14,
                    ref v15);
                blockR[16 * i] = v0;
                blockR[(16 * i) + 1] = v1;
                blockR[(16 * i) + 2] = v2;
                blockR[(16 * i) + 3] = v3;
                blockR[(16 * i) + 4] = v4;
                blockR[(16 * i) + 5] = v5;
                blockR[(16 * i) + 6] = v6;
                blockR[(16 * i) + 7] = v7;
                blockR[(16 * i) + 8] = v8;
                blockR[(16 * i) + 9] = v9;
                blockR[(16 * i) + 10] = v10;
                blockR[(16 * i) + 11] = v11;
                blockR[(16 * i) + 12] = v12;
                blockR[(16 * i) + 13] = v13;
                blockR[(16 * i) + 14] = v14;
                blockR[(16 * i) + 15] = v15;
            }

            // Apply Blake2 on rows of 64-bit words:
            // (0,1,16,17,...112,113), then
            // (2,3,18,19,...,114,115).. finally
            // (14,15,30,31,...,126,127)
            for (int i = 0; i < 8; ++i)
            {
                ulong v0 = blockR[2 * i];
                ulong v1 = blockR[(2 * i) + 1];
                ulong v2 = blockR[(2 * i) + 16];
                ulong v3 = blockR[(2 * i) + 17];
                ulong v4 = blockR[(2 * i) + 32];
                ulong v5 = blockR[(2 * i) + 33];
                ulong v6 = blockR[(2 * i) + 48];
                ulong v7 = blockR[(2 * i) + 49];
                ulong v8 = blockR[(2 * i) + 64];
                ulong v9 = blockR[(2 * i) + 65];
                ulong v10 = blockR[(2 * i) + 80];
                ulong v11 = blockR[(2 * i) + 81];
                ulong v12 = blockR[(2 * i) + 96];
                ulong v13 = blockR[(2 * i) + 97];
                ulong v14 = blockR[(2 * i) + 112];
                ulong v15 = blockR[(2 * i) + 113];
                BlakeRoundNoMsg(
                    ref v0,
                    ref v1,
                    ref v2,
                    ref v3,
                    ref v4,
                    ref v5,
                    ref v6,
                    ref v7,
                    ref v8,
                    ref v9,
                    ref v10,
                    ref v11,
                    ref v12,
                    ref v13,
                    ref v14,
                    ref v15);
                blockR[2 * i] = v0;
                blockR[(2 * i) + 1] = v1;
                blockR[(2 * i) + 16] = v2;
                blockR[(2 * i) + 17] = v3;
                blockR[(2 * i) + 32] = v4;
                blockR[(2 * i) + 33] = v5;
                blockR[(2 * i) + 48] = v6;
                blockR[(2 * i) + 49] = v7;
                blockR[(2 * i) + 64] = v8;
                blockR[(2 * i) + 65] = v9;
                blockR[(2 * i) + 80] = v10;
                blockR[(2 * i) + 81] = v11;
                blockR[(2 * i) + 96] = v12;
                blockR[(2 * i) + 97] = v13;
                blockR[(2 * i) + 112] = v14;
                blockR[(2 * i) + 113] = v15;
            }

            nextBlock.Copy(blockTmp);
            nextBlock.Xor(blockR);
        }
    }
}