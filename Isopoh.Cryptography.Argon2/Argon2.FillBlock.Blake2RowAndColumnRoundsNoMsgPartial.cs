// <copyright file="Argon2.FillBlock.Blake2RowAndColumnRoundsNoMsgPartial.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2
{
    /// <summary>
    /// Argon2 Hashing of passwords
    /// </summary>
    public partial class Argon2
    {
        private static void Blake2ColumnRoundNoMsg2(BlockValues blockR, int i7)
        {
            ulong v0;
            ulong v1;
            ulong v2;
            ulong v3;
            ulong v4;
            ulong v5;
            ulong v6;
            ulong v7;
            ulong v8;
            ulong v9;
            ulong v10;
            ulong v11;
            ulong v12;
            ulong v13;
            ulong v14;
            ulong v15;

            v0 = blockR[16 * i7];
            v1 = blockR[(16 * i7) + 1];
            v2 = blockR[(16 * i7) + 2];
            v3 = blockR[(16 * i7) + 3];
            v4 = blockR[(16 * i7) + 4];
            v5 = blockR[(16 * i7) + 5];
            v6 = blockR[(16 * i7) + 6];
            v7 = blockR[(16 * i7) + 7];
            v8 = blockR[(16 * i7) + 8];
            v9 = blockR[(16 * i7) + 9];
            v10 = blockR[(16 * i7) + 10];
            v11 = blockR[(16 * i7) + 11];
            v12 = blockR[(16 * i7) + 12];
            v13 = blockR[(16 * i7) + 13];
            v14 = blockR[(16 * i7) + 14];
            v15 = blockR[(16 * i7) + 15];

            // G(ref v0, ref v4, ref v8, ref v12);
            v0 = v0 + v4 + (2 * (v0 & 0xFFFFFFFF) * (v4 & 0xFFFFFFFF));
            ulong tmp = v12 ^ v0;
            v12 = (tmp >> 32) | (tmp << 32);
            v8 = v8 + v12 + (2 * (v8 & 0xFFFFFFFF) * (v12 & 0xFFFFFFFF));
            tmp = v4 ^ v8;
            v4 = (tmp >> 24) | (tmp << 40);
            v0 = v0 + v4 + (2 * (v0 & 0xFFFFFFFF) * (v4 & 0xFFFFFFFF));
            tmp = v12 ^ v0;
            v12 = (tmp >> 16) | (tmp << 48);
            v8 = v8 + v12 + (2 * (v8 & 0xFFFFFFFF) * (v12 & 0xFFFFFFFF));
            tmp = v4 ^ v8;
            v4 = (tmp >> 63) | (tmp << 1);

            // G(ref v1, ref v5, ref v9, ref v13);
            v1 = v1 + v5 + (2 * (v1 & 0xFFFFFFFF) * (v5 & 0xFFFFFFFF));
            tmp = v13 ^ v1;
            v13 = (tmp >> 32) | (tmp << 32);
            v9 = v9 + v13 + (2 * (v9 & 0xFFFFFFFF) * (v13 & 0xFFFFFFFF));
            tmp = v5 ^ v9;
            v5 = (tmp >> 24) | (tmp << 40);
            v1 = v1 + v5 + (2 * (v1 & 0xFFFFFFFF) * (v5 & 0xFFFFFFFF));
            tmp = v13 ^ v1;
            v13 = (tmp >> 16) | (tmp << 48);
            v9 = v9 + v13 + (2 * (v9 & 0xFFFFFFFF) * (v13 & 0xFFFFFFFF));
            tmp = v5 ^ v9;
            v5 = (tmp >> 63) | (tmp << 1);

            // G(ref v2, ref v6, ref v10, ref v14);
            v2 = v2 + v6 + (2 * (v2 & 0xFFFFFFFF) * (v6 & 0xFFFFFFFF));
            tmp = v14 ^ v2;
            v14 = (tmp >> 32) | (tmp << 32);
            v10 = v10 + v14 + (2 * (v10 & 0xFFFFFFFF) * (v14 & 0xFFFFFFFF));
            tmp = v6 ^ v10;
            v6 = (tmp >> 24) | (tmp << 40);
            v2 = v2 + v6 + (2 * (v2 & 0xFFFFFFFF) * (v6 & 0xFFFFFFFF));
            tmp = v14 ^ v2;
            v14 = (tmp >> 16) | (tmp << 48);
            v10 = v10 + v14 + (2 * (v10 & 0xFFFFFFFF) * (v14 & 0xFFFFFFFF));
            tmp = v6 ^ v10;
            v6 = (tmp >> 63) | (tmp << 1);

            // G(ref v3, ref v7, ref v11, ref v15);
            v3 = v3 + v7 + (2 * (v3 & 0xFFFFFFFF) * (v7 & 0xFFFFFFFF));
            tmp = v15 ^ v3;
            v15 = (tmp >> 32) | (tmp << 32);
            v11 = v11 + v15 + (2 * (v11 & 0xFFFFFFFF) * (v15 & 0xFFFFFFFF));
            tmp = v7 ^ v11;
            v7 = (tmp >> 24) | (tmp << 40);
            v3 = v3 + v7 + (2 * (v3 & 0xFFFFFFFF) * (v7 & 0xFFFFFFFF));
            tmp = v15 ^ v3;
            v15 = (tmp >> 16) | (tmp << 48);
            v11 = v11 + v15 + (2 * (v11 & 0xFFFFFFFF) * (v15 & 0xFFFFFFFF));
            tmp = v7 ^ v11;
            v7 = (tmp >> 63) | (tmp << 1);

            // G(ref v0, ref v5, ref v10, ref v15);
            v0 = v0 + v5 + (2 * (v0 & 0xFFFFFFFF) * (v5 & 0xFFFFFFFF));
            tmp = v15 ^ v0;
            v15 = (tmp >> 32) | (tmp << 32);
            v10 = v10 + v15 + (2 * (v10 & 0xFFFFFFFF) * (v15 & 0xFFFFFFFF));
            tmp = v5 ^ v10;
            v5 = (tmp >> 24) | (tmp << 40);
            v0 = v0 + v5 + (2 * (v0 & 0xFFFFFFFF) * (v5 & 0xFFFFFFFF));
            tmp = v15 ^ v0;
            v15 = (tmp >> 16) | (tmp << 48);
            v10 = v10 + v15 + (2 * (v10 & 0xFFFFFFFF) * (v15 & 0xFFFFFFFF));
            tmp = v5 ^ v10;
            v5 = (tmp >> 63) | (tmp << 1);

            // G(ref v1, ref v6, ref v11, ref v12);
            v1 = v1 + v6 + (2 * (v1 & 0xFFFFFFFF) * (v6 & 0xFFFFFFFF));
            tmp = v12 ^ v1;
            v12 = (tmp >> 32) | (tmp << 32);
            v11 = v11 + v12 + (2 * (v11 & 0xFFFFFFFF) * (v12 & 0xFFFFFFFF));
            tmp = v6 ^ v11;
            v6 = (tmp >> 24) | (tmp << 40);
            v1 = v1 + v6 + (2 * (v1 & 0xFFFFFFFF) * (v6 & 0xFFFFFFFF));
            tmp = v12 ^ v1;
            v12 = (tmp >> 16) | (tmp << 48);
            v11 = v11 + v12 + (2 * (v11 & 0xFFFFFFFF) * (v12 & 0xFFFFFFFF));
            tmp = v6 ^ v11;
            v6 = (tmp >> 63) | (tmp << 1);

            // G(ref v2, ref v7, ref v8, ref v13);
            v2 = v2 + v7 + (2 * (v2 & 0xFFFFFFFF) * (v7 & 0xFFFFFFFF));
            tmp = v13 ^ v2;
            v13 = (tmp >> 32) | (tmp << 32);
            v8 = v8 + v13 + (2 * (v8 & 0xFFFFFFFF) * (v13 & 0xFFFFFFFF));
            tmp = v7 ^ v8;
            v7 = (tmp >> 24) | (tmp << 40);
            v2 = v2 + v7 + (2 * (v2 & 0xFFFFFFFF) * (v7 & 0xFFFFFFFF));
            tmp = v13 ^ v2;
            v13 = (tmp >> 16) | (tmp << 48);
            v8 = v8 + v13 + (2 * (v8 & 0xFFFFFFFF) * (v13 & 0xFFFFFFFF));
            tmp = v7 ^ v8;
            v7 = (tmp >> 63) | (tmp << 1);

            // G(ref v3, ref v4, ref v9, ref v14);
            v3 = v3 + v4 + (2 * (v3 & 0xFFFFFFFF) * (v4 & 0xFFFFFFFF));
            tmp = v14 ^ v3;
            v14 = (tmp >> 32) | (tmp << 32);
            v9 = v9 + v14 + (2 * (v9 & 0xFFFFFFFF) * (v14 & 0xFFFFFFFF));
            tmp = v4 ^ v9;
            v4 = (tmp >> 24) | (tmp << 40);
            v3 = v3 + v4 + (2 * (v3 & 0xFFFFFFFF) * (v4 & 0xFFFFFFFF));
            tmp = v14 ^ v3;
            v14 = (tmp >> 16) | (tmp << 48);
            v9 = v9 + v14 + (2 * (v9 & 0xFFFFFFFF) * (v14 & 0xFFFFFFFF));
            tmp = v4 ^ v9;
            v4 = (tmp >> 63) | (tmp << 1);
            blockR[16 * i7] = v0;
            blockR[(16 * i7) + 1] = v1;
            blockR[(16 * i7) + 2] = v2;
            blockR[(16 * i7) + 3] = v3;
            blockR[(16 * i7) + 4] = v4;
            blockR[(16 * i7) + 5] = v5;
            blockR[(16 * i7) + 6] = v6;
            blockR[(16 * i7) + 7] = v7;
            blockR[(16 * i7) + 8] = v8;
            blockR[(16 * i7) + 9] = v9;
            blockR[(16 * i7) + 10] = v10;
            blockR[(16 * i7) + 11] = v11;
            blockR[(16 * i7) + 12] = v12;
            blockR[(16 * i7) + 13] = v13;
            blockR[(16 * i7) + 14] = v14;
            blockR[(16 * i7) + 15] = v15;
        }

        private static void Blake2RowRoundNoMsg2(BlockValues blockR, int i7)
        {
            ulong v0;
            ulong v1;
            ulong v2;
            ulong v3;
            ulong v4;
            ulong v5;
            ulong v6;
            ulong v7;
            ulong v8;
            ulong v9;
            ulong v10;
            ulong v11;
            ulong v12;
            ulong v13;
            ulong v14;
            ulong v15;
            ulong tmp;
            v0 = blockR[2 * i7];
            v1 = blockR[(2 * i7) + 1];
            v2 = blockR[(2 * i7) + 16];
            v3 = blockR[(2 * i7) + 17];
            v4 = blockR[(2 * i7) + 32];
            v5 = blockR[(2 * i7) + 33];
            v6 = blockR[(2 * i7) + 48];
            v7 = blockR[(2 * i7) + 49];
            v8 = blockR[(2 * i7) + 64];
            v9 = blockR[(2 * i7) + 65];
            v10 = blockR[(2 * i7) + 80];
            v11 = blockR[(2 * i7) + 81];
            v12 = blockR[(2 * i7) + 96];
            v13 = blockR[(2 * i7) + 97];
            v14 = blockR[(2 * i7) + 112];
            v15 = blockR[(2 * i7) + 113];

            // G(ref v0, ref v4, ref v8, ref v12);
            v0 = v0 + v4 + (2 * (v0 & 0xFFFFFFFF) * (v4 & 0xFFFFFFFF));
            tmp = v12 ^ v0;
            v12 = (tmp >> 32) | (tmp << 32);
            v8 = v8 + v12 + (2 * (v8 & 0xFFFFFFFF) * (v12 & 0xFFFFFFFF));
            tmp = v4 ^ v8;
            v4 = (tmp >> 24) | (tmp << 40);
            v0 = v0 + v4 + (2 * (v0 & 0xFFFFFFFF) * (v4 & 0xFFFFFFFF));
            tmp = v12 ^ v0;
            v12 = (tmp >> 16) | (tmp << 48);
            v8 = v8 + v12 + (2 * (v8 & 0xFFFFFFFF) * (v12 & 0xFFFFFFFF));
            tmp = v4 ^ v8;
            v4 = (tmp >> 63) | (tmp << 1);

            // G(ref v1, ref v5, ref v9, ref v13);
            v1 = v1 + v5 + (2 * (v1 & 0xFFFFFFFF) * (v5 & 0xFFFFFFFF));
            tmp = v13 ^ v1;
            v13 = (tmp >> 32) | (tmp << 32);
            v9 = v9 + v13 + (2 * (v9 & 0xFFFFFFFF) * (v13 & 0xFFFFFFFF));
            tmp = v5 ^ v9;
            v5 = (tmp >> 24) | (tmp << 40);
            v1 = v1 + v5 + (2 * (v1 & 0xFFFFFFFF) * (v5 & 0xFFFFFFFF));
            tmp = v13 ^ v1;
            v13 = (tmp >> 16) | (tmp << 48);
            v9 = v9 + v13 + (2 * (v9 & 0xFFFFFFFF) * (v13 & 0xFFFFFFFF));
            tmp = v5 ^ v9;
            v5 = (tmp >> 63) | (tmp << 1);

            // G(ref v2, ref v6, ref v10, ref v14);
            v2 = v2 + v6 + (2 * (v2 & 0xFFFFFFFF) * (v6 & 0xFFFFFFFF));
            tmp = v14 ^ v2;
            v14 = (tmp >> 32) | (tmp << 32);
            v10 = v10 + v14 + (2 * (v10 & 0xFFFFFFFF) * (v14 & 0xFFFFFFFF));
            tmp = v6 ^ v10;
            v6 = (tmp >> 24) | (tmp << 40);
            v2 = v2 + v6 + (2 * (v2 & 0xFFFFFFFF) * (v6 & 0xFFFFFFFF));
            tmp = v14 ^ v2;
            v14 = (tmp >> 16) | (tmp << 48);
            v10 = v10 + v14 + (2 * (v10 & 0xFFFFFFFF) * (v14 & 0xFFFFFFFF));
            tmp = v6 ^ v10;
            v6 = (tmp >> 63) | (tmp << 1);

            // G(ref v3, ref v7, ref v11, ref v15);
            v3 = v3 + v7 + (2 * (v3 & 0xFFFFFFFF) * (v7 & 0xFFFFFFFF));
            tmp = v15 ^ v3;
            v15 = (tmp >> 32) | (tmp << 32);
            v11 = v11 + v15 + (2 * (v11 & 0xFFFFFFFF) * (v15 & 0xFFFFFFFF));
            tmp = v7 ^ v11;
            v7 = (tmp >> 24) | (tmp << 40);
            v3 = v3 + v7 + (2 * (v3 & 0xFFFFFFFF) * (v7 & 0xFFFFFFFF));
            tmp = v15 ^ v3;
            v15 = (tmp >> 16) | (tmp << 48);
            v11 = v11 + v15 + (2 * (v11 & 0xFFFFFFFF) * (v15 & 0xFFFFFFFF));
            tmp = v7 ^ v11;
            v7 = (tmp >> 63) | (tmp << 1);

            // G(ref v0, ref v5, ref v10, ref v15);
            v0 = v0 + v5 + (2 * (v0 & 0xFFFFFFFF) * (v5 & 0xFFFFFFFF));
            tmp = v15 ^ v0;
            v15 = (tmp >> 32) | (tmp << 32);
            v10 = v10 + v15 + (2 * (v10 & 0xFFFFFFFF) * (v15 & 0xFFFFFFFF));
            tmp = v5 ^ v10;
            v5 = (tmp >> 24) | (tmp << 40);
            v0 = v0 + v5 + (2 * (v0 & 0xFFFFFFFF) * (v5 & 0xFFFFFFFF));
            tmp = v15 ^ v0;
            v15 = (tmp >> 16) | (tmp << 48);
            v10 = v10 + v15 + (2 * (v10 & 0xFFFFFFFF) * (v15 & 0xFFFFFFFF));
            tmp = v5 ^ v10;
            v5 = (tmp >> 63) | (tmp << 1);

            // G(ref v1, ref v6, ref v11, ref v12);
            v1 = v1 + v6 + (2 * (v1 & 0xFFFFFFFF) * (v6 & 0xFFFFFFFF));
            tmp = v12 ^ v1;
            v12 = (tmp >> 32) | (tmp << 32);
            v11 = v11 + v12 + (2 * (v11 & 0xFFFFFFFF) * (v12 & 0xFFFFFFFF));
            tmp = v6 ^ v11;
            v6 = (tmp >> 24) | (tmp << 40);
            v1 = v1 + v6 + (2 * (v1 & 0xFFFFFFFF) * (v6 & 0xFFFFFFFF));
            tmp = v12 ^ v1;
            v12 = (tmp >> 16) | (tmp << 48);
            v11 = v11 + v12 + (2 * (v11 & 0xFFFFFFFF) * (v12 & 0xFFFFFFFF));
            tmp = v6 ^ v11;
            v6 = (tmp >> 63) | (tmp << 1);

            // G(ref v2, ref v7, ref v8, ref v13);
            v2 = v2 + v7 + (2 * (v2 & 0xFFFFFFFF) * (v7 & 0xFFFFFFFF));
            tmp = v13 ^ v2;
            v13 = (tmp >> 32) | (tmp << 32);
            v8 = v8 + v13 + (2 * (v8 & 0xFFFFFFFF) * (v13 & 0xFFFFFFFF));
            tmp = v7 ^ v8;
            v7 = (tmp >> 24) | (tmp << 40);
            v2 = v2 + v7 + (2 * (v2 & 0xFFFFFFFF) * (v7 & 0xFFFFFFFF));
            tmp = v13 ^ v2;
            v13 = (tmp >> 16) | (tmp << 48);
            v8 = v8 + v13 + (2 * (v8 & 0xFFFFFFFF) * (v13 & 0xFFFFFFFF));
            tmp = v7 ^ v8;
            v7 = (tmp >> 63) | (tmp << 1);

            // G(ref v3, ref v4, ref v9, ref v14);
            v3 = v3 + v4 + (2 * (v3 & 0xFFFFFFFF) * (v4 & 0xFFFFFFFF));
            tmp = v14 ^ v3;
            v14 = (tmp >> 32) | (tmp << 32);
            v9 = v9 + v14 + (2 * (v9 & 0xFFFFFFFF) * (v14 & 0xFFFFFFFF));
            tmp = v4 ^ v9;
            v4 = (tmp >> 24) | (tmp << 40);
            v3 = v3 + v4 + (2 * (v3 & 0xFFFFFFFF) * (v4 & 0xFFFFFFFF));
            tmp = v14 ^ v3;
            v14 = (tmp >> 16) | (tmp << 48);
            v9 = v9 + v14 + (2 * (v9 & 0xFFFFFFFF) * (v14 & 0xFFFFFFFF));
            tmp = v4 ^ v9;
            v4 = (tmp >> 63) | (tmp << 1);
            blockR[2 * i7] = v0;
            blockR[(2 * i7) + 1] = v1;
            blockR[(2 * i7) + 16] = v2;
            blockR[(2 * i7) + 17] = v3;
            blockR[(2 * i7) + 32] = v4;
            blockR[(2 * i7) + 33] = v5;
            blockR[(2 * i7) + 48] = v6;
            blockR[(2 * i7) + 49] = v7;
            blockR[(2 * i7) + 64] = v8;
            blockR[(2 * i7) + 65] = v9;
            blockR[(2 * i7) + 80] = v10;
            blockR[(2 * i7) + 81] = v11;
            blockR[(2 * i7) + 96] = v12;
            blockR[(2 * i7) + 97] = v13;
            blockR[(2 * i7) + 112] = v14;
            blockR[(2 * i7) + 113] = v15;
        }

        private static void Blake2RowAndColumnRoundsNoMsgPartial(BlockValues blockR)
        {
            // TODO: figure out and lift the code from Blake2BCore-FullyUnrolled.cs
            // apply Blake2 on columns of 64-bit words:
            //    (0,1,...,15), then
            //    (16,17,..31)... finally
            //    (112,113,...127)
            for (int i = 0; i < 8; ++i)
            {
                Blake2ColumnRoundNoMsg(blockR, i);
            }

            // Apply Blake2 on rows of 64-bit words:
            // (0,1,16,17,...112,113), then
            // (2,3,18,19,...,114,115).. finally
            // (14,15,30,31,...,126,127)
            for (int i = 0; i < 8; ++i)
            {
                Blake2RowRoundNoMsg(blockR, i);
            }
        }
    }
}
