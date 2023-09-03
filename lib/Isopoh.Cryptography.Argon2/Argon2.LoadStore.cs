// <copyright file="Argon2.LoadStore.cs" company="Isopoh">
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
        private static void Store32(byte[] buf, uint value)
        {
            buf[0] = (byte)value;
            buf[1] = (byte)(value >> 8);
            buf[2] = (byte)(value >> 16);
            buf[3] = (byte)(value >> 24);
        }

        private static void Store32(byte[] buf, int value)
        {
            buf[0] = (byte)value;
            buf[1] = (byte)((uint)value >> 8);
            buf[2] = (byte)((uint)value >> 16);
            buf[3] = (byte)((uint)value >> 24);
        }

        private static void Store32(byte[] buf, int offset, int value)
        {
            buf[0 + offset] = (byte)value;
            buf[1 + offset] = (byte)((uint)value >> 8);
            buf[2 + offset] = (byte)((uint)value >> 16);
            buf[3 + offset] = (byte)((uint)value >> 24);
        }

        private static void Store64(byte[] buf, int offset, ulong value)
        {
            buf[0 + offset] = (byte)value;
            buf[1 + offset] = (byte)(value >> 8);
            buf[2 + offset] = (byte)(value >> 16);
            buf[3 + offset] = (byte)(value >> 24);
            buf[4 + offset] = (byte)(value >> 32);
            buf[5 + offset] = (byte)(value >> 40);
            buf[6 + offset] = (byte)(value >> 48);
            buf[7 + offset] = (byte)(value >> 56);
        }

        private static void StoreBlock(byte[] buf, BlockValues blockValues)
        {
            for (int i = 0; i < QwordsInBlock; ++i)
            {
                Store64(buf, 8 * i, blockValues[i]);
            }
        }

        private static ulong Load64(byte[] value, int offset)
        {
            return value[offset]
                | ((ulong)value[offset + 1] << 8)
                | ((ulong)value[offset + 2] << 16)
                | ((ulong)value[offset + 3] << 24)
                | ((ulong)value[offset + 4] << 32)
                | ((ulong)value[offset + 5] << 40)
                | ((ulong)value[offset + 6] << 48)
                | ((ulong)value[offset + 7] << 56);
        }

        private static void LoadBlock(BlockValues dst, byte[] src)
        {
            for (int i = 0; i < QwordsInBlock; ++i)
            {
                dst[i] = Load64(src, i * 8);
            }
        }
    }
}