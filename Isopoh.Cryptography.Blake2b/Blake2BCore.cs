// BLAKE2 reference source code package - C# implementation

// Written in 2012 by Christian Winnerlein  <codesinchaos@gmail.com>

// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.

// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//
/*
  Based on BlakeSharp
  by Dominik Reichl <dominik.reichl@t-online.de>
  Web: http://www.dominik-reichl.de/
  If you're using this class, it would be nice if you'd mention
  me somewhere in the documentation of your program, but it's
  not required.

  BLAKE was designed by Jean-Philippe Aumasson, Luca Henzen,
  Willi Meier and Raphael C.-W. Phan.
  BlakeSharp was derived from the reference C implementation.
*/

namespace Isopoh.Cryptography.Blake2b
{
    using System;
    using SecureArray;

    public sealed partial class Blake2BCore
    {
        private bool isInitialized;

        private int bufferFilled;
        private readonly SecureArray<byte> buf = new SecureArray<byte>(128);

        private readonly SecureArray<ulong> mbuf = new SecureArray<ulong>(16);
        private readonly SecureArray<ulong> hbuf = new SecureArray<ulong>(8);
        private ulong counter0;
        private ulong counter1;
        private ulong finalizationFlag0;
        private ulong finalizationFlag1;

        private const int BlockSizeInBytes = 128;

        private const ulong Iv0 = 0x6A09E667F3BCC908UL;
        private const ulong Iv1 = 0xBB67AE8584CAA73BUL;
        private const ulong Iv2 = 0x3C6EF372FE94F82BUL;
        private const ulong Iv3 = 0xA54FF53A5F1D36F1UL;
        private const ulong Iv4 = 0x510E527FADE682D1UL;
        private const ulong Iv5 = 0x9B05688C2B3E6C1FUL;
        private const ulong Iv6 = 0x1F83D9ABFB41BD6BUL;
        private const ulong Iv7 = 0x5BE0CD19137E2179UL;

        internal static ulong BytesToUInt64(byte[] buf, int offset)
        {
            return
                ((ulong)buf[offset + 7] << 7 * 8 |
                ((ulong)buf[offset + 6] << 6 * 8) |
                ((ulong)buf[offset + 5] << 5 * 8) |
                ((ulong)buf[offset + 4] << 4 * 8) |
                ((ulong)buf[offset + 3] << 3 * 8) |
                ((ulong)buf[offset + 2] << 2 * 8) |
                ((ulong)buf[offset + 1] << 1 * 8) |
                buf[offset]);
        }

        private static void UInt64ToBytes(ulong value, byte[] buf, int offset)
        {
            buf[offset + 7] = (byte)(value >> 7 * 8);
            buf[offset + 6] = (byte)(value >> 6 * 8);
            buf[offset + 5] = (byte)(value >> 5 * 8);
            buf[offset + 4] = (byte)(value >> 4 * 8);
            buf[offset + 3] = (byte)(value >> 3 * 8);
            buf[offset + 2] = (byte)(value >> 2 * 8);
            buf[offset + 1] = (byte)(value >> 1 * 8);
            buf[offset] = (byte)value;
        }

        partial void Compress(byte[] block, int start);

        public void Initialize(ulong[] config)
        {
            if (config == null)
            {
                throw new ArgumentNullException(nameof(config));
            }

            if (config.Length != 8)
            {
                throw new ArgumentException("config length must be 8 words", nameof(config));
            }

            this.isInitialized = true;

            this.hbuf[0] = Iv0;
            this.hbuf[1] = Iv1;
            this.hbuf[2] = Iv2;
            this.hbuf[3] = Iv3;
            this.hbuf[4] = Iv4;
            this.hbuf[5] = Iv5;
            this.hbuf[6] = Iv6;
            this.hbuf[7] = Iv7;

            this.counter0 = 0;
            this.counter1 = 0;
            this.finalizationFlag0 = 0;
            this.finalizationFlag1 = 0;

            this.bufferFilled = 0;

            Array.Clear(this.buf.Buffer, 0, this.buf.Buffer.Length);

            for (int i = 0; i < 8; i++)
                this.hbuf[i] ^= config[i];
        }

        public void HashCore(byte[] array, int start, int count)
        {
            if (!this.isInitialized)
            {
                throw new InvalidOperationException("Not initialized");
            }

            if (array == null)
            {
                throw new ArgumentNullException(nameof(array));
            }

            if (start < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(start));
            }

            if (count < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(count));
            }

            if (start + (long)count > array.Length)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(count),
                    $"Expected start+count <= array.Length, got {start}+{count} > {array.Length}");
            }

            int offset = start;
            int bufferRemaining = BlockSizeInBytes - this.bufferFilled;

            if ((this.bufferFilled > 0) && (count > bufferRemaining))
            {
                Array.Copy(array, offset, this.buf.Buffer, this.bufferFilled, bufferRemaining);
                this.counter0 += BlockSizeInBytes;
                if (this.counter0 == 0)
                {
                    this.counter1++;
                }

                this.Compress(this.buf.Buffer, 0);
                offset += bufferRemaining;
                count -= bufferRemaining;
                this.bufferFilled = 0;
            }

            while (count > BlockSizeInBytes)
            {
                this.counter0 += BlockSizeInBytes;
                if (this.counter0 == 0)
                {
                    this.counter1++;
                }

                this.Compress(array, offset);
                offset += BlockSizeInBytes;
                count -= BlockSizeInBytes;
            }

            if (count > 0)
            {
                Array.Copy(array, offset, this.buf.Buffer, this.bufferFilled, count);
                this.bufferFilled += count;
            }
        }

        public byte[] HashFinal(byte[] hash)
        {
            return this.HashFinal(hash, false);
        }

        public byte[] HashFinal(byte[] hash, bool isEndOfLayer)
        {
            if (!this.isInitialized)
                throw new InvalidOperationException("Not initialized");
            if (hash?.Length != 64)
            {
                throw new ArgumentException($"Invalid hash length, got {hash?.Length.ToString() ?? "<null>"}, expected 64", nameof(hash));
            }

            this.isInitialized = false;

            // Last compression
            this.counter0 += (uint)this.bufferFilled;
            this.finalizationFlag0 = ulong.MaxValue;
            if (isEndOfLayer)
            {
                this.finalizationFlag1 = ulong.MaxValue;
            }

            for (int i = this.bufferFilled; i < this.buf.Buffer.Length; i++)
            {
                this.buf[i] = 0;
            }

            this.Compress(this.buf.Buffer, 0);

            // Output
            for (int i = 0; i < 8; ++i)
            {
                UInt64ToBytes(this.hbuf[i], hash, i << 3);
            }

            return hash;
        }

        public byte[] HashFinal()
        {
            return this.HashFinal(false);
        }

        public byte[] HashFinal(bool isEndOfLayer)
        {
            byte[] hash = new byte[64];
            this.HashFinal(hash, isEndOfLayer);
            return hash;
        }

    }
}
