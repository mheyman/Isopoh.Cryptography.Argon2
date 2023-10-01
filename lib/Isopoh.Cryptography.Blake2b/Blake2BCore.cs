﻿// <copyright file="Blake2BCore.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Blake2b
{
    // Originally written in 2012 by Christian Winnerlein  <codesinchaos@gmail.com>
    // Original copyright notice:
    //   To the extent possible under law, the author(s) have dedicated all
    //   copyright and related and neighboring rights to this software to the
    //   public domain worldwide. This software is distributed without any
    //   warranty.
    //
    //   You should have received a copy of the CC0 Public Domain Dedication
    //   along with this software. If not, see
    //   <http://creativecommons.org/publicdomain/zero/1.0/>.
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

    using System;
    using System.Runtime.InteropServices;
    using Isopoh.Cryptography.SecureArray;

    /// <summary>
    /// The core of the Blake2 hash.
    /// </summary>
    public partial class Blake2BCore
    {
        private const int BlockSizeInBytes = 128;

        private const ulong Iv0 = 0x6A09E667F3BCC908UL;
        private const ulong Iv1 = 0xBB67AE8584CAA73BUL;
        private const ulong Iv2 = 0x3C6EF372FE94F82BUL;
        private const ulong Iv3 = 0xA54FF53A5F1D36F1UL;
        private const ulong Iv4 = 0x510E527FADE682D1UL;
        private const ulong Iv5 = 0x9B05688C2B3E6C1FUL;
        private const ulong Iv6 = 0x1F83D9ABFB41BD6BUL;
        private const ulong Iv7 = 0x5BE0CD19137E2179UL;

        private readonly SecureArray<byte> secureArray;
        private readonly Memory<byte> buf;
        private readonly Memory<byte> mbufBacking;
        private readonly Memory<byte> hbufBacking;
        private bool isInitialized;
        private int bufferFilled;
        private ulong counter0;
        private ulong counter1;
        private ulong finalizationFlag0;
        private ulong finalizationFlag1;

        /// <summary>
        /// Initializes a new instance of the <see cref="Blake2BCore"/> class.
        /// </summary>
        /// <param name="secureArrayCall">
        /// The methods that get called to secure arrays. A null value defaults to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
        /// </param>
        /// <param name="lockMemory">
        /// Used to set locking strategy for buffers used in creating the hash. The memory
        /// will always be zeroed prior to destruction. The memory is also always pinned
        /// so the CLR can't move it and leave extraneous copies floating around in RAM.
        /// </param>
        public Blake2BCore(SecureArrayCall secureArrayCall, LockMemoryPolicy lockMemory = LockMemoryPolicy.BestEffort)
        {
            const int totalSize = 128 + (sizeof(ulong) * (16 + 8));
            this.secureArray = SecureArray<byte>.Create(totalSize, secureArrayCall, lockMemory);
            var fullBuf = new Memory<byte>(this.secureArray.Buffer);
            this.buf = fullBuf.Slice(0, 128);
            this.mbufBacking = fullBuf.Slice(128, 16 * sizeof(ulong));
            this.hbufBacking = fullBuf.Slice(128 + (16 * sizeof(ulong)), 8 * sizeof(ulong));
        }

        /// <summary>
        /// Convert a big-endian buffer into a <see cref="ulong"/>.
        /// </summary>
        /// <param name="buf">Buffer holding an 8-byte big-endian ulong.</param>
        /// <param name="offset">Offset into the buffer to start reading the ulong.</param>
        /// <returns>The parsed ulong.</returns>
        /// <remarks>
        /// No checking is done to verify that an 8-byte value can be read from <paramref name="buf"/> at <paramref name="offset"/>.
        /// </remarks>
        public static ulong BytesToUInt64(ReadOnlySpan<byte> buf, int offset)
        {
            return
                ((ulong)buf[offset + 7] << (7 * 8)) |
                ((ulong)buf[offset + 6] << (6 * 8)) |
                ((ulong)buf[offset + 5] << (5 * 8)) |
                ((ulong)buf[offset + 4] << (4 * 8)) |
                ((ulong)buf[offset + 3] << (3 * 8)) |
                ((ulong)buf[offset + 2] << (2 * 8)) |
                ((ulong)buf[offset + 1] << (1 * 8)) |
                buf[offset];
        }

        /// <summary>
        /// Store a ulong into a byte buffer as big-endian.
        /// </summary>
        /// <param name="value">The ulong to store.</param>
        /// <param name="buf">The buffer to load the 8-byte value into.</param>
        /// <param name="offset">The offset to start <paramref name="value"/> at in <paramref name="buf"/>.</param>
        /// <remarks>
        /// No checking is done to validate the buffer can store <paramref name="value"/> at <paramref name="offset"/>.
        /// </remarks>
        public static void UInt64ToBytes(ulong value, byte[] buf, int offset)
        {
            buf[offset + 7] = (byte)(value >> (7 * 8));
            buf[offset + 6] = (byte)(value >> (6 * 8));
            buf[offset + 5] = (byte)(value >> (5 * 8));
            buf[offset + 4] = (byte)(value >> (4 * 8));
            buf[offset + 3] = (byte)(value >> (3 * 8));
            buf[offset + 2] = (byte)(value >> (2 * 8));
            buf[offset + 1] = (byte)(value >> (1 * 8));
            buf[offset] = (byte)value;
        }

        /// <summary>
        /// Initialize the hash.
        /// </summary>
        /// <param name="config">8-element configuration array.</param>
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

            this.Hbuf[0] = Iv0;
            this.Hbuf[1] = Iv1;
            this.Hbuf[2] = Iv2;
            this.Hbuf[3] = Iv3;
            this.Hbuf[4] = Iv4;
            this.Hbuf[5] = Iv5;
            this.Hbuf[6] = Iv6;
            this.Hbuf[7] = Iv7;

            this.counter0 = 0;
            this.counter1 = 0;
            this.finalizationFlag0 = 0;
            this.finalizationFlag1 = 0;

            this.bufferFilled = 0;

            this.buf.Span.Clear();

            for (int i = 0; i < 8; i++)
            {
                this.Hbuf[i] ^= config[i];
            }
        }

        /// <summary>
        /// Update the hash state.
        /// </summary>
        /// <param name="array">
        /// Data to use to update the hash state.
        /// </param>
        /// <param name="start">
        /// Index of the first byte in <paramref name="array"/> to use.
        /// </param>
        /// <param name="count">
        /// Number of bytes in <paramref name="array"/> to use.
        /// </param>
        public void HashCore(Span<byte> array, int start, int count)
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
                this.buf.Slice(this.bufferFilled, bufferRemaining).Span.CopyTo(array.Slice(offset));
                this.counter0 += BlockSizeInBytes;
                if (this.counter0 == 0)
                {
                    this.counter1++;
                }

                this.Compress(this.buf.Span, 0);
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
                array.Slice(offset, count).CopyTo(this.buf.Span.Slice(this.bufferFilled));
                this.bufferFilled += count;
            }
        }

        /// <summary>
        /// Compute the hash.
        /// </summary>
        /// <param name="hash">
        /// Loaded with the hash.
        /// </param>
        /// <returns>
        /// <paramref name="hash"/>.
        /// </returns>
        public byte[] HashFinal(byte[] hash)
        {
            return this.HashFinal(hash, false);
        }

        /// <summary>
        /// Compute the hash.
        /// </summary>
        /// <param name="hash">
        /// Loaded with the hash.
        /// </param>
        /// <param name="isEndOfLayer">
        /// True to signal the last node of a layer in tree-hashing mode; false otherwise.
        /// </param>
        /// <returns>
        /// <paramref name="hash"/>.
        /// </returns>
        public byte[] HashFinal(byte[] hash, bool isEndOfLayer)
        {
            if (!this.isInitialized)
            {
                throw new InvalidOperationException("Not initialized");
            }

            if (hash.Length != 64)
            {
                throw new ArgumentException(
                    $"Invalid hash length, got {hash.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)}, expected 64",
                    nameof(hash));
            }

            this.isInitialized = false;

            // Last compression
            this.counter0 += (uint)this.bufferFilled;
            this.finalizationFlag0 = ulong.MaxValue;
            if (isEndOfLayer)
            {
                this.finalizationFlag1 = ulong.MaxValue;
            }

            for (int i = this.bufferFilled; i < this.buf.Length; i++)
            {
                this.buf.Span[i] = 0;
            }

            this.Compress(this.buf.Span, 0);

            // Output
            for (int i = 0; i < 8; ++i)
            {
                UInt64ToBytes(this.Hbuf[i], hash, i << 3);
            }

            return hash;
        }

        /// <summary>
        /// Return the hash.
        /// </summary>
        /// <returns>
        /// The 64-byte hash.
        /// </returns>
        public byte[] HashFinal()
        {
            return this.HashFinal(false);
        }

        /// <summary>
        /// Return the hash.
        /// </summary>
        /// <param name="isEndOfLayer">
        /// True to signal the last node of a layer in tree-hashing mode; false otherwise.
        /// </param>
        /// <returns>
        /// The 64-byte hash.
        /// </returns>
        public byte[] HashFinal(bool isEndOfLayer)
        {
            byte[] hash = new byte[64];
            this.HashFinal(hash, isEndOfLayer);
            return hash;
        }

        /// <summary>
        /// Release unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            this.secureArray.Dispose();
        }

        partial void Compress(ReadOnlySpan<byte> block, int start);

        private Span<ulong> Mbuf => MemoryMarshal.Cast<byte, ulong>(this.mbufBacking.Span);

        private Span<ulong> Hbuf => MemoryMarshal.Cast<byte, ulong>(this.hbufBacking.Span);

    }
}
