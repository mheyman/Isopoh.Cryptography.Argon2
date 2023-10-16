// <copyright file="Blake2BCore.cs" company="Isopoh">
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
    public partial class Blake2BCore : IDisposable
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

        private readonly SecureArray<byte>? secureArray;
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
        /// <param name="blake2BCoreBuffer">
        /// Used to perform the Blake2b operations. Must be at least <see cref="BufferTotalSize"/> bytes long.
        /// </param>
        public Blake2BCore(Memory<byte> blake2BCoreBuffer)
        {
            if (blake2BCoreBuffer.Length < BufferTotalSize)
            {
                throw new ArgumentException(
                    nameof(blake2BCoreBuffer),
                    $"Expected {nameof(blake2BCoreBuffer)}.Length to be at least {BufferTotalSize}, got {blake2BCoreBuffer.Length}.");
            }

            this.secureArray = null;
            this.buf = blake2BCoreBuffer.Slice(0, 128);
            this.buf.Span.Clear();
            this.mbufBacking = blake2BCoreBuffer.Slice(128, 16 * sizeof(ulong));
            this.hbufBacking = blake2BCoreBuffer.Slice(128 + (16 * sizeof(ulong)), 8 * sizeof(ulong));
        }

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
            this.secureArray = SecureArray<byte>.Create(BufferTotalSize, secureArrayCall, lockMemory);
            var fullBuf = new Memory<byte>(this.secureArray.Buffer);
            this.buf = fullBuf.Slice(0, 128);
            this.mbufBacking = fullBuf.Slice(128, 16 * sizeof(ulong));
            this.hbufBacking = fullBuf.Slice(128 + (16 * sizeof(ulong)), 8 * sizeof(ulong));
        }

        /// <summary>
        /// Gets the total size of the buffer needed to do <see cref="Blake2BCore"/> operations.
        /// </summary>
        public static int BufferTotalSize => 128 + (sizeof(ulong) * (16 + 8));

        private Span<ulong> Mbuf => MemoryMarshal.Cast<byte, ulong>(this.mbufBacking.Span);

        private Span<ulong> Hbuf => MemoryMarshal.Cast<byte, ulong>(this.hbufBacking.Span);

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
        public static void UInt64ToBytes(ulong value, Span<byte> buf, int offset)
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
        public void Initialize(ReadOnlySpan<ulong> config)
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
        /// <param name="data">
        /// Data to use to update the hash state.
        /// </param>
        public void HashCore(ReadOnlySpan<byte> data)
        {
            if (!this.isInitialized)
            {
                throw new InvalidOperationException("Not initialized");
            }

            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            int offset = 0;
            int count = data.Length;
            int bufferRemaining = BlockSizeInBytes - this.bufferFilled;

            if ((this.bufferFilled > 0) && (count > bufferRemaining))
            {
                data.Slice(offset, bufferRemaining).CopyTo(this.buf.Span.Slice(this.bufferFilled));
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

                this.Compress(data, offset);
                offset += BlockSizeInBytes;
                count -= BlockSizeInBytes;
            }

            if (count > 0)
            {
                data.Slice(offset, count).CopyTo(this.buf.Span.Slice(this.bufferFilled));
                this.bufferFilled += count;
            }
        }

        /// <summary>
        /// Compute the hash.
        /// </summary>
        /// <param name="hash">
        /// Loaded with the hash. Must be 64 bytes.
        /// </param>
        /// <param name="isEndOfLayer">
        /// True to signal the last node of a layer in tree-hashing mode; false otherwise.
        /// </param>
        /// <returns>
        /// <paramref name="hash"/>.
        /// </returns>
        /// <exception cref="InvalidOperationException">If <see cref="Initialize"/> was not called.</exception>
        /// <exception cref="ArgumentException">When <see cref="hash"/>.Length != 64.</exception>
        public Span<byte> HashFinal(Span<byte> hash, bool isEndOfLayer)
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

            this.buf.Slice(this.bufferFilled).Span.Clear(); // zero to end of buffer
            this.Compress(this.buf.Span, 0);

            // Output
            if (BitConverter.IsLittleEndian)
            {
                this.hbufBacking.Span.CopyTo(hash);
            }
            else
            {
                for (int i = 0; i < 8; ++i)
                {
                    UInt64ToBytes(this.Hbuf[i], hash, i << 3);
                }
            }

            return hash;
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
        public Span<byte> HashFinal(Span<byte> hash)
        {
            return this.HashFinal(hash, false);
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
            this.HashFinal(hash.AsSpan(), false);
            return hash;
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
        /// <exception cref="InvalidOperationException">If <see cref="Initialize"/> was not called.</exception>
        /// <exception cref="ArgumentException">When <see cref="hash"/>.Length != 64.</exception>
        public byte[] HashFinal(byte[] hash, bool isEndOfLayer)
        {
            this.HashFinal(hash.AsSpan(), isEndOfLayer);
            return hash;
        }

        /// <summary>
        /// Return the hash.
        /// </summary>
        /// <returns>
        /// The 64-byte hash.
        /// </returns>
        /// <exception cref="InvalidOperationException">If <see cref="Initialize"/> was not called.</exception>
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
        /// <exception cref="InvalidOperationException">If <see cref="Initialize"/> was not called.</exception>
        public byte[] HashFinal(bool isEndOfLayer)
        {
            byte[] hash = new byte[64];
            this.HashFinal(hash.AsSpan(), isEndOfLayer);
            return hash;
        }

        /// <summary>
        /// Release unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Dispose pattern Dispose method.
        /// </summary>
        /// <param name="disposing">True to dispose; false otherwise (when calling from destructor).</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                this.secureArray?.Dispose();
            }
        }

        partial void Compress(ReadOnlySpan<byte> block, int start);
    }
}
