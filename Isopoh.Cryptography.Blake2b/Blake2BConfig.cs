// BLAKE2 reference source code package - C# implementation

// Written in 2012 by Christian Winnerlein  <codesinchaos@gmail.com>
// Modified in 2016 by Michael Heyman for sensitive information


// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.

// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

namespace Isopoh.Cryptography.Blake2b
{
    using System;

    /// <summary>
    /// Configuration for the Blake2 hash.
    /// </summary>
    public sealed class Blake2BConfig
    {
        private int outputSizeInBytes;
        private byte[] outputBuffer;

        private byte[] personalization;

        private byte[] salt;

        private byte[] key;

        /// <summary>
        ///
        /// </summary>
        public Blake2BConfig()
        {
            this.OutputSizeInBytes = 64;
        }

        /// <summary>
        /// Gets or sets the policy for created memory buffers.
        /// </summary>
        public LockMemoryPolicy LockMemoryPolicy { get; set; } = LockMemoryPolicy.BestEffort;

        /// <summary>
        /// Gets or sets the personalization value used in the hash. If not null, must be 16 bytes.
        /// </summary>
        /// <exception cref="ArgumentException">
        /// Attempt to set <see cref="Personalization"/> to non-null other than 16 bytes.
        /// </exception>
        public byte[] Personalization
        {
            get => this.personalization;

            set
            {
                if (value != null && value.Length != 16)
                {
                    throw new ArgumentException($"Blake2BConfig.Personalization must be 16 bytes, got {value.Length}");
                }

                this.personalization = value;
            }
        }

        /// <summary>
        /// Gets or sets the salt value used in the hash. If not null, must be 16 bytes.
        /// </summary>
        /// <exception cref="ArgumentException">
        /// Attempt to set <see cref="Salt"/> to non-null other than 16 bytes.
        /// </exception>
        public byte[] Salt
        {
            get => this.salt;

            set
            {
                if (value != null && value.Length != 16)
                {
                    throw new ArgumentException($"Blake2BConfig.Salt must be 16 bytes, got {value.Length}");
                }

                this.salt = value;
            }
        }

        /// <summary>
        /// Gets or sets the key value used in the hash. If not null, must be 128 bytes or shorter.
        /// </summary>
        /// <remarks>
        /// Blake2 keyed hashing can be used for authentication as a faster and
        /// simpler replacement for HMAC.
        /// </remarks>
        /// <exception cref="ArgumentException">
        /// Attempt to set <see cref="Key"/> greater than 128 bytes.
        /// </exception>
        public byte[] Key
        {
            get => this.key;

            set
            {
                if (value != null && value.Length > 128)
                {
                    throw new ArgumentException($"Blake2BConfig.Key must be 129 bytes or less, got {value.Length}");
                }

                this.key = value;
            }
        }

        /// <summary>
        /// Gets or sets the output size in bytes. Must be less than or equal to 64.
        /// </summary>
        /// <remarks>
        /// Blake2 incorporates this value into the hash. The array returned by the
        /// <see cref="Blake2BHasher"/>.<see cref="Blake2BHasher.Finish"/> call will
        /// be this length unless the <see cref="Result64ByteBuffer"/> value is non-null.
        /// If that property is non-null, that buffer gets returned by the <see
        /// cref="Blake2BHasher"/>.<see cref="Blake2BHasher.Finish"/> call regarless of
        /// the <see cref="OutputSizeInBytes"/> property. In that case, you can copy the
        /// first <see cref="OutputSizeInBytes"/> bytes of the <see
        /// cref="Result64ByteBuffer"/> array to get the value that Blake2 would have
        /// returned.
        /// </remarks>
        public int OutputSizeInBytes
        {
            get => this.outputSizeInBytes;

            set
            {
                if (value > 64)
                {
                    throw new ArgumentOutOfRangeException($"Output size must be less than 64 byts, got {value}");
                }

                this.outputSizeInBytes = value;
            }
        }

        // ReSharper disable once UnusedMember.Global
        /// <summary>
        /// Gets or sets the output size in bits. Must be a multiple of 8.
        /// </summary>
        /// <exception cref="ArgumentException">
        /// Attempt to set <see cref="OutputSizeInBits"/> to a value not a multiple of 8 bits.
        /// </exception>
        public int OutputSizeInBits
        {
            get => this.OutputSizeInBytes * 8;

            set
            {
                if (value % 8 != 0)
                    throw new ArgumentException("Output size must be a multiple of 8 bits");
                this.OutputSizeInBytes = value / 8;
            }
        }

        /// <summary>
        /// Gets or sets the 64-byte result buffer the Blake2 algorithm will use.
        /// </summary>
        /// <remarks>
        /// If not null, this is the buffer that will get returned by the
        /// <see cref="Blake2BHasher"/>.<see cref="Blake2BHasher.Finish"/> call
        /// regarless of the value of <see cref="OutputSizeInBytes"/>.
        /// </remarks>
        /// <exception cref="ArgumentException">
        /// Attempt to set <see cref="Result64ByteBuffer"/> to non-null other than 64 bytes.
        /// </exception>
        public byte[] Result64ByteBuffer
        {
            get => this.outputBuffer;

            set
            {
                if (value != null && value.Length != 64)
                {
                    throw new ArgumentOutOfRangeException(
                        $"Blake2 output buffer must be 64 bytes, got {value.Length}");
                }

                this.outputBuffer = value;

            }
        }
    }
}
