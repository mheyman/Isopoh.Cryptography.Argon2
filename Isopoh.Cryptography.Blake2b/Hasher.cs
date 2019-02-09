// BLAKE2 reference source code package - C# implementation

// Written in 2012 by Christian Winnerlein  <codesinchaos@gmail.com>

// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.

// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

using System;
using System.Security.Cryptography;

namespace Isopoh.Cryptography.Blake2b
{
    /// <summary>
    /// The bash hasher class.
    /// </summary>
    public abstract class Hasher : IDisposable
    {
        /// <summary>
        /// Initialize for hash generation.
        /// </summary>
        public abstract void Init();

        /// <summary>
        /// Generate the hash from the hash's state.
        /// </summary>
        /// <returns>
        /// The generated hash.
        /// </returns>
        public abstract byte[] Finish();

        /// <summary>
        /// Update the hash's state with the given data.
        /// </summary>
        /// <param name="data">
        /// The data to add to the hash's state
        /// </param>
        /// <param name="start">
        /// The index of the first byte of <paramref name="data"/> to add to the hash's state.
        /// </param>
        /// <param name="count">
        /// The number of bytes of <paramref name="data"/> to add to the hash's state.
        /// </param>
        public abstract void Update(byte[] data, int start, int count);

        /// <summary>
        /// Update the hash's state with the given data.
        /// </summary>
        /// <param name="data">
        /// The data to add to the hash's state
        /// </param>
        public void Update(byte[] data)
        {
            this.Update(data, 0, data.Length);
        }

        // ReSharper disable once UnusedMember.Global
        /// <summary>
        /// Create a <see cref="HashAlgorithm"/> from this.
        /// </summary>
        /// <returns>
        /// The <see cref="HashAlgorithm"/> based on this <see cref="Hasher"/>.
        /// </returns>
        public HashAlgorithm AsHashAlgorithm()
        {
            return new HashAlgorithmAdapter(this);
        }

        internal class HashAlgorithmAdapter : HashAlgorithm
        {
            private readonly Hasher hasher;

            protected override void HashCore(byte[] array, int ibStart, int cbSize)
            {
                this.hasher.Update(array, ibStart, cbSize);
            }

            protected override byte[] HashFinal()
            {
                return this.hasher.Finish();
            }

            public override void Initialize()
            {
                this.hasher.Init();
            }

            public HashAlgorithmAdapter(Hasher hasher)
            {
                this.hasher = hasher;
            }
        }

        /// <summary>
        /// Zero and release sensitive resources.
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes resources if <paramref name="disposing"/> is true.
        /// </summary>
        /// <param name="disposing">
        /// Set to true if disposing.
        /// </param>
        protected virtual void Dispose(bool disposing)
        {
        }
    }
}
