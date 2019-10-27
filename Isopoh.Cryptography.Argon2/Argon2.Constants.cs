// <copyright file="Argon2.Constants.cs" company="Isopoh">
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
        /// <summary>
        /// The Argon2 block size in bytes.
        /// </summary>
        public const int BlockSize = 1024;

        /// <summary>
        /// The number of 8-byte words in an Argon2 block.
        /// </summary>
        public const int QwordsInBlock = BlockSize / 8;

        /// <summary>
        /// The number of bytes hashed in initializing Argon2.
        /// </summary>
        public const int PrehashDigestLength = 64;

        /// <summary>
        /// Bytes required in the buffer passed into the <see cref="Argon2.FillFirstBlocks"/> method.
        /// </summary>
        public const int PrehashSeedLength = 72;

        /// <summary>
        /// Number of synchronization points between lanes per pass.
        /// </summary>
        public const int SyncPoints = 4;
    }
}
