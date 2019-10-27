// <copyright file="Argon2.Blake2BLong.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2
{
    using System;

    using Isopoh.Cryptography.Blake2b;
    using Isopoh.Cryptography.SecureArray;

    /// <summary>
    /// Argon2 Hashing of passwords.
    /// </summary>
    public sealed partial class Argon2
    {
        /// <summary>
        /// Does a Blake2 hash with the ability to truncate or extend the hash to any length.
        /// </summary>
        /// <param name="hash">
        /// The buffer to fill with the hash.
        /// </param>
        /// <param name="inbuf">
        /// What to hash.
        /// </param>
        /// <param name="secureArrayCall">
        /// The methods that get called to secure arrays. A null value defaults to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
        /// </param>
        private static void Blake2BLong(byte[] hash, byte[] inbuf, SecureArrayCall secureArrayCall)
        {
            var outlenBytes = new byte[4];
            using (var intermediateHash = SecureArray<byte>.Best(Blake2B.OutputLength, secureArrayCall))
            {
                var config = new Blake2BConfig
                {
                    Result64ByteBuffer = intermediateHash.Buffer,
                    OutputSizeInBytes = hash.Length > 64 ? 64 : hash.Length,
                };
                Store32(outlenBytes, hash.Length);
                using (var blakeHash = Blake2B.Create(config, secureArrayCall))
                {
                    blakeHash.Update(outlenBytes);
                    blakeHash.Update(inbuf);
                    blakeHash.Finish();
                }

                if (hash.Length <= intermediateHash.Buffer.Length)
                {
                    Array.Copy(intermediateHash.Buffer, hash, hash.Length);
                    return;
                }

                const int b2B2 = Blake2B.OutputLength / 2;
                Array.Copy(intermediateHash.Buffer, hash, b2B2);
                int pos = b2B2;
                int lastHashIndex = hash.Length - Blake2B.OutputLength;
                var toHash = new byte[Blake2B.OutputLength];
                while (pos < lastHashIndex)
                {
                    Array.Copy(intermediateHash.Buffer, toHash, intermediateHash.Buffer.Length);
                    Blake2B.ComputeHash(toHash, config, secureArrayCall);
                    Array.Copy(intermediateHash.Buffer, 0, hash, pos, b2B2);
                    pos += b2B2;
                }

                Array.Copy(intermediateHash.Buffer, toHash, intermediateHash.Buffer.Length);
                Blake2B.ComputeHash(toHash, config, secureArrayCall);
                Array.Copy(intermediateHash.Buffer, 0, hash, pos, hash.Length - pos);
            }
        }
    }
}