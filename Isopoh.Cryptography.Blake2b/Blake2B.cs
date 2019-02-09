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
    using System.Security.Cryptography;

    using SecureArray;

    /// <summary>
    /// Convenience calls for performing Blake2 hashes.
    /// </summary>
    public static class Blake2B
    {
        /// <summary>
        /// The output length of the Blake2 hash in bytes.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This is the maximum length buffer a Blake2 hash can produce Blake2
        /// will always hash to this length even when configured to hash to a
        /// shorter value - the final step is to truncate the result.
        /// </para>
        /// <para>
        /// Note, the length of the expected result is hashed into the result
        /// so the <see cref="OutputLength"/>-byte buffer will hold different
        /// values depending on the configured output length. Do not run Blake2
        /// using the default length and then truncate and expect to get the
        /// same result as if you configured Blake2 to produce a shorter
        /// result.
        /// </para>
        /// </remarks>
        public const int OutputLength = 64;

        // ReSharper disable once UnusedMember.Global
        /// <summary>
        /// Create a default Blake2 hash.
        /// </summary>
        /// <param name="secureArrayCall">
        /// The methods that get called to secure arrays. A null value defaults to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
        /// </param>
        /// <returns>
        /// A <see cref="Hasher"/> that can be converted to a <see cref="HashAlgorithm"/>.
        /// </returns>
        public static Hasher Create(SecureArrayCall secureArrayCall)
        {
            return Create(new Blake2BConfig(), secureArrayCall);
        }

        /// <summary>
        /// Create a Blake2 hash with the given configuration.
        /// </summary>
        /// <param name="config">
        /// The configuration to use.
        /// </param>
        /// <param name="secureArrayCall">
        /// The methods that get called to secure arrays. A null value defaults to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
        /// </param>
        /// <returns>
        /// A <see cref="Hasher"/> that can be converted to a <see cref="HashAlgorithm"/>.
        /// </returns>
        public static Hasher Create(Blake2BConfig config, SecureArrayCall secureArrayCall)
        {
            return new Blake2BHasher(config, secureArrayCall);
        }

        // ReSharper disable once UnusedMember.Global
        /// <summary>
        /// Perform a default Blake2 hash on the given buffer.
        /// </summary>
        /// <param name="data">
        /// The buffer to hash.
        /// </param>
        /// <param name="start">
        /// The byte in the buffer to start hashing.
        /// </param>
        /// <param name="count">
        /// The number of bytes to hash.
        /// </param>
        /// <param name="secureArrayCall">
        /// The methods that get called to secure arrays. A null value defaults to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
        /// </param>
        /// <returns>
        /// The hash of the buffer.
        /// </returns>
        public static byte[] ComputeHash(byte[] data, int start, int count, SecureArrayCall secureArrayCall)
        {
            return ComputeHash(data, start, count, null, secureArrayCall);
        }

        // ReSharper disable once UnusedMember.Global
        /// <summary>
        /// Perform a default Blake2 hash on the given buffer.
        /// </summary>
        /// <param name="data">
        /// The buffer to hash.
        /// </param>
        /// <param name="secureArrayCall">
        /// The methods that get called to secure arrays. A null value defaults to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
        /// </param>
        /// <returns>
        /// The hash of the buffer.
        /// </returns>
        public static byte[] ComputeHash(byte[] data, SecureArrayCall secureArrayCall)
        {
            return ComputeHash(data, 0, data.Length, null, secureArrayCall);
        }

        /// <summary>
        /// Perform a Blake2 hash on the given buffer using the given Blake2
        /// configuration.
        /// </summary>
        /// <param name="data">
        /// The buffer to hash.
        /// </param>
        /// <param name="config">
        /// The configuration to use.
        /// </param>
        /// <param name="secureArrayCall">
        /// The methods that get called to secure arrays. A null value defaults to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
        /// </param>
        /// <returns>
        /// The hash of the buffer.
        /// </returns>
        public static byte[] ComputeHash(byte[] data, Blake2BConfig config, SecureArrayCall secureArrayCall)
        {
            return ComputeHash(data, 0, data.Length, config, secureArrayCall);
        }

        /// <summary>
        /// Perform a Blake2 hash on the given buffer using the given Blake2
        /// configuration.
        /// </summary>
        /// <param name="data">
        /// The buffer to hash.
        /// </param>
        /// <param name="start">
        /// The byte in the buffer to start hashing.
        /// </param>
        /// <param name="count">
        /// The number of bytes to hash.
        /// </param>
        /// <param name="config">
        /// The configuration to use.
        /// </param>
        /// <param name="secureArrayCall">
        /// The methods that get called to secure arrays. A null value defaults to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
        /// </param>
        /// <returns>
        /// The hash of the buffer.
        /// </returns>
        public static byte[] ComputeHash(byte[] data, int start, int count, Blake2BConfig config, SecureArrayCall secureArrayCall)
        {
            using(var hasher = Create(config, secureArrayCall))
            {
                hasher.Update(data, start, count);
                return hasher.Finish();
            }
        }
        //public static byte[] ComputeParallelHash(byte[] data);
        //public static byte[] ComputeParallelHash(byte[] data, Blake2Config config);
    }
}
