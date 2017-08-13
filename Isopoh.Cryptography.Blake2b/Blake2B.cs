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

        /// <summary>
        /// Create a default Blake2 hash.
        /// </summary>
        /// <returns>
        /// A <see cref="Hasher"/> that can be converted to a <see cref="HashAlgorithm"/>.
        /// </returns>
        public static Hasher Create()
        {
            return Create(new Blake2BConfig());
        }

        /// <summary>
        /// Create a Blake2 hash with the given configuration.
        /// </summary>
        /// <param name="config">
        /// The configuration to use.
        /// </param>
        /// <returns>
        /// A <see cref="Hasher"/> that can be converted to a <see cref="HashAlgorithm"/>.
        /// </returns>
        public static Hasher Create(Blake2BConfig config)
        {
            return new Blake2BHasher(config);
        }

        /*public static Hasher CreateParallel(int parallelism = 4)
        {
            return CreateParallel(null, parallelism);
        }

        public static Hasher CreateParallel(Blake2Config config, int parallelism = 4)
        {
            if (parallelism < 2)
                throw new ArgumentOutOfRangeException("parallelism", "parallism must be at least 2");
            throw new NotImplementedException();
        }

        public static Hasher CreateTreeHasher(Blake2BConfig config, Blake2TreeConfig treeConfig)
        {
        }

        public static NodeHasher CreateNodeHasher(Blake2BConfig config, Blake2TreeConfig treeConfig)
        {
        }*/

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
        /// <returns>
        /// The hash of the buffer.
        /// </returns>
        public static byte[] ComputeHash(byte[] data, int start, int count)
        {
            return ComputeHash(data, start, count, null);
        }

        /// <summary>
        /// Perform a default Blake2 hash on the given buffer.
        /// </summary>
        /// <param name="data">
        /// The buffer to hash.
        /// </param>
        /// <returns>
        /// The hash of the buffer.
        /// </returns>
        public static byte[] ComputeHash(byte[] data)
        {
            return ComputeHash(data, 0, data.Length, null);
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
        /// <returns>
        /// The hash of the buffer.
        /// </returns>
        public static byte[] ComputeHash(byte[] data, Blake2BConfig config)
        {
            return ComputeHash(data, 0, data.Length, config);
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
        /// <returns>
        /// The hash of the buffer.
        /// </returns>
        public static byte[] ComputeHash(byte[] data, int start, int count, Blake2BConfig config)
        {
            using(var hasher = Create(config))
            {
                hasher.Update(data, start, count);
                return hasher.Finish();
            }
        }
        //public static byte[] ComputeParallelHash(byte[] data);
        //public static byte[] ComputeParallelHash(byte[] data, Blake2Config config);
    }
}
