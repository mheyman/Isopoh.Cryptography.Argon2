// <copyright file="Argon2.Helpers.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2
{
    using System.Linq;
    using System.Text;

    using SecureArray;

    /// <summary>
    /// Argon2 Hashing of passwords
    /// </summary>
    public sealed partial class Argon2
    {
        /// <summary>
        /// Hash the given password to a Argon2 hash string.
        /// </summary>
        /// <param name="password">
        /// The password to hash. Gets UTF-8 encoded before hashing.
        /// </param>
        /// <param name="timeCost">
        /// The time cost to use. Defaults to 3.
        /// </param>
        /// <param name="memoryCost">
        /// The memory cost to use. Defaults to 65536 (64K).
        /// </param>
        /// <param name="parallelism">
        /// The parallelism to use. Default to 1 (single threaded).
        /// </param>
        /// <param name="type">
        /// Data-dependent or data-independent. Defaults to data-independent
        /// (as recommended for password hashing).
        /// </param>
        /// <param name="hashLength">
        /// The length of the hash in bytes. Note, the string returned base-64
        /// encodes this with other parameters so the resulting string is
        /// significantly longer.
        /// </param>
        /// <returns>
        /// The Argon2 hash of the given password.
        /// </returns>
        public static string Hash(
            string password,
            int timeCost = 3,
            int memoryCost = 65536,
            int parallelism = 1,
            Argon2Type type = Argon2Type.DataIndependentAddressing,
            int hashLength = 32)
        {
            using (var passwordBuf = new SecureArray<byte>(Encoding.UTF8.GetByteCount(password)))
            {
                byte[] salt = new byte[16];
                System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(salt);
                Encoding.UTF8.GetBytes(password, 0, password.Length, passwordBuf.Buffer, 0);
                var argon2 =
                    new Argon2(
                        new Argon2Config
                        {
                            TimeCost = timeCost,
                            MemoryCost = memoryCost,
                            Threads = parallelism,
                            Lanes = parallelism,
                            Password = passwordBuf.Buffer,
                            Salt = salt,
                            HashLength = hashLength,
                            Version = Argon2Version.Nineteen
                        });
                using (var hash = argon2.Hash())
                {
                    return argon2.config.EncodeString(hash.Buffer);
                }
            }
        }

        /// <summary>
        /// Verify the given Argon2 hash as being that of the given password.
        /// </summary>
        /// <param name="encoded">
        /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
        /// </param>
        /// <param name="password">
        /// The password to verify
        /// </param>
        /// <returns>
        /// True on success; false otherwise.
        /// </returns>
        public static bool Verify(
            string encoded,
            byte[] password)
        {
            SecureArray<byte> hash = null;
            try
            {
                var configToVerify = new Argon2Config { Password = password };
                if (!configToVerify.DecodeString(encoded, out hash) || hash == null)
                {
                    return false;
                }

                var hasherToVerify = new Argon2(configToVerify);
                var hashToVerify = hasherToVerify.Hash();
                return !hash.Buffer.Where((b, i) => b != hashToVerify[i]).Any();
            }
            finally
            {
                hash?.Dispose();
            }
        }

        /// <summary>
        /// Verify the given Argon2 hash as being that of the given password.
        /// </summary>
        /// <param name="encoded">
        /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
        /// </param>
        /// <param name="password">
        /// The password to verify. This gets UTF-8 encoded.
        /// </param>
        /// <returns>
        /// True on success; false otherwise.
        /// </returns>
        public static bool Verify(
            string encoded,
            string password)
        {
            using (var passwordBuf = new SecureArray<byte>(Encoding.UTF8.GetByteCount(password)))
            {
                Encoding.UTF8.GetBytes(password, 0, password.Length, passwordBuf.Buffer, 0);
                return Verify(encoded, passwordBuf.Buffer);
            }
        }
    }
}
