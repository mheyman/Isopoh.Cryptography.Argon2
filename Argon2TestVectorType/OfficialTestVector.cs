// <copyright file="OfficialTestVector.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>
namespace Argon2TestVectorType
{
    using Isopoh.Cryptography.Argon2;

    /// <summary>
    /// Holds Argon2 test vector information.
    /// </summary>
    public class OfficialTestVector
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OfficialTestVector"/> class.
        /// </summary>
        /// <param name="type">The Argon2 type.</param>
        /// <param name="version">The Argon2 version.</param>
        /// <param name="iterationCount">The iteration count.</param>
        /// <param name="memoryKByteCount">The target number of kibibytes.</param>
        /// <param name="parallelism">The parallelism.</param>
        /// <param name="password">The password hashed.</param>
        /// <param name="salt">The salt hashed.</param>
        /// <param name="secret">The secret hashed.</param>
        /// <param name="associatedData">The associated data hashed.</param>
        /// <param name="tag">The hexadecimal-encoded tag resulting from the hash.</param>
        public OfficialTestVector(
            Argon2Type type,
            Argon2Version version,
            int iterationCount,
            int memoryKByteCount,
            int parallelism,
            string password,
            string salt,
            string secret,
            string associatedData,
            string tag) =>
            (this.Type, this.Version, this.IterationCount, this.MemoryKByteCount, this.Parallelism, this.Password, this.Salt, this.Secret, this.AssociatedData, this.Tag)
            = (type, version, iterationCount, memoryKByteCount, parallelism, password, salt, secret, associatedData, tag);

        /// <summary>
        /// Gets the Argon2 type.
        /// </summary>
        public Argon2Type Type { get; private set; }

        /// <summary>
        /// Gets the Argon2 version.
        /// </summary>
        public Argon2Version Version { get; private set; }

        /// <summary>
        /// Gets iteration count.
        /// </summary>
        public int IterationCount { get; private set; }

        /// <summary>
        /// Gets target kibibytes.
        /// </summary>
        public int MemoryKByteCount { get; private set; }

        /// <summary>
        /// Gets the parallelism.
        /// </summary>
        public int Parallelism { get; private set; }

        /// <summary>
        /// Gets the password.
        /// </summary>
        public string Password { get; private set; }

        /// <summary>
        /// Gets the salt.
        /// </summary>
        public string Salt { get; private set; }

        /// <summary>
        /// Gets the secret.
        /// </summary>
        public string Secret { get; private set; }

        /// <summary>
        /// Gets the associated data.
        /// </summary>
        public string AssociatedData { get; private set; }

        /// <summary>
        /// Gets the hexadecimal-encoded tag.
        /// </summary>
        public string Tag { get; private set; }
    }
}