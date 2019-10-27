// <copyright file="Argon2Config.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2
{
    using System;

    using Isopoh.Cryptography.SecureArray;

    /// <summary>
    /// Holds configuration needed to perform an Argon2 hash.
    /// </summary>
    public sealed class Argon2Config
    {
        private int hashlen = 32;

        private int memoryCost = 65536;

        private int lanes = 4;

        private int threads = 1;

        private int timeCost = 3;

        private byte[] salt;

        /// <summary>
        /// Gets or sets the Argon2 version used in the password hash. Defaults to
        /// <see cref="Argon2Version"/>.<see cref="Argon2Version.Nineteen"/> (0x13).
        /// </summary>
        public Argon2Version Version { get; set; } = Argon2Version.Nineteen;

        /// <summary>
        /// Gets or sets the Argon2 type. Default to hybrid.
        /// </summary>
        public Argon2Type Type { get; set; } = Argon2Type.HybridAddressing;

        /// <summary>
        /// Gets or sets the hash length to output. Minimum of 4. Default 32.
        /// </summary>
        public int HashLength
        {
            get => this.hashlen;

            set
            {
                if (value < 4)
                {
                    throw new ArgumentException($"HashLength must be 4 or more, got {value}");
                }

                this.hashlen = value;
            }
        }

        /// <summary>
        /// Gets or sets the password to hash.
        /// </summary>
        public byte[] Password { get; set; }

        /// <summary>
        /// Gets or sets the salt used in the password hash. If non-null, must be at least 8 bytes.
        /// </summary>
        public byte[] Salt
        {
            get => this.salt;

            set
            {
                if (value != null && value.Length < 8)
                {
                    throw new ArgumentException($"Salt must be 8 bytes or more, got {value.Length}");
                }

                this.salt = value;
            }
        }

        /// <summary>
        /// Gets or sets the secret used in the password hash.
        /// </summary>
        public byte[] Secret { get; set; }

        /// <summary>
        /// Gets or sets the associated data used in the password hash.
        /// </summary>
        public byte[] AssociatedData { get; set; }

        /// <summary>
        /// Gets or sets the time cost used in the password hash. Minimum of 1. Defaults to 3.
        /// </summary>
        /// <remarks>
        /// This is the number of iterations to perform. There are attacks on the
        /// <see cref="Argon2Version"/>.<see cref="Argon2Version.Sixteen"/> with less than
        /// three iterations (if I'm reading the paper correctly). So, use a value
        /// greater then 3 here if you are not using <see cref="Argon2Version"/>.<see
        /// cref="Argon2Version.Nineteen"/>.
        /// </remarks>
        public int TimeCost
        {
            get => this.timeCost;

            set
            {
                if (value < 1)
                {
                    throw new ArgumentException($"TimeCost must be 1 or more, got {value}");
                }

                this.timeCost = value;
            }
        }

        /// <summary>
        /// Gets or sets the memory cost used in the password hash. Minimum of 1. Defaults to 65536.
        /// </summary>
        /// <remarks>
        /// This translates into the minimum memory used. The memory cost is the minimum number
        /// of 1024-byte blocks to used to perform the hash. If this value is less than
        /// 2 * <see cref="Argon2.SyncPoints"/> * <see cref="Lanes"/> then that value is used
        /// (<see cref="Argon2.SyncPoints"/> == 4).
        /// </remarks>
        public int MemoryCost
        {
            get => this.memoryCost;

            set
            {
                if (value < 1)
                {
                    throw new ArgumentException($"MemoryCost must be 1 or more, got {value}");
                }

                this.memoryCost = value;
            }
        }

        /// <summary>
        /// Gets or sets the lanes used in the password hash. Minimum of 1. Defaults to 4.
        /// </summary>
        /// <remarks>
        /// This describes the maximum parallelism that can be achieved. Each "lane" can
        /// be processed individually in its own thread. Setting <see cref="Threads"/>
        /// to a value greater than one when there is more than one lane will allow the
        /// use of multiple cores to speed up hashing.
        /// </remarks>
        public int Lanes
        {
            get => this.lanes;

            set
            {
                if (value < 1)
                {
                    throw new ArgumentException($"Lanes must be 1 or more, got {value}");
                }

                this.lanes = value;
            }
        }

        /// <summary>
        /// Gets or sets the threads used in the password hash. Minimum of 1. Defaults to 1.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This value makes no difference in the result. A value greater than one causes that
        /// many threads to get spawned to do the work on top of the main thread that orchestrates
        /// which thread does what work.
        /// </para>
        /// <para>
        /// <see cref="Lanes"/> defines the maximum parallelism that can be achieved. Setting
        /// <see cref="Threads"/> to a value greater than <see cref="Lanes"/> will not result
        /// in more than <see cref="Lanes"/> threads running.
        /// </para>
        /// </remarks>
        public int Threads
        {
            get => this.threads;

            set
            {
                if (value < 1)
                {
                    throw new ArgumentException($"Threads must be 1 or more, got {value}");
                }

                this.threads = value;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether to clear the password as
        /// soon as it is no longer needed.
        /// </summary>
        /// <remarks>
        /// If true and the configuration has a password, the configuration
        /// cannot be used more than once without resetting the password
        /// (unless you want an all zero password).
        /// </remarks>
        public bool ClearPassword { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to clear the secret as
        /// soon as it is no longer needed.
        /// </summary>
        /// <remarks>
        /// If true and the configuration has a secret, the configuration
        /// cannot be used more than once without resetting the secret
        /// (unless you want an all zero secret).
        /// </remarks>
        public bool ClearSecret { get; set; }

        /// <summary>
        /// Gets or sets the methods that get called to secure arrays. Defaults
        /// to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
        /// </summary>
        public SecureArrayCall SecureArrayCall { get; set; } = SecureArray.DefaultCall;
    }
}