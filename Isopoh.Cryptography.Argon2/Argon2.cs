// <copyright file="Argon2.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2
{
    using System;

    using Isopoh.Cryptography.SecureArray;

    /// <summary>
    /// Argon2 Hashing of passwords
    /// </summary>
    public sealed partial class Argon2 : IDisposable
    {
        private readonly SecureArray<ulong> memory;

        private readonly int threadCount;

        private readonly Action fillMemoryBlocks;

        private readonly Action<BlockValues> blake2RowAndColumnRoundsNoMsg;

        /// <summary>
        /// Initializes a new instance of the <see cref="Argon2"/> class.
        /// </summary>
        /// <param name="config">
        /// The configuration to use.
        /// </param>
        public Argon2(Argon2Config config)
        {
            this.Type = config.Type;
            this.Version = config.Version;
            this.TimeCost = config.TimeCost;
            this.HashLength = config.HashLength;
            this.ClearPassword = config.ClearPassword;
            this.Password = config.Password;
            this.Salt = config.Salt;
            this.Secret = config.Secret;
            this.AssociatedData = config.AssociatedData;
            this.MemoryCost = config.MemoryCost;
            this.Lanes = config.Lanes;
            this.ClearSecret = config.ClearSecret;
            this.threadCount = config.Threads > config.Lanes ? config.Lanes : config.Threads;
            this.fillMemoryBlocks = this.threadCount == 1
                                        ? this.FillMemoryBlocksSingleThreaded
                                        : config.ParallelismScheme == ParallelismScheme.NaiveTasks
                                              ? this.FillMemoryBlocksSimpleTasked
                                              : config.ParallelismScheme == ParallelismScheme.Tasks
                                                    ? this.FillMemoryBlocksTasked
                                                    : config.ParallelismScheme == ParallelismScheme.NaiveThreads
                                                          ? (Action)this.FillMemoryBlocksSimpleThreaded
                                                          : this.FillMemoryBlocksThreaded;
            this.blake2RowAndColumnRoundsNoMsg = config.UnrollScheme == UnrollScheme.Full
                                                     ? Blake2RowAndColumnRoundsNoMsgFull
                                                     : config.UnrollScheme == UnrollScheme.Partial
                                                           ? (Action<BlockValues>)Blake2RowAndColumnRoundsNoMsgPartial
                                                           : Blake2RowAndColumnRoundsNoMsg;
            uint memoryBlocks = (uint)config.MemoryCost;
            if (memoryBlocks < 2 * SyncPoints * config.Lanes)
            {
                memoryBlocks = 2 * SyncPoints * (uint)config.Lanes;
            }

            this.SegmentLength = (int)(memoryBlocks / (config.Lanes * SyncPoints));

            // ensure that all segments have equal length
            this.LaneLength = this.SegmentLength * SyncPoints;
            this.MemoryBlockCount = this.LaneLength * this.Lanes;
            this.memory = new SecureArray<ulong>(BlockSize * this.MemoryBlockCount / 8);
            this.Memory = new Blocks(this.memory.Buffer, this.MemoryBlockCount);
        }

        /// <summary>
        /// Gets the Argon2 type. Default to data independent.
        /// </summary>
        public Argon2Type Type { get; }

        /// <summary>
        /// Gets the Argon2 version used in the password hash. Defaults to
        /// <see cref="Argon2Version"/>.<see cref="Argon2Version.Nineteen"/> (0x13).
        /// </summary>
        public Argon2Version Version { get; }

        /// <summary>
        /// Gets the time cost used in the password hash. Minimum of 1.
        /// </summary>
        /// <remarks>
        /// This is the number of iterations to perform. There are attacks on the
        /// <see cref="Argon2Version"/>.<see cref="Argon2Version.Sixteen"/> with less than
        /// three iterations (if I'm reading the paper correctly). So, use a value
        /// greater then 3 here if you are not using <see cref="Argon2Version"/>.<see
        /// cref="Argon2Version.Nineteen"/>.
        /// </remarks>
        public int TimeCost { get; }

        /// <summary>
        /// Gets the hash length to output. Minimum of 4.
        /// </summary>
        public int HashLength { get; }

        /// <summary>
        /// Gets a value indicating whether to clear the password as
        /// soon as it is no longer needed.
        /// </summary>
        /// <remarks>
        /// If true and the configuration has a password, the configuration
        /// cannot be used more than once without resetting the password
        /// (unless you want an all zero password).
        /// </remarks>
        public bool ClearPassword { get; }

        /// <summary>
        /// Gets the password to hash.
        /// </summary>
        public byte[] Password { get; }

        /// <summary>
        /// Gets the salt used in the password hash. If non-null, must be at least 8 bytes.
        /// </summary>
        public byte[] Salt { get; }

        /// <summary>
        /// Gets the secret used in the password hash.
        /// </summary>
        public byte[] Secret { get; }

        /// <summary>
        /// Gets the associated data used in the password hash.
        /// </summary>
        public byte[] AssociatedData { get; }

        /// <summary>
        /// Gets the lanes used in the password hash. Minimum of 1.
        /// </summary>
        /// <remarks>
        /// This describes the maximum parallelism that can be achieved. Each "lane" can
        /// be processed individually in its own thread.
        /// </remarks>
        public int Lanes { get; }

        /// <summary>
        /// Gets a value indicating whether to clear the secret as
        /// soon as it is no longer needed.
        /// </summary>
        /// <remarks>
        /// If true and the configuration has a secret, the configuration
        /// cannot be used more than once without resetting the secret
        /// (unless you want an all zero secret).
        /// </remarks>
        public bool ClearSecret { get; }

        /// <summary>
        /// Gets the memory cost used in the password hash. Minimum of 1.
        /// </summary>
        /// <remarks>
        /// This translates into the minimum memory used. The memory cost is the minimum number
        /// of 1024-byte blocks to used to perform the hash. If this value is less than
        /// 2 * <see cref="Argon2.SyncPoints"/> * <see cref="Lanes"/> then that value is used
        /// (<see cref="Argon2.SyncPoints"/> == 4).
        /// </remarks>
        public int MemoryCost { get; }

        /// <summary>
        /// Gets the <see cref="MemoryBlockCount"/> blocks.
        /// </summary>
        public Blocks Memory { get; }

        /// <summary>
        /// Gets the number of memory blocks (<see cref="Argon2Config.Lanes"/>*<see cref="LaneLength"/>).
        /// </summary>
        public int MemoryBlockCount { get; }

        /// <summary>
        /// Gets the segment length
        /// </summary>
        public int SegmentLength { get; }

        /// <summary>
        /// Gets the lane length
        /// </summary>
        public int LaneLength { get; }

        /// <summary>
        /// Perform the hash.
        /// </summary>
        /// <returns>
        /// The hash bytes.
        /// </returns>
        public SecureArray<byte> Hash()
        {
            this.Initialize();
            this.fillMemoryBlocks();
            return this.Final();
        }

        /// <summary>
        /// Zero sensitive memory and dispose of resources.
        /// </summary>
        public void Dispose()
        {
            this.memory?.Dispose();
        }
    }
}