// <copyright file="Argon2.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

using System.Linq;

namespace Isopoh.Cryptography.Argon2
{
    using System;
    using System.Collections.Generic;
    using Isopoh.Cryptography.SecureArray;

    /// <summary>
    /// Argon2 Hashing of passwords.
    /// </summary>
    public sealed partial class Argon2 : IDisposable
    {
        private readonly List<SecureArray<ulong>> memories = new List<SecureArray<ulong>>();
        private readonly Argon2Config config;

        /// <summary>
        /// Initializes a new instance of the <see cref="Argon2"/> class.
        /// </summary>
        /// <param name="config">
        /// The configuration to use.
        /// </param>
        public Argon2(Argon2Config config)
        {
            this.config = config;
            uint memoryBlocks = (uint)config.MemoryCost;
            if (memoryBlocks < 2 * SyncPoints * config.Lanes)
            {
                memoryBlocks = 2 * SyncPoints * (uint)config.Lanes;
            }

            this.SegmentLength = (int)(memoryBlocks / (config.Lanes * SyncPoints));

            // ensure that all segments have equal length
            this.LaneLength = this.SegmentLength * SyncPoints;
            this.MemoryBlockCount = this.LaneLength * this.config.Lanes;
            var blockCount = BlockSize * this.MemoryBlockCount / 8;
            while (blockCount > CsharpMaxBlocksPerArray)
            {
                this.memories.Add(SecureArray<ulong>.Best(QwordsInBlock * CsharpMaxBlocksPerArray, config.SecureArrayCall));
                blockCount -= CsharpMaxBlocksPerArray;
            }

            this.memories.Add(SecureArray<ulong>.Best(QwordsInBlock * blockCount, config.SecureArrayCall));
            this.Memory = new Blocks(this.memories.Select(m => m.Buffer));
        }

        /// <summary>
        /// Gets the <see cref="MemoryBlockCount"/> blocks.
        /// </summary>
        public Blocks Memory { get; }

        /// <summary>
        /// Gets the number of memories blocks (<see cref="Argon2Config.Lanes"/>*<see cref="LaneLength"/>).
        /// </summary>
        public int MemoryBlockCount { get; }

        /// <summary>
        /// Gets the segment length.
        /// </summary>
        public int SegmentLength { get; }

        /// <summary>
        /// Gets the lane length.
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
            this.FillMemoryBlocks();
            return this.Final();
        }

        /// <summary>
        /// Zero sensitive memories and dispose of resources.
        /// </summary>
        public void Dispose()
        {
            this.memories?.ForEach(m => m?.Dispose());
            this.memories?.Clear();
        }
    }
}