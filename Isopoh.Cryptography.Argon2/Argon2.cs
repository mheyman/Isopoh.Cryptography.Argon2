﻿// <copyright file="Argon2.cs" company="Isopoh">
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
            if (memoryBlocks < 2 * SyncPointCount * config.Lanes)
            {
                memoryBlocks = 2 * SyncPointCount * (uint)config.Lanes;
            }

            this.SegmentBlockCount = (int)(memoryBlocks / (config.Lanes * SyncPointCount));

            // ensure that all segments have equal length
            this.LaneBlockCount = this.SegmentBlockCount * SyncPointCount;
            this.MemoryBlockCount = this.LaneBlockCount * config.Lanes;
            var blockCount = (ulong)QwordsInBlock * (ulong)this.MemoryBlockCount;
            try
            {
                while (blockCount > CsharpMaxBlocksPerArray)
                {
                    this.memories.Add(SecureArray<ulong>.Best(QwordsInBlock * CsharpMaxBlocksPerArray, config.SecureArrayCall));
                    blockCount -= CsharpMaxBlocksPerArray;
                }

                this.memories.Add(SecureArray<ulong>.Best(QwordsInBlock * (int) blockCount, config.SecureArrayCall));
            }
            catch (OutOfMemoryException e)
            {
                var memoryCount = this.memories.Count;

                // be nice, clear allocated memory that will never be used sooner rather than later
                this.memories?.ForEach(m => m?.Dispose());
                this.memories?.Clear();
                throw new OutOfMemoryException(
                    $"Failed to allocate {(blockCount > CsharpMaxBlocksPerArray ? CsharpMaxBlocksPerArray : blockCount) * QwordsInBlock}-byte Argon2 block array, " +
                    $"{(memoryCount > 0 ? $" allocation {memoryCount + 1} of multiple-allocation," : string.Empty)}" +
                    $" memory cost {config.MemoryCost}, lane count {config.Lanes}.",
                    e);
            }
            catch (Exception)
            {
                // be nice, clear allocated memory that will never be used sooner rather than later
                this.memories?.ForEach(m => m?.Dispose());
                this.memories?.Clear();
                throw;
            }

            this.Memory = new Blocks(this.memories.Select(m => m.Buffer));
        }

        /// <summary>
        /// Gets the <see cref="MemoryBlockCount"/> blocks.
        /// </summary>
        public Blocks Memory { get; }

        /// <summary>
        /// Gets the number of memory blocks, (<see cref="Argon2Config.Lanes"/>*<see cref="LaneBlockCount"/>).
        /// </summary>
        public int MemoryBlockCount { get; }

        /// <summary>
        /// Gets the number of memory blocks per segment. This value gets
        /// derived from the memory cost. The memory cost value is a request
        /// for that number of blocks. If that request is less than (2 *
        /// <see cref="SyncPointCount"/>) times the number of lanes requested,
        /// it is first bumped up to that amount. Then, it may be reduced to
        /// fit on a <see cref="SyncPointCount"/> times the number of lanes
        /// requested boundary.
        /// </summary>
        public int SegmentBlockCount { get; }

        /// <summary>
        /// Gets the number of memory blocks per lane. <see cref="SegmentBlockCount"/> * <see cref="SyncPointCount"/>.
        /// </summary>
        public int LaneBlockCount { get; }

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