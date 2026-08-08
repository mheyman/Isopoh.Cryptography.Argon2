// <copyright file="Argon2.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2;

using System;
using Isopoh.Cryptography.SecureArray;

/// <summary>
/// Argon2 Hashing of passwords.
/// </summary>
public sealed partial class Argon2 : IDisposable
{
    private readonly bool memoryIsOwned = false;
    private readonly Argon2Memory memory;

    /// <summary>
    /// Initializes a new instance of the <see cref="Argon2"/> class.
    /// </summary>
    /// <param name="config">
    /// The configuration to use.
    /// </param>
    public Argon2(Argon2Config config)
    {
        if (config == null)
        {
            throw new ArgumentNullException(
                nameof(config),
                "Argon2 requires configuration information. Accepting the defaults except for the password is fine.");
        }

        this.memory = new Argon2Memory(config, Argon2MemoryPolicy.NoShrink, LockMemoryPolicy.BestEffort);
        this.memoryIsOwned = true;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Argon2"/> class.
    /// </summary>
    /// <param name="memory">The memory (and <see cref="Argon2Config"/>) to use for the hash.</param>
    public Argon2(Argon2Memory memory)
    {
        if (memory == null)
        {
            throw new ArgumentNullException(
                nameof(memory),
                "Argon2 requires configuration information. Accepting the defaults except for the password is fine.");
        }

        this.memory = memory;
        this.memoryIsOwned = false;
    }

    /// <summary>
    /// Gets the <see cref="MemoryBlockCount"/> blocks.
    /// </summary>
    public Blocks Memory => this.memory.Blocks;

    /// <summary>
    /// Gets the number of memory blocks, (<see cref="Argon2Config.Lanes"/>*<see cref="LaneBlockCount"/>).
    /// </summary>
    public int MemoryBlockCount => this.memory.BlockCount;

    /// <summary>
    /// Gets the number of memory blocks per segment. This value gets
    /// derived from the memory cost. The memory cost value is a request
    /// for that number of blocks. If that request is less than (2 *
    /// <see cref="Argon2.SyncPointCount"/>) times the number of lanes requested,
    /// it is first bumped up to that amount. Then, it may be reduced to
    /// fit on a <see cref="Argon2.SyncPointCount"/> times the number of lanes
    /// requested boundary.
    /// </summary>
    public int SegmentBlockCount => this.memory.SegmentBlockCount;

    /// <summary>
    /// Gets the number of memory blocks per lane. <see cref="SegmentBlockCount"/> * <see cref="SyncPointCount"/>.
    /// </summary>
    public int LaneBlockCount => this.memory.LaneBlockCount;

    /// <summary>
    /// Perform the hash.
    /// </summary>
    /// <returns>
    /// The hash bytes.
    /// </returns>
    public Span<byte> Hash()
    {
        try
        {
            this.memory.StartUse();
            this.Initialize(this.memory.Argon2WorkingBuffer);
            this.FillMemoryBlocks(this.memory.FillMemoryBlocksWorkingBuffer);
            this.Final(this.memory.Hash, this.memory.Argon2WorkingBuffer);
            return this.memory.Hash;
        }
        finally
        {
            this.memory.EndUse();
        }
    }

    /// <summary>
    /// Zero sensitive memories and dispose of resources.
    /// </summary>
    public void Dispose()
    {
        if (this.memoryIsOwned)
        {
            this.memory.Dispose();
        }
    }
}