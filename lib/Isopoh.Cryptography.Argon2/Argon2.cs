// <copyright file="Argon2.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2;

using System;
using System.Collections.Generic;
using System.Linq;
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
        this.Config = config ?? throw new ArgumentNullException(nameof(config), "Argon2 requires configuration information. Accepting the defaults except for the password is fine.");
        this.memory = new Argon2Memory(this.Config, Argon2MemoryPolicy.NoShrink, LockMemoryPolicy.BestEffort);
        this.memoryIsOwned = true;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Argon2"/> class.
    /// </summary>
    /// <param name="config">
    /// The configuration to use.
    /// </param>
    /// <param name="memory">The memory to use for the hash.</param>
    /// <param name="memoryPolicy">Whether to shrink the memory to fit.</param>
    public Argon2(Argon2Config config, Argon2Memory memory, Argon2MemoryPolicy memoryPolicy = Argon2MemoryPolicy.NoShrink)
    {
        this.Config = config ?? throw new ArgumentNullException(nameof(config), "Argon2 requires configuration information. Accepting the defaults except for the password is fine.");
        this.memory = memory;
        this.memoryIsOwned = false;
        this.memory.Reset(this.Config);
    }

    /// <summary>
    /// Gets the <see cref="Argon2Config"/> for this hash.
    /// </summary>
    public Argon2Config Config { get; }

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
    public SecureArray<byte> Hash()
    {
        using SecureArray<ulong> workingBuffer = SecureArray<ulong>.Best(this.Config.WorkingBufferLength, this.Config.SecureArrayCall);
        return this.Hash(workingBuffer.Buffer.AsMemory());
    }

    /// <summary>
    /// Perform the hash.
    /// </summary>
    /// <param name="workingBuffer">Memory used during the hash operation. Must be at least <see cref="Config"/> <see cref="Argon2Config.WorkingBufferLength"/> in length.</param>
    /// <returns>
    /// The hash bytes.
    /// </returns>
    public SecureArray<byte> Hash(Memory<ulong> workingBuffer)
    {
        int wbLength = this.Config.WorkingBufferLength;
        Memory<ulong> wb = workingBuffer.Length >= wbLength
            ? workingBuffer.Slice(0, wbLength)
            : throw new ArgumentException(
                $"Expected the working buffer to be at least of length {wbLength}, got {workingBuffer.Length}",
                nameof(workingBuffer));
        this.Initialize();
        this.FillMemoryBlocks(wb);
        return this.Final();
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