﻿// <copyright file="Argon2Memory.cs" company="Isopoh">
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
/// Whether to shrink memory if <see cref="Argon2Config"/> changes to need less memory.
/// </summary>
public enum Argon2MemoryPolicy
{
    /// <summary>
    /// Shrink if <see cref="Argon2Config"/> requires less memory than currently allocated.
    /// </summary>
    Shrink,

    /// <summary>
    /// Don't shrink even inf <see cref="Argon2Config"/> requires less memory than currently allocated.
    /// </summary>
    NoShrink,
}

/// <summary>
/// Manages memory for a <see cref="Argon2"/>.
/// </summary>
public sealed class Argon2Memory
    : IDisposable
{
    /// <summary>
    /// C# has a limit of 0X7FEFFFFF elements per array (0x7FFFFFC7 per byte array). The blocks are
    /// 1024 bytes long, the elements are 8 bytes (ulong). This gives 0X7FEFFFFF / 128 blocks per
    /// C# array.
    /// </summary>
    public const int CsharpMaxBlocksPerArray = 0X7FEFFFFF / Argon2.QwordsInBlock;

    private readonly SecureArrayCall secureArrayCall;

    private readonly List<SecureArray<ulong>> blockSecureArrays = [];

    private readonly List<Memory<ulong>> blockMemories = [];

    private SecureArray<ulong>? workingSecureArray;

    private Memory<ulong> fillMemoryBlocksWorkingBuffer;

    private SecureArray<byte> blake2BSecureArray;

    /// <summary>
    /// Initializes a new instance of the <see cref="Argon2Memory"/> class.
    /// </summary>
    /// <param name="config">The initial configuration to use. Can be updated later with a call to <see cref="Reset"/>.</param>
    /// <param name="shrinkMemoryPolicy">
    /// Indicates whether to shrink memory to fit upon calling <see cref="Reset"/> with an <see cref="Argon2Config"/>
    /// that requires less memory. Note: the memory will always grow as needed.</param>
    /// <param name="lockMemory">The lock memory policy to use. Null to not secure memory at all.</param>
    public Argon2Memory(Argon2Config config, Argon2MemoryPolicy shrinkMemoryPolicy, LockMemoryPolicy? lockMemory)
    {
        this.secureArrayCall = config.SecureArrayCall;
        this.FillMemoryBlocksWorkingBufferLength = config.WorkingBufferLength;
        if (lockMemory.HasValue)
        {
            this.workingSecureArray = SecureArray<ulong>.Create(
                this.FillMemoryBlocksWorkingBufferLength,
                config.SecureArrayCall,
                lockMemory.Value);
            this.fillMemoryBlocksWorkingBuffer = new Memory<ulong>(this.workingSecureArray.Buffer);
            this.blake2BSecureArray = SecureArray<byte>.Create(Blake2b.Blake2B.OutputLength * 2 + Blake2b.Blake2B.BufferMinimumTotalSize, this.secureArrayCall, lockMemory.Value);
            this.Blake2BLongWorkingBuffer = new Memory<byte>(this.blake2BSecureArray.Buffer, Blake2b.Blake2B.BufferMinimumTotalSize, 2 * Blake2b.Blake2B.OutputLength);
            this.Blake2bWorkingBuffer = new Memory<byte>(this.blake2BSecureArray.Buffer, 0, Blake2b.Blake2B.BufferMinimumTotalSize);
        }
        else
        {
            this.fillMemoryBlocksWorkingBuffer = new Memory<ulong>(new ulong[this.FillMemoryBlocksWorkingBufferLength]);
            this.Blake2BLongWorkingBuffer = new Memory<byte>(new byte[Blake2b.Blake2B.OutputLength * 2]);
            this.Blake2bWorkingBuffer = new Memory<byte>(new byte[Blake2b.Blake2B.BufferMinimumTotalSize]);
        }

        this.ShrinkMemoryPolicy = shrinkMemoryPolicy;
        this.LockMemory = lockMemory;
        this.BlockCount = 0;
        this.SegmentBlockCount = 0;
        this.LaneBlockCount = 0;
        this.Blocks = new Blocks(Array.Empty<Memory<ulong>>());
        this.Reset(config);
    }

    /// <summary>
    /// Gets or sets the policy that determines whether to shrink memory when resetting with a new <see cref="Argon2Config"/>.
    /// </summary>
    public Argon2MemoryPolicy ShrinkMemoryPolicy { get; set; }

    /// <summary>
    /// Gets the lock memory policy. Null to not secure arrays at all.
    /// </summary>
    public LockMemoryPolicy? LockMemory { get; }

    /// <summary>
    /// Gets the count of ulong values in the <see cref="FillMemoryBlocksWorkingBuffer"/>.
    /// </summary>
    /// <remarks>
    /// Can change on every call to <see cref="Reset"/>.
    /// </remarks>
    public int FillMemoryBlocksWorkingBufferLength { get; private set; }

    /// <summary>
    /// Gets the working buffer sized to be used in <see cref="Argon2.FillMemoryBlocks"/>.
    /// </summary>
    /// <remarks>
    /// Can change on every call to <see cref="Reset"/>.
    /// </remarks>
    public Memory<ulong> FillMemoryBlocksWorkingBuffer => this.fillMemoryBlocksWorkingBuffer.Slice(0, this.FillMemoryBlocksWorkingBufferLength);

    /// <summary>
    /// Gets the working buffer sized for BLake2B hashing.
    /// </summary>
    public Memory<byte> Blake2BLongWorkingBuffer { get; }

    /// <summary>
    /// Gets the working buffer sized for BLake2B hashing.
    /// </summary>
    public Memory<byte> Blake2bWorkingBuffer { get; }

    /// <summary>
    /// Gets the memory block count for the latest <see cref="Argon2Config"/> that this <see cref="Argon2Memory"/> supports.
    /// </summary>
    /// <remarks>
    /// Can change on every call to <see cref="Reset"/>.
    /// </remarks>
    public int BlockCount { get; private set; }

    /// <summary>
    /// Gets the number of memory blocks per segment. This value gets
    /// derived from the memory cost. The memory cost value is a request
    /// for that number of blocks. If that request is less than (2 *
    /// <see cref="Argon2.SyncPointCount"/>) times the number of lanes requested,
    /// it is first bumped up to that amount. Then, it may be reduced to
    /// fit on a <see cref="Argon2.SyncPointCount"/> times the number of lanes
    /// requested boundary.
    /// </summary>
    /// <remarks>
    /// Can change on every call to <see cref="Reset"/>.
    /// </remarks>
    public int SegmentBlockCount { get; private set; }

    /// <summary>
    /// Gets the number of memory blocks per lane. <see cref="SegmentBlockCount"/> * <see cref="Argon2.SyncPointCount"/>.
    /// </summary>
    /// <remarks>
    /// Can change on every call to <see cref="Reset"/>.
    /// </remarks>
    public int LaneBlockCount { get; private set; }

    /// <summary>
    /// Gets the <see cref="Blocks"/> for this <see cref="Argon2Memory"/>.
    /// </summary>
    public Blocks Blocks { get; private set; }

    /// <summary>
    /// Gets the required block count for the given <see cref="Argon2Config"/>.
    /// </summary>
    /// <param name="config">Used to determine the required block count.</param>
    /// <returns>The required block count for the given <see cref="Argon2Config"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="config"/> is null.</exception>
    public static (int, int, ulong) RequiredBlockCount(Argon2Config config)
    {
        if (config == null)
        {
            throw new ArgumentNullException(
                nameof(config),
                "Argon2 requires configuration information. Accepting the defaults except for the password is fine.");
        }

        var minimumMemoryCost = config.MemoryCost < (2 * Argon2.SyncPointCount * config.Lanes)
            ? (uint)(2 * Argon2.SyncPointCount * config.Lanes)
            : (uint)config.MemoryCost;

        var segmentBlockCount = (int)(minimumMemoryCost / (config.Lanes * Argon2.SyncPointCount));

        // ensure that all segments have equal length
        var laneBlockCount = segmentBlockCount * Argon2.SyncPointCount;
        return (segmentBlockCount, laneBlockCount, (ulong)(laneBlockCount * config.Lanes));
    }

    /// <summary>
    /// Reset this <see cref="Argon2Memory"/> to what the given <see cref="Argon2Config"/> requires.
    /// </summary>
    /// <param name="config">
    /// The configuration used to determine memory required.
    /// </param>
    /// <exception cref="OutOfMemoryException">
    /// If the memory could not be allocated. Usually because of operating system
    /// enforced limits on securing the allocated arrays.
    /// </exception>
    public void Reset(Argon2Config config)
    {
        // +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+--------
        // |Block|Block|Block|Block|Block|Block|Block|Block|Block|Block|Block
        // +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+--------
        // +-----------------------------------+--------------------------------
        // | Memory (2GB)                      | Memory (2GB)
        // +-----------------------------------+--------------------------------
        var (segmentBlockCount, laneBlockCount, requiredMemoryBlockCount) = RequiredBlockCount(config);
        this.BlockCount = (int)requiredMemoryBlockCount;
        this.SegmentBlockCount = segmentBlockCount;
        this.LaneBlockCount = laneBlockCount;
        if (requiredMemoryBlockCount == 0)
        {
            if (this.ShrinkMemoryPolicy == Argon2MemoryPolicy.Shrink)
            {
                this.blockSecureArrays.ForEach(m => m.Dispose());
                this.blockSecureArrays.Clear();
                this.blockMemories.Clear();
                this.Blocks = new Blocks(Array.Empty<Memory<ulong>>());
            }

            return;
        }

        if (this.LockMemory == null)
        {
            this.ResetNoSecureArray(config, requiredMemoryBlockCount);
            return;
        }

        LockMemoryPolicy lockMemory = this.LockMemory.Value;
        if (this.FillMemoryBlocksWorkingBufferLength != config.WorkingBufferLength)
        {
            if ((this.ShrinkMemoryPolicy == Argon2MemoryPolicy.Shrink && this.FillMemoryBlocksWorkingBufferLength > config.WorkingBufferLength) || this.fillMemoryBlocksWorkingBuffer.Length < config.WorkingBufferLength)
            {
                this.workingSecureArray = SecureArray<ulong>.Create(config.WorkingBufferLength, config.SecureArrayCall, lockMemory);
                this.fillMemoryBlocksWorkingBuffer = new Memory<ulong>(this.workingSecureArray.Buffer);
            }

            this.FillMemoryBlocksWorkingBufferLength = config.WorkingBufferLength;
        }

        var currentMemoryBlockCount = this.blockMemories.Aggregate(0UL, (sum, m) => sum + (ulong)(m.Length / Argon2.QwordsInBlock));
        if (requiredMemoryBlockCount > currentMemoryBlockCount && this.ShrinkMemoryPolicy == Argon2MemoryPolicy.Shrink)
        {
            var remainingMemoryBlockCount = currentMemoryBlockCount;
            while (true)
            {
                var lastMemoryBlockCount = (ulong)(this.blockMemories[this.blockMemories.Count - 1].Length / Argon2.QwordsInBlock);
                if (remainingMemoryBlockCount - lastMemoryBlockCount < requiredMemoryBlockCount)
                {
                    break;
                }

                this.blockSecureArrays.RemoveAt(this.blockSecureArrays.Count - 1);
                this.blockMemories.RemoveAt(this.blockMemories.Count - 1);
            }
        }

        try
        {
            var fullMemoriesCount = requiredMemoryBlockCount / CsharpMaxBlocksPerArray;
            var lastMemoryBlockCount = (int)(requiredMemoryBlockCount % CsharpMaxBlocksPerArray);
            if (lastMemoryBlockCount == 0)
            {
                --fullMemoriesCount;
                lastMemoryBlockCount = CsharpMaxBlocksPerArray;
            }

            if (this.blockSecureArrays.Count == 0)
            {
                this.blockSecureArrays.Add(
                    SecureArray<ulong>.Create(
                        lastMemoryBlockCount * Argon2.QwordsInBlock,
                        this.secureArrayCall,
                        lockMemory));
                this.blockMemories.Add(this.blockSecureArrays[0].Buffer);
            }

            var lastSecureArray = this.blockSecureArrays[this.blockSecureArrays.Count - 1];
            this.blockSecureArrays.RemoveAt(this.blockSecureArrays.Count - 1);
            this.blockMemories.RemoveAt(this.blockMemories.Count - 1);

            for (var i = (ulong)this.blockSecureArrays.Count; i < fullMemoriesCount; ++i)
            {
                SecureArray<ulong> secureArray = SecureArray<ulong>.Create(
                    CsharpMaxBlocksPerArray * Argon2.QwordsInBlock,
                    this.secureArrayCall,
                    lockMemory);
                this.blockSecureArrays.Add(secureArray);
                this.blockMemories.Add(secureArray.Buffer);
            }

            if (lastMemoryBlockCount > lastSecureArray.Buffer.Length / Argon2.QwordsInBlock)
            {
                lastSecureArray = SecureArray<ulong>.Create(
                    lastMemoryBlockCount * Argon2.QwordsInBlock,
                    this.secureArrayCall,
                    lockMemory);
            }

            this.blockSecureArrays.Add(lastSecureArray);
            this.blockMemories.Add(lastSecureArray.Buffer);
            this.Blocks = new Blocks(this.blockMemories);
        }
        catch (OutOfMemoryException e)
        {
            this.Blocks = new Blocks(Array.Empty<Memory<ulong>>());
            int memoryCount = this.blockMemories.Count;

            // be nice, clear allocated memory that will never be used sooner rather than later
            this.Clear();
#pragma warning disable S112
            throw new OutOfMemoryException(
                $"Failed to allocate {(requiredMemoryBlockCount > Argon2Memory.CsharpMaxBlocksPerArray ? Argon2Memory.CsharpMaxBlocksPerArray : requiredMemoryBlockCount) * Argon2.QwordsInBlock}-byte Argon2 block array, " +
                $"{(memoryCount > 0 ? $" allocation {memoryCount + 1} of multiple-allocation," : string.Empty)}" +
                $" memory cost {config.MemoryCost}, lane count {config.Lanes}.",
                e);
#pragma warning restore S112
        }
        catch (Exception)
        {
            this.Blocks = new Blocks(Array.Empty<Memory<ulong>>());

            // be nice, clear allocated memory that will never be used sooner rather than later
            this.Clear();
            throw;
        }
    }

    /// <summary>
    /// Dispose.
    /// </summary>
    public void Dispose()
    {
        this.Clear();
    }

    private void ResetNoSecureArray(Argon2Config config, ulong requiredMemoryBlockCount)
    {
        if (this.FillMemoryBlocksWorkingBufferLength != config.WorkingBufferLength)
        {
            if ((this.ShrinkMemoryPolicy == Argon2MemoryPolicy.Shrink && this.FillMemoryBlocksWorkingBufferLength > config.WorkingBufferLength) || this.fillMemoryBlocksWorkingBuffer.Length < config.WorkingBufferLength)
            {
                this.fillMemoryBlocksWorkingBuffer = new Memory<ulong>(new ulong[config.WorkingBufferLength]);
            }

            this.FillMemoryBlocksWorkingBufferLength = config.WorkingBufferLength;
        }
        
        // +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+--------
        // |Block|Block|Block|Block|Block|Block|Block|Block|Block|Block|Block
        // +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+--------
        // +-----------------------------------+--------------------------------
        // | Memory (2GB)                      | Memory (2GB)
        // +-----------------------------------+--------------------------------

        var currentMemoryBlockCount = this.blockMemories.Aggregate(0UL, (sum, m) => sum + (ulong)(m.Length / Argon2.QwordsInBlock));
        if (requiredMemoryBlockCount > currentMemoryBlockCount && this.ShrinkMemoryPolicy == Argon2MemoryPolicy.Shrink)
        {
            var remainingMemoryBlockCount = currentMemoryBlockCount;
            while (true)
            {
                var lastMemoryBlockCount = (ulong)(this.blockMemories[this.blockMemories.Count - 1].Length / Argon2.QwordsInBlock);
                if (remainingMemoryBlockCount - lastMemoryBlockCount < requiredMemoryBlockCount)
                {
                    break;
                }

                this.blockMemories.RemoveAt(this.blockMemories.Count - 1);
            }
        }

        try
        {
            var fullMemoriesCount = requiredMemoryBlockCount / CsharpMaxBlocksPerArray;
            var lastMemoryBlockCount = (int)(requiredMemoryBlockCount % CsharpMaxBlocksPerArray);
            if (lastMemoryBlockCount == 0)
            {
                --fullMemoriesCount;
                lastMemoryBlockCount = CsharpMaxBlocksPerArray;
            }

            if (this.blockMemories.Count == 0)
            {
                this.blockMemories.Add(new ulong[lastMemoryBlockCount * Argon2.QwordsInBlock]);
            }

            var lastMemory = this.blockMemories[this.blockMemories.Count - 1];
            this.blockMemories.RemoveAt(this.blockMemories.Count - 1);

            for (var i = (ulong)this.blockMemories.Count; i < fullMemoriesCount; ++i)
            {
                this.blockMemories.Add(new ulong[CsharpMaxBlocksPerArray * Argon2.QwordsInBlock]);
            }

            if (lastMemoryBlockCount > lastMemory.Length / Argon2.QwordsInBlock)
            {
                lastMemory = new ulong[lastMemoryBlockCount * Argon2.QwordsInBlock];
            }

            this.blockMemories.Add(lastMemory);
            this.Blocks = new Blocks(this.blockMemories);
        }
        catch (OutOfMemoryException e)
        {
            this.Blocks = new Blocks(Array.Empty<Memory<ulong>>());
            int memoryCount = this.blockMemories.Count;

            // be nice, clear allocated memory that will never be used sooner rather than later
            this.Clear();
#pragma warning disable S112
            throw new OutOfMemoryException(
                $"Failed to allocate {(requiredMemoryBlockCount > Argon2Memory.CsharpMaxBlocksPerArray ? Argon2Memory.CsharpMaxBlocksPerArray : requiredMemoryBlockCount) * Argon2.QwordsInBlock}-byte Argon2 block array, " +
                $"{(memoryCount > 0 ? $" allocation {memoryCount + 1} of multiple-allocation," : string.Empty)}" +
                $" memory cost {config.MemoryCost}, lane count {config.Lanes}.",
                e);
#pragma warning restore S112
        }
        catch (Exception)
        {
            this.Blocks = new Blocks(Array.Empty<Memory<ulong>>());

            // be nice, clear allocated memory that will never be used sooner rather than later
            this.Clear();
            throw;
        }
    }

    private void Clear()
    {
        this.blockSecureArrays.ForEach(m => m.Dispose());
        this.workingSecureArray?.Dispose();
        this.blake2BSecureArray?.Dispose();
        this.blockSecureArrays.Clear();
        this.blockMemories.Clear();
        this.FillMemoryBlocksWorkingBufferLength = 0;
        this.BlockCount = 0;
        this.SegmentBlockCount = 0;
        this.LaneBlockCount = 0;
    }
}