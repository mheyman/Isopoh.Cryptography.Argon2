// <copyright file="Argon2Memory.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2;

using System;
using System.Collections.Generic;
using System.Linq;
using Isopoh.Cryptography.Blake2b;
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

    /// <summary>
    /// Size in bytes required for the Argon2 working buffer.
    /// </summary>
    public const int Argon2WorkingBufferSize = Argon2InitWorkingBufferSize > Argon2FinalWorkingBufferSize
        ? Argon2InitWorkingBufferSize

        // ReSharper disable once HeuristicUnreachableCode
        : Argon2FinalWorkingBufferSize;

    /// <summary>
    /// The working buffer size Argon2 requires for the <see cref="Argon2.Initialize"/> stage. Argon2 never keys the Blake2B hash.
    /// </summary>
    private const int Argon2InitWorkingBufferSize =
        (2 * Argon2.BlockSize) + (2 * Blake2B.OutputLength) + Blake2B.NoKeyBufferMinimumTotalSize;

    /// <summary>
    /// The working buffer size Argon2 requires for the <see cref="Argon2.Final"/> stage. Argon2 never keys the Blake2B hash.
    /// </summary>
    private const int Argon2FinalWorkingBufferSize = Argon2.PrehashSeedLength + Argon2.BlockSize + (2 * Blake2B.OutputLength) + Blake2B.NoKeyBufferMinimumTotalSize;

    private readonly SecureArrayCall secureArrayCall;

    private readonly List<SecureArray<ulong>> blockSecureArrays = [];

    private readonly List<Memory<ulong>> blockMemories = [];

    private readonly SecureArray<byte>? argon2SecureArray;

    private SecureArray<ulong>? workingSecureArray;

    private Memory<ulong> fillMemoryBlocksWorkingBuffer;

    private SecureArray<byte>? hashSecureArray;

    private Memory<byte> hashMemory;

    private int hashLength;
    private Argon2MemoryPolicy shrinkMemoryPolicy;

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
        this.Config = (Argon2Config)config.Clone();
        this.secureArrayCall = this.Config.SecureArrayCall;
        this.FillMemoryBlocksWorkingBufferLength = this.Config.WorkingBufferLength;
        if (lockMemory.HasValue)
        {
            this.workingSecureArray = SecureArray<ulong>.Create(
                this.FillMemoryBlocksWorkingBufferLength,
                this.Config.SecureArrayCall,
                lockMemory.Value);
            this.fillMemoryBlocksWorkingBuffer = new Memory<ulong>(this.workingSecureArray.Buffer);
            this.argon2SecureArray = SecureArray<byte>.Create(Argon2WorkingBufferSize, this.secureArrayCall, lockMemory.Value);
            this.hashSecureArray = SecureArray<byte>.Create(this.Config.HashLength, this.secureArrayCall, lockMemory.Value);
            this.hashMemory = new Memory<byte>(this.hashSecureArray.Buffer);
            this.hashLength = this.Config.HashLength;
            this.Argon2WorkingBuffer = new Memory<byte>(this.argon2SecureArray.Buffer);
        }
        else
        {
            this.fillMemoryBlocksWorkingBuffer = new Memory<ulong>(new ulong[this.FillMemoryBlocksWorkingBufferLength]);
            this.Argon2WorkingBuffer = new Memory<byte>(new byte[Argon2WorkingBufferSize]);
            this.hashMemory = new Memory<byte>(new byte[this.Config.HashLength]);
            this.hashLength = this.Config.HashLength;
        }

        this.ShrinkMemoryPolicy = shrinkMemoryPolicy;
        this.LockMemory = lockMemory;
        this.BlockCount = 0;
        this.SegmentBlockCount = 0;
        this.LaneBlockCount = 0;
        this.Blocks = new Blocks(Array.Empty<Memory<ulong>>());
        this.ResetNoConfigClone();
    }

    /// <summary>
    /// Gets a value indicating whether the memory is currently in use.
    /// </summary>
    public bool InUse { get; private set; }

    /// <summary>
    /// Gets the <see cref="Argon2Config"/> associated with this <see cref="Argon2Memory"/>.
    /// </summary>
    public Argon2Config Config { get; private set; }

    /// <summary>
    /// Gets or sets the policy that determines whether to shrink memory when resetting with a new <see cref="Argon2Config"/>.
    /// </summary>
    public Argon2MemoryPolicy ShrinkMemoryPolicy
    {
        get => this.shrinkMemoryPolicy;
        set
        {
            if (this.InUse)
            {
                throw new InvalidOperationException("Attempt to set Argon2Memory ShrinkMemoryPolicy while memory currently in use.");
            }

            this.shrinkMemoryPolicy = value;
        }
    }

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
    /// Gets the ulong-based working buffer sized to be used in <see cref="Argon2.FillMemoryBlocks"/>.
    /// </summary>
    /// <remarks>
    /// This gets used and overwritten on every hash.
    /// <para/>
    /// Can change on every call to <see cref="Reset"/>.
    /// </remarks>
    public Memory<ulong> FillMemoryBlocksWorkingBuffer => this.fillMemoryBlocksWorkingBuffer.Slice(0, this.FillMemoryBlocksWorkingBufferLength);

    /// <summary>
    /// Gets the byte-based working buffer sized for Argon2 to use internally.
    /// </summary>
    /// <remarks>
    /// This gets used and overwritten on every hash.
    /// </remarks>
    public Memory<byte> Argon2WorkingBuffer { get; }

    /// <summary>
    /// Gets the span associated with the final Argon2 hash value.
    /// </summary>
    /// <remarks>
    /// This gets used and overwritten on every hash.
    /// <para/>
    /// Can change on every call to <see cref="Reset"/>.
    /// </remarks>
    public Span<byte> Hash => this.hashMemory.Span.Slice(0, this.hashLength);

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
    /// <remarks>
    /// This gets used and overwritten on every hash.
    /// <para/>
    /// Can change on every call to <see cref="Reset"/>.
    /// </remarks>
    public Blocks Blocks { get; private set; }

    /// <summary>
    /// Gets the required block count for the given <see cref="Argon2Config"/>.
    /// </summary>
    /// <param name="config">Used to determine the required block count.</param>
    /// <returns>The required segment, lane, and total block count for the given <see cref="Argon2Config"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="config"/> is null.</exception>
    public static (int SegmentBlockCount, int LaneBlockCount, ulong BlockCount) RequiredBlockCounts(Argon2Config config)
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
        if (this.InUse)
        {
            throw new InvalidOperationException("Attempt to reset Argon2Memory currently in use.");
        }

        this.Config = (Argon2Config)config.Clone();
        this.ResetNoConfigClone();
    }

    /// <summary>
    /// Dispose.
    /// </summary>
    public void Dispose()
    {
        this.Clear();
    }

    /// <summary>
    /// Start the use of this memory. <see cref="Argon2Memory"/> should not be used by more than one hash operation as a time.
    /// </summary>
    public void StartUse()
    {
        this.InUse = true;
    }

    /// <summary>
    /// Mark this memory as free to use again.
    /// </summary>
    public void EndUse()
    {
        this.InUse = false;
    }

    private void ResetNoConfigClone()
    {
        // +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+--------
        // |Block|Block|Block|Block|Block|Block|Block|Block|Block|Block|Block
        // +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+--------
        // +-----------------------------------+--------------------------------
        // | Memory (2GB)                      | Memory (2GB)
        // +-----------------------------------+--------------------------------
        var (segmentBlockCount, laneBlockCount, requiredMemoryBlockCount) = RequiredBlockCounts(this.Config);
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
            this.ResetNoSecureArray(this.Config, requiredMemoryBlockCount);
            return;
        }

        LockMemoryPolicy lockMemory = this.LockMemory.Value;
        if (this.FillMemoryBlocksWorkingBufferLength != this.Config.WorkingBufferLength)
        {
            if ((this.ShrinkMemoryPolicy == Argon2MemoryPolicy.Shrink && this.FillMemoryBlocksWorkingBufferLength > this.Config.WorkingBufferLength) || this.fillMemoryBlocksWorkingBuffer.Length < this.Config.WorkingBufferLength)
            {
                this.workingSecureArray = SecureArray<ulong>.Create(this.Config.WorkingBufferLength, this.Config.SecureArrayCall, lockMemory);
                this.fillMemoryBlocksWorkingBuffer = new Memory<ulong>(this.workingSecureArray.Buffer);
            }

            this.FillMemoryBlocksWorkingBufferLength = this.Config.WorkingBufferLength;
        }

        if (this.hashLength != this.Config.HashLength)
        {
            if ((this.ShrinkMemoryPolicy == Argon2MemoryPolicy.Shrink && this.hashLength > this.Config.HashLength) || this.hashMemory.Length < this.Config.HashLength)
            {
                this.hashSecureArray = SecureArray<byte>.Create(this.Config.HashLength, this.Config.SecureArrayCall, lockMemory);
                this.hashMemory = new Memory<byte>(this.hashSecureArray.Buffer);
            }

            this.hashLength = this.Config.HashLength;
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
                $" memory cost {this.Config.MemoryCost}, lane count {this.Config.Lanes}.",
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

        if (this.hashLength != config.HashLength)
        {
            if ((this.ShrinkMemoryPolicy == Argon2MemoryPolicy.Shrink && this.hashLength > config.HashLength) || this.hashMemory.Length < config.HashLength)
            {
                this.hashMemory = new Memory<byte>(new byte[config.HashLength]);
            }

            this.hashLength = config.HashLength;
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
        this.argon2SecureArray?.Dispose();
        this.hashSecureArray?.Dispose();
        this.blockSecureArrays.Clear();
        this.blockMemories.Clear();
        this.FillMemoryBlocksWorkingBufferLength = 0;
        this.BlockCount = 0;
        this.SegmentBlockCount = 0;
        this.LaneBlockCount = 0;
    }
}