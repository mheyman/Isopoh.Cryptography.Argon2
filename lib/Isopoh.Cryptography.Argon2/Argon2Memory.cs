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
    private Argon2Config config;

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
        this.config = (Argon2Config)config.Clone();
        this.secureArrayCall = this.config.SecureArrayCall;
        this.FillMemoryBlocksWorkingBufferLength = this.config.WorkingBufferLength;
        if (lockMemory.HasValue)
        {
            this.workingSecureArray = SecureArray<ulong>.Create(
                this.FillMemoryBlocksWorkingBufferLength,
                this.config.SecureArrayCall,
                lockMemory.Value);
            this.fillMemoryBlocksWorkingBuffer = new Memory<ulong>(this.workingSecureArray.Buffer);
            this.argon2SecureArray = SecureArray<byte>.Create(Argon2WorkingBufferSize, this.secureArrayCall, lockMemory.Value);
            this.hashSecureArray = SecureArray<byte>.Create(this.config.HashLength, this.secureArrayCall, lockMemory.Value);
            this.hashMemory = new Memory<byte>(this.hashSecureArray.Buffer);
            this.hashLength = this.config.HashLength;
            this.Argon2WorkingBuffer = new Memory<byte>(this.argon2SecureArray.Buffer);
        }
        else
        {
            this.fillMemoryBlocksWorkingBuffer = new Memory<ulong>(new ulong[this.FillMemoryBlocksWorkingBufferLength]);
            this.Argon2WorkingBuffer = new Memory<byte>(new byte[Argon2WorkingBufferSize]);
            this.hashMemory = new Memory<byte>(new byte[this.config.HashLength]);
            this.hashLength = this.config.HashLength;
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
    /// Gets the lanes used in the password hash. Minimum of 1. Defaults to 4.
    /// </summary>
    /// <remarks>
    /// This describes the maximum parallelism that can be achieved. Each "lane" can
    /// be processed individually in its own thread. Setting <see cref="Threads"/>
    /// to a value greater than one when there is more than one lane will allow the
    /// use of multiple cores to speed up hashing.
    /// </remarks>
    public int Lanes => this.config.Lanes;

    /// <summary>
    /// Gets the hash length to output. Minimum of 4. Default 32.
    /// </summary>
    public int HashLength => this.config.HashLength;

    /// <summary>
    /// Gets the memory cost used in the password hash. Minimum of 1. Defaults to 65536.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This translates into a target count of memory blocks to use for hashing. A memory block
    /// is 1024 bytes so the default 65536 is for a 64MB hash.
    /// </para>
    /// <para>
    /// If this value is less than 2*<see cref="Argon2.SyncPointCount"/>*<see cref="Lanes"/>,
    /// than 2*<see cref="Argon2.SyncPointCount"/>*<see cref="Lanes"/> will be used.
    /// </para>
    /// <para>
    /// If this value is not a multiple of <see cref="Argon2.SyncPointCount"/>*<see
    /// cref="Lanes"/>, then it is rounded down to a multiple of <see
    /// cref="Argon2.SyncPointCount"/>*<see cref="Lanes"/>.
    /// </para>
    /// </remarks>
    public int MemoryCost => this.config.MemoryCost;

    /// <summary>
    /// Gets the time cost used in the password hash. Minimum of 1. Defaults to 3.
    /// </summary>
    /// <remarks>
    /// This is the number of iterations to perform. There are attacks on the
    /// <see cref="Argon2Version"/>.<see cref="Argon2Version.Sixteen"/> with less than
    /// three iterations (if I'm reading the paper correctly). So, use a value
    /// greater than 3 here if you are not using <see cref="Argon2Version"/>.<see
    /// cref="Argon2Version.Nineteen"/>.
    /// </remarks>
    public int TimeCost => this.config.TimeCost;

    /// <summary>
    /// Gets the Argon2 version used in the password hash. Defaults to
    /// <see cref="Argon2Version"/>.<see cref="Argon2Version.Nineteen"/> (0x13).
    /// </summary>
    public Argon2Version Version => this.config.Version;

    /// <summary>
    /// Gets the Argon2 type. Default to hybrid.
    /// </summary>
    public Argon2Type Type => this.config.Type;

    /// <summary>
    /// Gets the password to hash.
    /// </summary>
    public byte[]? Password => this.config.Password;

    /// <summary>
    /// Gets a value indicating whether to clear the password as
    /// soon as it is no longer needed.
    /// </summary>
    /// <remarks>
    /// If true and the configuration has a password, the configuration
    /// cannot be used more than once without resetting the password
    /// (unless you want an all zero password).
    /// </remarks>
    public bool ClearPassword => this.config.ClearPassword;

    /// <summary>
    /// Gets the salt used in the password hash. If non-null, must be at least 8 bytes.
    /// </summary>
    public byte[]? Salt => this.config.Salt;

    /// <summary>
    /// Gets the secret used in the password hash.
    /// </summary>
    public byte[]? Secret => this.config.Secret;

    /// <summary>
    /// Gets a value indicating whether to clear the secret as
    /// soon as it is no longer needed.
    /// </summary>
    /// <remarks>
    /// If true and the configuration has a secret, the configuration
    /// cannot be used more than once without resetting the secret
    /// (unless you want an all zero secret).
    /// </remarks>
    public bool ClearSecret => this.config.ClearSecret;

    /// <summary>
    /// Gets the associated data used in the password hash.
    /// </summary>
    public byte[]? AssociatedData => this.config.AssociatedData;

    /// <summary>
    /// Gets the threads used in the password hash. Minimum of 1. Defaults to 1.
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
    public int Threads => this.config.Threads;

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
    /// Encodes an Argon2 instance into a string.
    /// </summary>
    /// <param name="hash">
    /// The hash to put in the encoded string. May be null.
    /// </param>
    /// <returns>
    /// The encoded Argon2 instance.
    /// </returns>
    /// <remarks>
    /// <para>
    /// Resulting format:
    /// </para>
    /// <para>
    /// $argon2&lt;T>[$v=&lt;num>]$m=&lt;num>,t=&lt;num>,p=&lt;num>[,keyid=&lt;bin>][,data=&lt;bin>][$&lt;bin>[$&lt;bin>]].
    /// </para>
    /// <para>
    /// where &lt;T> is either 'd' or 'i', &lt;num> is a decimal integer (positive, fits in
    /// an 'unsigned long'), and &lt;bin> is Base64-encoded data (no '=' padding
    /// characters, no newline or whitespace).
    /// The "keyid" is a binary identifier for a key (up to 8 bytes);
    /// "data" is associated data (up to 32 bytes). When the 'keyid'
    /// (resp. the 'data') is empty, then it is omitted from the output.
    /// </para>
    /// <para>
    /// The last two binary chunks (encoded in Base64) are, in that order,
    /// the salt and the output. Both are optional, but you cannot have an
    /// output without a salt. The binary salt length is between 8 and 48 bytes.
    /// The output length is always exactly 32 bytes.
    /// </para>
    /// </remarks>
    public string EncodeString(Span<byte> hash)
    {
        return this.config.EncodeString(hash);
    }

    /// <summary>
    /// Reset this <see cref="Argon2Memory"/> to what the given <see cref="Argon2Config"/> requires.
    /// </summary>
    /// <param name="resetConfig">
    /// The configuration used to determine memory required.
    /// </param>
    /// <exception cref="OutOfMemoryException">
    /// If the memory could not be allocated. Usually because of operating system
    /// enforced limits on securing the allocated arrays.
    /// </exception>
    public void Reset(Argon2Config resetConfig)
    {
        if (this.InUse)
        {
            throw new InvalidOperationException("Attempt to reset Argon2Memory currently in use.");
        }

        this.config = (Argon2Config)resetConfig.Clone();
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
        var (segmentBlockCount, laneBlockCount, requiredMemoryBlockCount) = RequiredBlockCounts(this.config);
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
            this.ResetNoSecureArray(this.config, requiredMemoryBlockCount);
            return;
        }

        LockMemoryPolicy lockMemory = this.LockMemory.Value;
        if (this.FillMemoryBlocksWorkingBufferLength != this.config.WorkingBufferLength)
        {
            if ((this.ShrinkMemoryPolicy == Argon2MemoryPolicy.Shrink && this.FillMemoryBlocksWorkingBufferLength > this.config.WorkingBufferLength) || this.fillMemoryBlocksWorkingBuffer.Length < this.config.WorkingBufferLength)
            {
                this.workingSecureArray = SecureArray<ulong>.Create(this.config.WorkingBufferLength, this.config.SecureArrayCall, lockMemory);
                this.fillMemoryBlocksWorkingBuffer = new Memory<ulong>(this.workingSecureArray.Buffer);
            }

            this.FillMemoryBlocksWorkingBufferLength = this.config.WorkingBufferLength;
        }

        if (this.hashLength != this.config.HashLength)
        {
            if ((this.ShrinkMemoryPolicy == Argon2MemoryPolicy.Shrink && this.hashLength > this.config.HashLength) || this.hashMemory.Length < this.config.HashLength)
            {
                this.hashSecureArray = SecureArray<byte>.Create(this.config.HashLength, this.config.SecureArrayCall, lockMemory);
                this.hashMemory = new Memory<byte>(this.hashSecureArray.Buffer);
            }

            this.hashLength = this.config.HashLength;
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
                $" memory cost {this.config.MemoryCost}, lane count {this.config.Lanes}.",
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

    private void ResetNoSecureArray(Argon2Config resetConfig, ulong requiredMemoryBlockCount)
    {
        if (this.FillMemoryBlocksWorkingBufferLength != resetConfig.WorkingBufferLength)
        {
            if ((this.ShrinkMemoryPolicy == Argon2MemoryPolicy.Shrink && this.FillMemoryBlocksWorkingBufferLength > resetConfig.WorkingBufferLength) || this.fillMemoryBlocksWorkingBuffer.Length < resetConfig.WorkingBufferLength)
            {
                this.fillMemoryBlocksWorkingBuffer = new Memory<ulong>(new ulong[resetConfig.WorkingBufferLength]);
            }

            this.FillMemoryBlocksWorkingBufferLength = resetConfig.WorkingBufferLength;
        }

        if (this.hashLength != resetConfig.HashLength)
        {
            if ((this.ShrinkMemoryPolicy == Argon2MemoryPolicy.Shrink && this.hashLength > resetConfig.HashLength) || this.hashMemory.Length < resetConfig.HashLength)
            {
                this.hashMemory = new Memory<byte>(new byte[resetConfig.HashLength]);
            }

            this.hashLength = resetConfig.HashLength;
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
                $" memory cost {resetConfig.MemoryCost}, lane count {resetConfig.Lanes}.",
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