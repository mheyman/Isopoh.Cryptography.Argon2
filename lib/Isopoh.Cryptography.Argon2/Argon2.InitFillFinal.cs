// <copyright file="Argon2.InitFillFinal.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2;

using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using Isopoh.Cryptography.Blake2b;
using Isopoh.Cryptography.SecureArray;

/// <summary>
/// Argon2 Hashing of passwords.
/// </summary>
public sealed partial class Argon2
{
    private void Initialize(Memory<byte> workingBuffer)
    {
        if (workingBuffer.Length < PrehashSeedLength + BlockSize + (2 * Blake2B.OutputLength) + Blake2B.BufferMinimumTotalSize)
        {
            throw new ArgumentException(
                $"Expected at least {PrehashSeedLength + BlockSize + (2 * Blake2B.OutputLength) + Blake2B.BufferMinimumTotalSize} bytes, got {workingBuffer.Length}",
                nameof(workingBuffer));
        }

        var blockHash = workingBuffer.Span.Slice(0, PrehashSeedLength);
        var initialHash = workingBuffer.Slice(blockHash.Length, Blake2B.OutputLength);
        var initialHashWorkingBuffer = workingBuffer.Slice(blockHash.Length + initialHash.Length);
        var fillFirstBlocksWorkingBuffer = workingBuffer.Slice(blockHash.Length);
        this.InitialHash(initialHash, initialHashWorkingBuffer);
        initialHash.Span.Slice(0, PrehashDigestLength).CopyTo(blockHash.Slice(0, PrehashDigestLength));
        InitialKat(blockHash, this);
        this.FillFirstBlocks(blockHash, fillFirstBlocksWorkingBuffer);
    }

    /// <summary>
    /// Get the initial hash.
    /// </summary>
    /// <param name="hashResult"><see cref="Blake2B"/>.<see cref="Blake2B.OutputLength"/>-byte span to hold the result.</param>
    /// <param name="workingBuffer">At least (4 + <see cref="Blake2B"/>.<see cref="Blake2B.NoKeyBufferMinimumTotalSize"/>)-bytes working buffer.</param>
    private void InitialHash(Memory<byte> hashResult, Memory<byte> workingBuffer)
    {
        if (workingBuffer.Length < 4 + Blake2B.NoKeyBufferMinimumTotalSize)
        {
            throw new ArgumentException(
                $"Expected working buffer to be at least {4 + Blake2B.NoKeyBufferMinimumTotalSize}, got {workingBuffer.Length}");
        }

        using Hasher blakeHash =
            Blake2B.Create(
                new Blake2BConfig
                {
                    OutputSizeInBytes = PrehashDigestLength,
                    Result64ByteBuffer = hashResult,
                },
                workingBuffer.Slice(4));
        var value = workingBuffer.Span.Slice(0, 4);
        Store32(value, this.memory.Lanes);
        blakeHash.Update(value);
        Store32(value, this.memory.HashLength);
        blakeHash.Update(value);
        Store32(value, this.memory.MemoryCost);
        blakeHash.Update(value);
        Store32(value, this.memory.TimeCost);
        blakeHash.Update(value);
        Store32(value, (uint)this.memory.Version);
        blakeHash.Update(value);
        Store32(value, (uint)this.memory.Type);
        blakeHash.Update(value);
        Store32(value, this.memory.Password.Length);
        blakeHash.Update(value);
        if (this.memory.Password != null)
        {
            blakeHash.Update(this.memory.Password);
            if (this.memory.ClearPassword)
            {
                SecureArray.Zero(this.memory.Password);
            }
        }

        Store32(value, this.memory.Salt.Length);
        blakeHash.Update(value);
        if (this.memory.Salt != null)
        {
            blakeHash.Update(this.memory.Salt);
        }

        Store32(value, this.memory.Secret.Length);
        blakeHash.Update(value);
        if (this.memory.Secret != null)
        {
            blakeHash.Update(this.memory.Secret);
            if (this.memory.ClearSecret)
            {
                SecureArray.Zero(this.memory.Secret);
            }
        }

        Store32(value, this.memory.AssociatedData.Length);
        blakeHash.Update(value);
        if (this.memory.AssociatedData != null)
        {
            blakeHash.Update(this.memory.AssociatedData);
        }

        blakeHash.Finish();
    }

    /// <summary>
    /// Fill <paramref name="initialHash"/> with the initial hash. Also set the initial <see cref="Memory"/> <see cref="Blocks"/>.
    /// </summary>
    /// <param name="initialHash"><see cref="PrehashSeedLength"/>-byte result of <see cref="InitialHash"/>.</param>
    /// <param name="workingBuffer">At least <see cref="BlockSize"/> + (2 * <see cref="Blake2B"/>.<see cref="Blake2B.OutputLength"/>) + <see cref="Blake2B"/>.<see cref="Blake2B.BufferMinimumTotalSize"/> bytes.</param>
    /// <exception cref="ArgumentException">Bad <paramref name="workingBuffer"/>.</exception>
    private void FillFirstBlocks(Span<byte> initialHash, Memory<byte> workingBuffer)
    {
        if (workingBuffer.Length < BlockSize + (2 * Blake2B.OutputLength) + Blake2B.BufferMinimumTotalSize)
        {
            throw new ArgumentException(
                $"Expected to have at least {BlockSize + (2 * Blake2B.OutputLength) + Blake2B.BufferMinimumTotalSize}-byte working buffer, got {workingBuffer.Length}.", nameof(workingBuffer));
        }

        var blockHashBytes = workingBuffer.Span.Slice(0, BlockSize);
        var blake2BWorkingBuffer = workingBuffer.Slice(BlockSize);

        for (var l = 0; l < this.memory.Lanes; ++l)
        {
            Store32(initialHash, PrehashDigestLength, 0);
            Store32(initialHash, PrehashDigestLength + 4, l);
            Blake2BLong(blockHashBytes, initialHash, blake2BWorkingBuffer);
            LoadBlock(this.Memory[l * this.LaneBlockCount], blockHashBytes);
            Store32(initialHash, PrehashDigestLength, 1);
            Blake2BLong(blockHashBytes, initialHash, blake2BWorkingBuffer);
            LoadBlock(this.Memory[(l * this.LaneBlockCount) + 1], blockHashBytes);
        }
    }

    /// <summary>
    /// Fills memory blocks.
    /// </summary>
    /// <param name="buf">
    /// Working buffer of size ((2 * <see cref="Argon2.QwordsInBlock"/>) + this.SegmentBlockCount) * (parallel count)
    /// for <see cref="Argon2Type.DataDependentAddressing"/>; otherwise
    /// ((6 * <see cref="Argon2.QwordsInBlock"/>) + this.SegmentBlockCount) * (parallel count).
    /// Where "parallel count" is the fewest of this.config.Threads and this.config.Lanes.
    /// </param>
    /// <exception cref="ArgumentException">If buf is improperly sized.</exception>
    private void FillMemoryBlocks(Memory<ulong> buf)
    {
        int parallelCount = this.memory.Threads > this.memory.Lanes ? this.memory.Lanes : this.memory.Threads;
        int threadWorkingBufferSize = (QwordsInBlock * (this.memory.Type == Argon2Type.DataDependentAddressing ? 2 : 6)) + this.SegmentBlockCount;
        if (buf.Length != threadWorkingBufferSize * parallelCount)
        {
            throw new ArgumentException(
                $"Expected length of {threadWorkingBufferSize}, got {buf.Length}",
                nameof(buf));
        }

        if (parallelCount > 1)
        {
            // ReSharper disable once SuggestVarOrType_Elsewhere
            WaitHandle[] waitHandles =
                Enumerable.Range(0, parallelCount)
                    .Select(_ => new AutoResetEvent(false))
                    .Cast<WaitHandle>()
                    .ToArray();
            Memory<ulong>[] workingBuffers = Enumerable.Range(0, parallelCount)
                .Select(i => buf.Slice(i * threadWorkingBufferSize, threadWorkingBufferSize))
                .ToArray();

            for (var passNumber = 0; passNumber < this.memory.TimeCost; ++passNumber)
            {
                for (var sliceNumber = 0; sliceNumber < SyncPointCount; ++sliceNumber)
                {
                    var laneNumber = 0;
                    int remaining = this.memory.Lanes;
                    for (; laneNumber < waitHandles.Length && laneNumber < this.memory.Lanes; ++laneNumber)
                    {
                        ThreadPool.QueueUserWorkItem(
                            fs =>
                            {
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
#pragma warning disable CS8602 // Dereference of a possibly null reference.
                                this.FillSegment(((FillState)fs).Position, ((FillState)fs).Buf.Span);
                                ((FillState)fs).Are.Set();
#pragma warning restore CS8602 // Dereference of a possibly null reference.
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.
                            },
                            new FillState(new Position { Pass = passNumber, Lane = laneNumber, Slice = sliceNumber, Index = 0 }, workingBuffers[laneNumber], (AutoResetEvent)waitHandles[laneNumber]));
                    }

                    while (laneNumber < this.memory.Lanes)
                    {
                        int i = WaitHandle.WaitAny(waitHandles);
                        --remaining;
                        ThreadPool.QueueUserWorkItem(
                            fs =>
                            {
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
#pragma warning disable CS8602 // Dereference of a possibly null reference.
                                this.FillSegment(((FillState)fs).Position, ((FillState)fs).Buf.Span);
                                ((FillState)fs).Are.Set();
#pragma warning restore CS8602 // Dereference of a possibly null reference.
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.
                            },
                            new FillState(new Position { Pass = passNumber, Lane = laneNumber, Slice = sliceNumber, Index = 0 }, workingBuffers[i], (AutoResetEvent)waitHandles[i]));
                        ++laneNumber;
                    }

                    while (remaining > 0)
                    {
                        _ = WaitHandle.WaitAny(waitHandles);
                        --remaining;
                    }
                }

                InternalKat(this, passNumber);
            }
        }
        else
        {
            for (var passNumber = 0; passNumber < this.memory.TimeCost; ++passNumber)
            {
                for (var sliceNumber = 0; sliceNumber < SyncPointCount; ++sliceNumber)
                {
                    for (var laneNumber = 0; laneNumber < this.memory.Lanes; ++laneNumber)
                    {
                        this.FillSegment(
                            new Position
                            {
                                Pass = passNumber,
                                Lane = laneNumber,
                                Slice = sliceNumber,
                                Index = 0,
                            },
                            buf.Span);
                    }
                }

                InternalKat(this, passNumber);
            }
        }
    }

    private void Final(Span<byte> destination, Memory<byte> workingBuffer)
    {
        if (workingBuffer.Length < (2 * BlockSize) + (2 * Blake2B.OutputLength) + Blake2B.NoKeyBufferMinimumTotalSize)
        {
            throw new ArgumentException(
                $"Expected {(2 * BlockSize) + (2 * Blake2B.OutputLength) + Blake2B.NoKeyBufferMinimumTotalSize}-byte working buffer. Got {workingBuffer.Length}");
        }

        var blockHashBuffer = Unsafe.As<Memory<byte>, Memory<ulong>>(ref workingBuffer).Slice(0, BlockSize / 8);
        var blockHashBytes = workingBuffer.Span.Slice(BlockSize, BlockSize);
        var blake2BLongWorkingBuffer = workingBuffer.Slice(2 * BlockSize);
        var blockHash = new BlockValues(blockHashBuffer);
        blockHash.Copy(this.Memory[this.LaneBlockCount - 1]);

        // XOR last blocks
        for (var l = 1; l < this.memory.Lanes; ++l)
        {
            blockHash.Xor(this.Memory[(l * this.LaneBlockCount) + (this.LaneBlockCount - 1)]);
        }

        StoreBlock(blockHashBytes, blockHash);
        Blake2BLong(destination, blockHashBytes, blake2BLongWorkingBuffer);
        PrintTag(destination);
    }

    /// <summary>
    /// Fill the <paramref name="position"/> <see cref="Memory"/> segment.
    /// </summary>
    /// <param name="position">The position to fill.</param>
    /// <param name="buf">
    /// Working buffer of size (2 * <see cref="Argon2.QwordsInBlock"/>) + this.SegmentBlockCount
    /// for <see cref="Argon2Type.DataDependentAddressing"/>; otherwise
    /// (6 * <see cref="Argon2.QwordsInBlock"/>) + this.SegmentBlockCount.
    /// </param>
    /// <exception cref="ArgumentException">If <paramref name="buf"/> is improperly sized.</exception>
    private void FillSegment(Position position, Span<ulong> buf)
    {
        int pseudoRandsOffset = (this.memory.Type == Argon2Type.DataDependentAddressing ? 2 : 6) * QwordsInBlock;
        int expectedBufLen = pseudoRandsOffset + this.SegmentBlockCount;
        if (buf.Length != expectedBufLen)
        {
            throw new ArgumentException($"Expected length of {expectedBufLen}, got {buf.Length}.", nameof(buf));
        }

        bool dataIndependentAddressing = this.memory.Type == Argon2Type.DataIndependentAddressing ||
            (this.memory.Type == Argon2Type.HybridAddressing && position is { Pass: 0, Slice: < SyncPointCount / 2 });
        Span<ulong> pseudoRands = buf.Slice(pseudoRandsOffset, this.SegmentBlockCount);
        if (dataIndependentAddressing)
        {
            this.GenerateAddresses(position, pseudoRands, buf.Slice(0, 6 * QwordsInBlock));
        }

        // 2 if already generated the first two blocks
        int startingIndex = position is { Pass: 0, Slice: 0 } ? 2 : 0;
        int curOffset = (position.Lane * this.LaneBlockCount) + (position.Slice * this.SegmentBlockCount) + startingIndex;
        int prevOffset = curOffset % this.LaneBlockCount == 0 ? curOffset + this.LaneBlockCount - 1 : curOffset - 1;

        Span<ulong> fillBuf = buf.Slice(0, 2 * QwordsInBlock);
        for (int i = startingIndex; i < this.SegmentBlockCount; ++i, ++curOffset, ++prevOffset)
        {
            if (curOffset % this.LaneBlockCount == 1)
            {
                prevOffset = curOffset - 1;
            }

            // compute index of reference block taking pseudo-random value from previous block
            ulong pseudoRand = dataIndependentAddressing ? pseudoRands[i] : this.Memory[prevOffset][0];

            // cannot reference other lanes until pass or slice are not zero
            int refLane =
                position is { Pass: 0, Slice: 0 }
                    ? position.Lane
                    : (int)((uint)(pseudoRand >> 32) % (uint)this.memory.Lanes);

            // compute possible number of reference blocks in lane
            position.Index = i;
            int refIndex = this.IndexAlpha(position, (uint)pseudoRand, refLane == position.Lane);

            BlockValues refBlock = this.Memory[(this.LaneBlockCount * refLane) + refIndex];
            BlockValues curBlock = this.Memory[curOffset];
            if (this.memory.Version == Argon2Version.Sixteen)
            {
                // version 1.2.1 and earlier: overwrite, not XOR
                FillBlock(this.Memory[prevOffset], refBlock, curBlock, fillBuf);
            }
            else if (position.Pass == 0)
            {
                FillBlock(this.Memory[prevOffset], refBlock, curBlock, fillBuf);
            }
            else
            {
                FillBlockWithXor(this.Memory[prevOffset], refBlock, curBlock, fillBuf);
            }
        }
    }

    private int IndexAlpha(Position position, uint pseudoRand, bool sameLane)
    {
        // Pass 0:
        //   This lane : all already finished segments plus already constructed
        //   blocks in this segment
        // Other lanes : all already finished segments
        // Pass 1+:
        //   This lane : (SYNC_POINTS - 1) last segments plus already constructed
        //   blocks in this segment
        //   Other lanes : (SYNC_POINTS - 1) last segments
        int referenceAreaSize;
        if (position.Pass == 0)
        {
            // first pass
            if (position.Slice == 0)
            {
                // first slice
                referenceAreaSize = position.Index - 1; // all but previous
            }
            else
            {
                if (sameLane)
                {
                    // same lane, add current segment
                    referenceAreaSize = (position.Slice * this.SegmentBlockCount) + position.Index - 1;
                }
                else
                {
                    referenceAreaSize = (position.Slice * this.SegmentBlockCount) + (position.Index == 0 ? -1 : 0);
                }
            }
        }
        else
        {
            // second pass
            if (sameLane)
            {
                referenceAreaSize = this.LaneBlockCount - this.SegmentBlockCount + position.Index - 1;
            }
            else
            {
                referenceAreaSize = this.LaneBlockCount - this.SegmentBlockCount + (position.Index == 0 ? -1 : 0);
            }
        }

        ulong relativePosition = pseudoRand;
        relativePosition = (relativePosition * relativePosition) >> 32;
        relativePosition = (uint)referenceAreaSize - 1 - (((uint)referenceAreaSize * relativePosition) >> 32);

        int startPosition = position.Pass != 0
            ? position.Slice == (SyncPointCount - 1)
                ? 0
                : (position.Slice + 1) * this.SegmentBlockCount
            : 0;
        var absolutePosition = (int)(((ulong)startPosition + relativePosition) % (ulong)this.LaneBlockCount);
        return absolutePosition;
    }

    /// <summary>
    /// Populate <paramref name="pseudoRands"/> with values.
    /// </summary>
    /// <param name="position">Position to populate.</param>
    /// <param name="pseudoRands">Loaded with values.</param>
    /// <param name="buf">Working buffer of size 6 * <see cref="Argon2.QwordsInBlock"/>.</param>
    /// <exception cref="ArgumentException">If <paramref name="buf"/> is improperly sized.</exception>
    private void GenerateAddresses(Position position, Span<ulong> pseudoRands, Span<ulong> buf)
    {
        if (buf.Length != QwordsInBlock * 6)
        {
            throw new ArgumentException($"Expected length of {QwordsInBlock * 4}, got {buf.Length}", nameof(buf));
        }

        var zeroBlock = new ReadOnlyBlockValues(buf.Slice(0, QwordsInBlock), 0);
        var inputBlock = new TempBlockValues(buf.Slice(QwordsInBlock, QwordsInBlock), 0);
        var addressBlock = new TempBlockValues(buf.Slice(2 * QwordsInBlock, QwordsInBlock));
        var tmpBlock = new TempBlockValues(buf.Slice(3 * QwordsInBlock, QwordsInBlock));
        Span<ulong> workingBlock = buf.Slice(4 * QwordsInBlock, 2 * QwordsInBlock);

        inputBlock[0] = (ulong)position.Pass;
        inputBlock[1] = (ulong)position.Lane;
        inputBlock[2] = (ulong)position.Slice;
        inputBlock[3] = (ulong)this.MemoryBlockCount;
        inputBlock[4] = (ulong)this.memory.TimeCost;
        inputBlock[5] = (ulong)this.memory.Type;
        for (var i = 0; i < this.SegmentBlockCount; ++i)
        {
            if (i % QwordsInBlock == 0)
            {
                inputBlock[6] += 1;
                tmpBlock.Init(0);
                addressBlock.Init(0);
                FillBlockWithXor(zeroBlock, inputBlock, tmpBlock, workingBlock);
                FillBlockWithXor(zeroBlock, tmpBlock, addressBlock, workingBlock);
            }

            pseudoRands[i] = addressBlock[i % QwordsInBlock];
        }
    }

    private sealed class Position
    {
        public int Pass { get; init; }

        public int Lane { get; init; }

        public int Slice { get; init; }

        public int Index { get; set; }
    }

    private sealed class FillState(Position position, Memory<ulong> buf, AutoResetEvent are)
    {
        public Position Position { get; } = position;

        public Memory<ulong> Buf { get; } = buf;

        public AutoResetEvent Are { get; } = are;
    }
}