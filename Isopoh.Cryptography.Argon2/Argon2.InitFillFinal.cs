// <copyright file="Argon2.InitFillFinal.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Threading;
    using System.Threading.Tasks;

    using Isopoh.Cryptography.Blake2b;
    using Isopoh.Cryptography.SecureArray;

    /// <summary>
    /// Argon2 Hashing of passwords
    /// </summary>
    public sealed partial class Argon2
    {
        private void Initialize()
        {
            using (var blockhash = new SecureArray<byte>(PrehashSeedLength))
            {
                using (var initialHash = this.InitialHash())
                {
                    Array.Copy(initialHash.Buffer, blockhash.Buffer, PrehashDigestLength);
                }

                InitialKat(blockhash.Buffer, this);
                this.FillFirstBlocks(blockhash.Buffer);
            }
        }

        private SecureArray<byte> InitialHash()
        {
            var ret = new SecureArray<byte>(Blake2B.OutputLength);
            var blakeHash =
                Blake2B.Create(
                    new Blake2BConfig
                    {
                        OutputSizeInBytes = PrehashDigestLength,
                        Result64ByteBuffer = ret.Buffer
                    });
            var value = new byte[4];
            Store32(value, this.config.Lanes);
            blakeHash.Update(value);
            Store32(value, this.config.HashLength);
            blakeHash.Update(value);
            Store32(value, this.config.MemoryCost);
            blakeHash.Update(value);
            Store32(value, this.config.TimeCost);
            blakeHash.Update(value);
            Store32(value, (uint)this.config.Version);
            blakeHash.Update(value);
            Store32(value, (uint)this.config.Type);
            blakeHash.Update(value);
            Store32(value, this.config.Password?.Length ?? 0);
            blakeHash.Update(value);
            if (this.config.Password != null)
            {
                blakeHash.Update(this.config.Password);
                if (this.config.ClearPassword)
                {
                    SecureArray.Zero(this.config.Password);
                }
            }

            Store32(value, this.config.Salt?.Length ?? 0);
            blakeHash.Update(value);
            if (this.config.Salt != null)
            {
                blakeHash.Update(this.config.Salt);
            }

            Store32(value, this.config.Secret?.Length ?? 0);
            blakeHash.Update(value);
            if (this.config.Secret != null)
            {
                blakeHash.Update(this.config.Secret);
                if (this.config.ClearSecret)
                {
                    SecureArray.Zero(this.config.Secret);
                }
            }

            Store32(value, this.config.AssociatedData?.Length ?? 0);
            blakeHash.Update(value);
            if (this.config.AssociatedData != null)
            {
                blakeHash.Update(this.config.AssociatedData);
            }

            blakeHash.Finish();
            return ret;
        }

        private void FillFirstBlocks(byte[] blockhash)
        {
            using (var blockhashBytes = new SecureArray<byte>(BlockSize))
            {
                for (int l = 0; l < this.config.Lanes; ++l)
                {
                    Store32(blockhash, PrehashDigestLength, 0);
                    Store32(blockhash, PrehashDigestLength + 4, l);
                    Blake2BLong(blockhashBytes.Buffer, blockhash);
                    LoadBlock(this.Memory[l * this.LaneLength], blockhashBytes.Buffer);
                    Store32(blockhash, PrehashDigestLength, 1);
                    Blake2BLong(blockhashBytes.Buffer, blockhash);
                    LoadBlock(this.Memory[(l * this.LaneLength) + 1], blockhashBytes.Buffer);
                }
            }
        }

        private void FillMemoryBlocks()
        {
            if (this.config.Threads > 1)
            {
#if false
                Func<Position, AutoResetEvent, Thread> startFillSegmentThread = (position, autoResetEvent) =>
                    {
                        var ret = new Thread(
                            () =>
                                {
                                    this.FillSegment(position);
                                    autoResetEvent.Set();
                                });
                        ret.Start();
                        return ret;
                    };
                // Version of code ported from C reference that spawns a new
                // thread for every segment fill. This is really slow, don't do
                // this - with typical parameters, Argon2 is always faster with
                // no parallelism rather than using this code.
                var waitHandles =
                    Enumerable.Range(
                        0,
                        this.config.Threads > this.config.Lanes ? this.config.Lanes : this.config.Threads)
                        .Select(i => new AutoResetEvent(false))
                        .Cast<WaitHandle>()
                        .ToArray();
                var threads = new Thread[waitHandles.Length];
                for (int passNumber = 0; passNumber < this.config.TimeCost; ++passNumber)
                {
                    for (int sliceNumber = 0; sliceNumber < SyncPoints; ++sliceNumber)
                    {
                        int laneNumber = 0;
                        int remaining = this.config.Lanes;
                        for (; laneNumber < threads.Length && laneNumber < this.config.Lanes; ++laneNumber)
                        {
                            threads[laneNumber] = startFillSegmentThread(
                                new Position(passNumber, laneNumber, sliceNumber),
                                (AutoResetEvent)waitHandles[laneNumber]);
                        }

                        while (laneNumber < this.config.Lanes)
                        {
                            int i = WaitHandle.WaitAny(waitHandles);
                            threads[i].Join();
                            --remaining;
                            threads[i] = startFillSegmentThread(
                                new Position(passNumber, laneNumber, sliceNumber),
                                (AutoResetEvent)waitHandles[i]);
                            ++laneNumber;
                        }

                        while (remaining > 0)
                        {
                            int i = WaitHandle.WaitAny(waitHandles);
                            threads[i].Join();
                            --remaining;
                        }
                    }

                    InternalKat(this, passNumber);
                }

#elif false
                var tasks = new Task[this.config.Threads > this.config.Lanes ? this.config.Lanes : this.config.Threads];
                for (int passNumber = 0; passNumber < this.config.TimeCost; ++passNumber)
                {
                    for (int sliceNumber = 0; sliceNumber < SyncPoints; ++sliceNumber)
                    {
                        int laneNumber = 0;
                        for (; laneNumber < tasks.Length && laneNumber < this.config.Lanes; ++laneNumber)
                        {
                            tasks[laneNumber] = Task.Factory.StartNew(
                                p =>
                                    {
                                        this.FillSegment((Position)p);
                                    },
                                new Position(passNumber, laneNumber, sliceNumber));
                        }

                        while (laneNumber < this.config.Lanes)
                        {
                            int i = Task.WaitAny(tasks);
                            tasks[i] = Task.Factory.StartNew(
                                p =>
                                    {
                                        this.FillSegment((Position)p);
                                    },
                                new Position(passNumber, laneNumber, sliceNumber));
                            ++laneNumber;
                        }

                        Task.WaitAll(tasks);
                    }

                    InternalKat(this, passNumber);
                }
#else
                ////var positions = new Queue<Position>();
                ////for (int passNumber = 0; passNumber < this.config.TimeCost; ++passNumber)
                ////{
                ////    for (int sliceNumber = 0; sliceNumber < SyncPoints; ++sliceNumber)
                ////    {
                ////        for (int laneNumber = 0; laneNumber < this.config.Lanes; ++laneNumber)
                ////        {
                ////            positions.Enqueue(new Position(passNumber, laneNumber, sliceNumber));
                ////        }
                ////    }
                ////}

                int positionIndex = -1;
                int positionIndexDone = this.config.Lanes * SyncPoints * this.config.TimeCost;
                int positionIndexSync = this.config.Lanes;
                int positionIndexKat = this.config.Lanes * SyncPoints;
                var pauseForSyncs =
                    Enumerable.Range(0, SyncPoints * this.config.TimeCost)
                    .Select(i => new ManualResetEvent(false))
                    .ToArray();
                int pauseForSyncIndex = 0;
                int atSyncIndex = 0;
                int threadCount = this.config.Threads > this.config.Lanes ? this.config.Lanes : this.config.Threads;
                var waitingForSyncs =
                    Enumerable.Range(0, threadCount - 1)
                        .Select(i => new AutoResetEvent(false))
                        .Cast<WaitHandle>()
                        .ToArray();

                Func<Position, bool> setPostion = toSet =>
                    {
                        while (true)
                        {
                            int myPauseForSyncIndex = -1;
                            lock (pauseForSyncs)
                            {
                                if (positionIndex == positionIndexDone)
                                {
                                    // done
                                    return false;
                                }

                                if (positionIndex == positionIndexSync)
                                {
                                    // other thread wants this thread to wait for sync
                                    ((AutoResetEvent)waitingForSyncs[atSyncIndex]).Set();
                                    ++atSyncIndex;
                                    myPauseForSyncIndex = pauseForSyncIndex;
                                }
                                else
                                {
                                    Interlocked.Increment(ref positionIndex);

                                    if (positionIndex == positionIndexSync)
                                    {
                                        if (positionIndex == positionIndexDone)
                                        {
                                            // done
                                            return false;
                                        }

                                        atSyncIndex = 0;
                                    }
                                    else
                                    {
                                        toSet.Pass = positionIndex / (SyncPoints * this.config.Lanes);
                                        toSet.Slice = (positionIndex / this.config.Lanes) % SyncPoints;
                                        toSet.Lane = positionIndex % this.config.Lanes;
                                        toSet.Index = 0;
                                        return true;
                                    }
                                }
                            }

                            if (myPauseForSyncIndex != -1)
                            {
                                pauseForSyncs[myPauseForSyncIndex].WaitOne();
                            }
                            else
                            {
                                // Wait for others to sync
                                WaitHandle.WaitAll(waitingForSyncs);
                                lock (pauseForSyncs)
                                {
                                    // other threads waiting at pauseForSync
                                    positionIndexSync += this.config.Lanes;
                                    if (positionIndex == positionIndexKat)
                                    {
                                        InternalKat(this, positionIndex / (SyncPoints * this.config.Lanes));
                                        positionIndexKat += this.config.Lanes * SyncPoints;
                                    }

                                    // release others
                                    pauseForSyncs[pauseForSyncIndex].Set();
                                    ++pauseForSyncIndex;
                                    toSet.Pass = positionIndex / (SyncPoints * this.config.Lanes);
                                    toSet.Slice = (positionIndex / this.config.Lanes) % SyncPoints;
                                    toSet.Lane = positionIndex % this.config.Lanes;
                                    toSet.Index = 0;
                                    return true;
                                }
                            }
                        }
                    };

                var tasks = new Task[threadCount - 1];
                for (int i = 0; i < tasks.Length; ++i)
                {
                    tasks[i] = Task.Factory.StartNew(() =>
                    {
                        Position p = new Position(0, 0, 0);
                        while (setPostion(p))
                        {
                            this.FillSegment(p);
                        }
                    });
                }

                Position position = new Position(0, 0, 0);
                while (setPostion(position))
                {
                    this.FillSegment(position);
                }

                Task.WaitAll(tasks);
                InternalKat(this, this.config.TimeCost - 1);
#endif
            }
            else
            {
                for (int passNumber = 0; passNumber < this.config.TimeCost; ++passNumber)
                {
                    for (int sliceNumber = 0; sliceNumber < SyncPoints; ++sliceNumber)
                    {
                        for (int laneNumber = 0; laneNumber < this.config.Lanes; ++laneNumber)
                        {
                            this.FillSegment(new Position(passNumber, laneNumber, sliceNumber));
                        }
                    }

                    InternalKat(this, passNumber);
                }
            }
        }

        private SecureArray<byte> Final()
        {
            using (var blockhashBuffer = new SecureArray<ulong>(BlockSize / 8))
            {
                var blockhash = new BlockValues(blockhashBuffer.Buffer, 0);
                blockhash.Copy(this.Memory[this.LaneLength - 1]);

                // XOR last blocks
                for (int l = 1; l < this.config.Lanes; ++l)
                {
                    blockhash.Xor(this.Memory[(l * this.LaneLength) + (this.LaneLength - 1)]);
                }

                using (var blockhashBytes = new SecureArray<byte>(BlockSize))
                {
                    StoreBlock(blockhashBytes.Buffer, blockhash);
                    var ret = new SecureArray<byte>(this.config.HashLength);
                    Blake2BLong(ret.Buffer, blockhashBytes.Buffer);
                    PrintTag(ret.Buffer);
                    return ret;
                }
            }
        }

        private void FillSegment(Position position)
        {
            bool dataIndependentAddressing = this.config.Type == Argon2Type.DataIndependentAddressing;
            var pseudoRands = new ulong[this.SegmentLength];
            if (dataIndependentAddressing)
            {
                this.GenerateAddresses(position, pseudoRands);
            }

            // 2 if already generated the first two blocks
            int startingIndex = position.Pass == 0 && position.Slice == 0 ? 2 : 0;
            int curOffset = (position.Lane * this.LaneLength) + (position.Slice * this.SegmentLength) + startingIndex;
            int prevOffset = curOffset % this.LaneLength == 0 ? curOffset + this.LaneLength - 1 : curOffset - 1;

            for (int i = startingIndex; i < this.SegmentLength; ++i, ++curOffset, ++prevOffset)
            {
                if (curOffset % this.LaneLength == 1)
                {
                    prevOffset = curOffset - 1;
                }

                // compute index of reference block taking pseudo-random value from previous block
                ulong pseudoRand = dataIndependentAddressing ? pseudoRands[i] : this.Memory[prevOffset][0];

                // cannot reference other lanes until pass or slice are not zero
                int refLane =
                    (position.Pass == 0 && position.Slice == 0)
                    ? position.Lane
                    : (int)((uint)(pseudoRand >> 32) % (uint)this.config.Lanes);

                // compute possible number of reference blocks in lane
                position.Index = i;
                int refIndex = this.IndexAlpha(position, (uint)pseudoRand, refLane == position.Lane);

                BlockValues refBlock = this.Memory[(this.LaneLength * refLane) + refIndex];
                BlockValues curBlock = this.Memory[curOffset];
                if (this.config.Version == Argon2Version.Sixteen)
                {
                    // version 1.2.1 and earlier: overwrite, not XOR
                    FillBlock(this.Memory[prevOffset], refBlock, curBlock);
                }
                else if (position.Pass == 0)
                {
                    FillBlock(this.Memory[prevOffset], refBlock, curBlock);
                }
                else
                {
                    FillBlockWithXor(this.Memory[prevOffset], refBlock, curBlock);
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
                        referenceAreaSize = (position.Slice * this.SegmentLength) + position.Index - 1;
                    }
                    else
                    {
                        referenceAreaSize = (position.Slice * this.SegmentLength) + (position.Index == 0 ? -1 : 0);
                    }
                }
            }
            else
            {
                // second pass
                if (sameLane)
                {
                    referenceAreaSize = this.LaneLength - this.SegmentLength + position.Index - 1;
                }
                else
                {
                    referenceAreaSize = this.LaneLength - this.SegmentLength + (position.Index == 0 ? -1 : 0);
                }
            }

            ulong relativePosition = pseudoRand;
            relativePosition = (relativePosition * relativePosition) >> 32;
            relativePosition = (uint)referenceAreaSize - 1 - (((uint)referenceAreaSize * relativePosition) >> 32);

            int startPosition = position.Pass != 0
                                    ? position.Slice == (SyncPoints - 1)
                                          ? 0
                                          : (position.Slice + 1) * this.SegmentLength
                                    : 0;
            int absolutePosition = (int)(((ulong)startPosition + relativePosition) % (ulong)this.LaneLength);
            return absolutePosition;
        }

        private void GenerateAddresses(Position position, ulong[] pseudoRands)
        {
            var buf = new ulong[QwordsInBlock * 4];
            var zeroBlock = new BlockValues(buf, 0);
            var inputBlock = new BlockValues(buf, 1);
            var addressBlock = new BlockValues(buf, 2);
            var tmpBlock = new BlockValues(buf, 3);

            inputBlock[0] = (ulong)position.Pass;
            inputBlock[1] = (ulong)position.Lane;
            inputBlock[2] = (ulong)position.Slice;
            inputBlock[3] = (ulong)this.MemoryBlockCount;
            inputBlock[4] = (ulong)this.config.TimeCost;
            inputBlock[5] = (ulong)this.config.Type;
            for (int i = 0; i < this.SegmentLength; ++i)
            {
                if (i % QwordsInBlock == 0)
                {
                    inputBlock[6] += 1;
                    tmpBlock.Init(0);
                    addressBlock.Init(0);
                    FillBlockWithXor(zeroBlock, inputBlock, tmpBlock);
                    FillBlockWithXor(zeroBlock, tmpBlock, addressBlock);
                }

                pseudoRands[i] = addressBlock[i % QwordsInBlock];
            }
        }

        private class Position
        {
            public Position(int pass, int lane, int slice)
            {
                this.Pass = pass;
                this.Lane = lane;
                this.Slice = slice;
            }

            public int Pass { get; set; }

            public int Lane { get; set; }

            public int Slice { get; set; }

            public int Index { get; set; }
        }
    }
}