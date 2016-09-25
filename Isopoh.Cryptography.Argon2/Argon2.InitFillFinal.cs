// <copyright file="Argon2.InitFillFinal.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2
{
    using System;
    using System.Linq;
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
            Store32(value, this.Lanes);
            blakeHash.Update(value);
            Store32(value, this.HashLength);
            blakeHash.Update(value);
            Store32(value, this.MemoryCost);
            blakeHash.Update(value);
            Store32(value, this.TimeCost);
            blakeHash.Update(value);
            Store32(value, (uint)this.Version);
            blakeHash.Update(value);
            Store32(value, (uint)this.Type);
            blakeHash.Update(value);
            Store32(value, this.Password?.Length ?? 0);
            blakeHash.Update(value);
            if (this.Password != null)
            {
                blakeHash.Update(this.Password);
                if (this.ClearPassword)
                {
                    SecureArray.Zero(this.Password);
                }
            }

            Store32(value, this.Salt?.Length ?? 0);
            blakeHash.Update(value);
            if (this.Salt != null)
            {
                blakeHash.Update(this.Salt);
            }

            Store32(value, this.Secret?.Length ?? 0);
            blakeHash.Update(value);
            if (this.Secret != null)
            {
                blakeHash.Update(this.Secret);
                if (this.ClearSecret)
                {
                    SecureArray.Zero(this.Secret);
                }
            }

            Store32(value, this.AssociatedData?.Length ?? 0);
            blakeHash.Update(value);
            if (this.AssociatedData != null)
            {
                blakeHash.Update(this.AssociatedData);
            }

            blakeHash.Finish();
            return ret;
        }

        private void FillFirstBlocks(byte[] blockhash)
        {
            using (var blockhashBytes = new SecureArray<byte>(BlockSize))
            {
                for (int l = 0; l < this.Lanes; ++l)
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

        private void FillMemoryBlocksSingleThreaded()
        {
            for (int passNumber = 0; passNumber < this.TimeCost; ++passNumber)
            {
                for (int sliceNumber = 0; sliceNumber < SyncPoints; ++sliceNumber)
                {
                    for (int laneNumber = 0; laneNumber < this.Lanes; ++laneNumber)
                    {
                        this.FillSegment(new Position(passNumber, laneNumber, sliceNumber));
                    }
                }

                InternalKat(this, passNumber);
            }
        }

        private void FillMemoryBlocksTasked()
        {
            int positionIndex = -1;
            int positionIndexDone = this.Lanes * SyncPoints * this.TimeCost;
            int positionIndexSync = this.Lanes;
            int positionIndexKat = this.Lanes * SyncPoints;
            var barrier = new Barrier(
                this.threadCount,
                bar =>
                {
                    positionIndexSync += this.Lanes;
                    if (positionIndex == positionIndexKat)
                    {
                        InternalKat(this, positionIndex);
                        positionIndexKat += this.Lanes * SyncPoints;
                    }
                });

            Func<Position, bool> setPostion = toSet =>
                {
                    while (true)
                    {
                        int myPositionIndex = -1;
                        lock (barrier)
                        {
                            if (positionIndex == positionIndexDone)
                            {
                                // done
                                return false;
                            }

                            if (positionIndex != positionIndexSync)
                            {
                                Interlocked.Increment(ref positionIndex);

                                if (positionIndex == positionIndexSync)
                                {
                                    if (positionIndex == positionIndexDone)
                                    {
                                        // done
                                        return false;
                                    }

                                    myPositionIndex = positionIndex;
                                }
                                else
                                {
                                    toSet.Pass = positionIndex / (SyncPoints * this.Lanes);
                                    toSet.Slice = (positionIndex / this.Lanes) % SyncPoints;
                                    toSet.Lane = positionIndex % this.Lanes;
                                    toSet.Index = 0;
                                    return true;
                                }
                            }
                        }

                        barrier.SignalAndWait();
                        if (myPositionIndex != -1)
                        {
                            toSet.Pass = myPositionIndex / (SyncPoints * this.Lanes);
                            toSet.Slice = (myPositionIndex / this.Lanes) % SyncPoints;
                            toSet.Lane = myPositionIndex % this.Lanes;
                            toSet.Index = 0;
                            return true;
                        }
                    }
                };

            var tasks = new Task[this.threadCount - 1];
            for (int i = 0; i < tasks.Length; ++i)
            {
                tasks[i] = Task.Factory.StartNew(
                    () =>
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
            InternalKat(this, this.TimeCost - 1);
        }

        private void FillMemoryBlocksSimpleTasked()
        {
            var tasks = new Task[this.threadCount];
            for (int passNumber = 0; passNumber < this.TimeCost; ++passNumber)
            {
                for (int sliceNumber = 0; sliceNumber < SyncPoints; ++sliceNumber)
                {
                    int laneNumber = 0;
                    for (; laneNumber < tasks.Length && laneNumber < this.Lanes; ++laneNumber)
                    {
                        tasks[laneNumber] = Task.Factory.StartNew(
                            p => { this.FillSegment((Position)p); },
                            new Position(passNumber, laneNumber, sliceNumber));
                    }

                    while (laneNumber < this.Lanes)
                    {
                        int i = Task.WaitAny(tasks);
                        tasks[i] = Task.Factory.StartNew(
                            p => { this.FillSegment((Position)p); },
                            new Position(passNumber, laneNumber, sliceNumber));
                        ++laneNumber;
                    }

                    Task.WaitAll(tasks);
                }

                InternalKat(this, passNumber);
            }
        }

        private void FillMemoryBlocksThreaded()
        {
            int positionIndex = -1;
            int positionIndexDone = this.Lanes * SyncPoints * this.TimeCost;
            int positionIndexSync = this.Lanes;
            int positionIndexKat = this.Lanes * SyncPoints;
            var barrier = new Barrier(
                this.threadCount,
                bar =>
                    {
                        positionIndexSync += this.Lanes;
                        if (positionIndex == positionIndexKat)
                        {
                            InternalKat(this, positionIndex);
                            positionIndexKat += this.Lanes * SyncPoints;
                        }
                    });

            Func<Position, bool> setPostion = toSet =>
                {
                    while (true)
                    {
                        int myPositionIndex = -1;
                        lock (barrier)
                        {
                            if (positionIndex == positionIndexDone)
                            {
                                // done
                                return false;
                            }

                            if (positionIndex == positionIndexSync)
                            {
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

                                    myPositionIndex = positionIndex;
                                }
                                else
                                {
                                    toSet.Pass = positionIndex / (SyncPoints * this.Lanes);
                                    toSet.Slice = (positionIndex / this.Lanes) % SyncPoints;
                                    toSet.Lane = positionIndex % this.Lanes;
                                    toSet.Index = 0;
                                    return true;
                                }
                            }
                        }

                        barrier.SignalAndWait();
                        if (myPositionIndex != -1)
                        {
                            toSet.Pass = myPositionIndex / (SyncPoints * this.Lanes);
                            toSet.Slice = (myPositionIndex / this.Lanes) % SyncPoints;
                            toSet.Lane = myPositionIndex % this.Lanes;
                            toSet.Index = 0;
                            return true;
                        }
                    }
                };

            var threads = new Thread[this.threadCount - 1];
            for (int i = 0; i < threads.Length; ++i)
            {
                threads[i] = new Thread(
                    () =>
                        {
                            Position p = new Position(0, 0, 0);
                            while (setPostion(p))
                            {
                                this.FillSegment(p);
                            }
                        }) { Name = $"Argon2({i})" };

                threads[i].Start();
            }

            Position position = new Position(0, 0, 0);
            while (setPostion(position))
            {
                this.FillSegment(position);
            }

            foreach (var thread in threads)
            {
                thread.Join();
            }

            InternalKat(this, this.TimeCost - 1);
        }

        private void FillMemoryBlocksSimpleThreaded()
        {
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
                Enumerable.Range(0, this.threadCount)
                    .Select(i => new AutoResetEvent(false))
                    .Cast<WaitHandle>()
                    .ToArray();
            var threads = new Thread[waitHandles.Length];
            for (int passNumber = 0; passNumber < this.TimeCost; ++passNumber)
            {
                for (int sliceNumber = 0; sliceNumber < SyncPoints; ++sliceNumber)
                {
                    int laneNumber = 0;
                    int remaining = this.Lanes;
                    for (; laneNumber < threads.Length && laneNumber < this.Lanes; ++laneNumber)
                    {
                        threads[laneNumber] = startFillSegmentThread(
                            new Position(passNumber, laneNumber, sliceNumber),
                            (AutoResetEvent)waitHandles[laneNumber]);
                    }

                    while (laneNumber < this.Lanes)
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
        }

        private SecureArray<byte> Final()
        {
            using (var blockhashBuffer = new SecureArray<ulong>(BlockSize / 8))
            {
                var blockhash = new BlockValues(blockhashBuffer.Buffer, 0);
                blockhash.Copy(this.Memory[this.LaneLength - 1]);

                // XOR last blocks
                for (int l = 1; l < this.Lanes; ++l)
                {
                    blockhash.Xor(this.Memory[(l * this.LaneLength) + (this.LaneLength - 1)]);
                }

                using (var blockhashBytes = new SecureArray<byte>(BlockSize))
                {
                    StoreBlock(blockhashBytes.Buffer, blockhash);
                    var ret = new SecureArray<byte>(this.HashLength);
                    Blake2BLong(ret.Buffer, blockhashBytes.Buffer);
                    PrintTag(ret.Buffer);
                    return ret;
                }
            }
        }

        private void FillSegment(Position position)
        {
            bool dataIndependentAddressing = this.Type == Argon2Type.DataIndependentAddressing;
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
                    : (int)((uint)(pseudoRand >> 32) % (uint)this.Lanes);

                // compute possible number of reference blocks in lane
                position.Index = i;
                int refIndex = this.IndexAlpha(position, (uint)pseudoRand, refLane == position.Lane);

                BlockValues refBlock = this.Memory[(this.LaneLength * refLane) + refIndex];
                BlockValues curBlock = this.Memory[curOffset];
                if (this.Version == Argon2Version.Sixteen)
                {
                    // version 1.2.1 and earlier: overwrite, not XOR
                    FillBlock(this.blake2RowAndColumnRoundsNoMsg, this.Memory[prevOffset], refBlock, curBlock);
                }
                else if (position.Pass == 0)
                {
                    FillBlock(this.blake2RowAndColumnRoundsNoMsg, this.Memory[prevOffset], refBlock, curBlock);
                }
                else
                {
                    FillBlockWithXor(this.blake2RowAndColumnRoundsNoMsg, this.Memory[prevOffset], refBlock, curBlock);
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
            inputBlock[4] = (ulong)this.TimeCost;
            inputBlock[5] = (ulong)this.Type;
            for (int i = 0; i < this.SegmentLength; ++i)
            {
                if (i % QwordsInBlock == 0)
                {
                    inputBlock[6] += 1;
                    tmpBlock.Init(0);
                    addressBlock.Init(0);
                    FillBlockWithXor(this.blake2RowAndColumnRoundsNoMsg, zeroBlock, inputBlock, tmpBlock);
                    FillBlockWithXor(this.blake2RowAndColumnRoundsNoMsg, zeroBlock, tmpBlock, addressBlock);
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