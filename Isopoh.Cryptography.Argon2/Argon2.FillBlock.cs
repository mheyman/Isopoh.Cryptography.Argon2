// <copyright file="Argon2.FillBlock.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2
{
    using System;

    /// <summary>
    /// Argon2 Hashing of passwords
    /// </summary>
    public sealed partial class Argon2
    {
        private static void FillBlock(
            Action<BlockValues> blake2RowAndColumnRoundsNoMsg,
            BlockValues prevBlock,
            BlockValues refBlock,
            BlockValues nextBlock)
        {
            var buf = new ulong[Argon2.QwordsInBlock * 2];
            var blockR = new BlockValues(buf, 0);
            var blockTmp = new BlockValues(buf, 1);
            blockR.Copy(refBlock);
            blockR.Xor(prevBlock);
            blockTmp.Copy(blockR);
            blake2RowAndColumnRoundsNoMsg(blockR);
            nextBlock.Copy(blockTmp);
            nextBlock.Xor(blockR);
        }

        private static void FillBlockWithXor(
            Action<BlockValues> blake2RowAndColumnRoundsNoMsg,
            BlockValues prevBlock,
            BlockValues refBlock,
            BlockValues nextBlock)
        {
            var buf = new ulong[Argon2.QwordsInBlock * 2];
            var blockR = new BlockValues(buf, 0);
            var blockTmp = new BlockValues(buf, 1);
            blockR.Copy(refBlock);
            blockR.Xor(prevBlock);
            blockTmp.Copy(blockR);
            blockTmp.Xor(nextBlock); // saving the next block for XOR over
            blake2RowAndColumnRoundsNoMsg(blockR);
            nextBlock.Copy(blockTmp);
            nextBlock.Xor(blockR);
        }
    }
}