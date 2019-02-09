// <copyright file="BlockValues.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2
{
    using System;

    /// <summary>
    /// Gets the values from a ulong array. Block lengths are <see cref="Argon2.QwordsInBlock"/>
    /// elements long.
    /// </summary>
    public class BlockValues
    {
        private readonly ulong[] memory;

        private readonly int offset;

        /// <summary>
        /// Initializes a new instance of the <see cref="BlockValues"/> class.
        /// </summary>
        /// <param name="memory">
        /// The array of ulong elements the <see cref="BlockValues"/> will use.
        /// </param>
        /// <param name="blockIndex">
        /// The index of the block in <paramref name="memory"/> the <see
        /// cref="BlockValues"/> will use. Blocks are <see cref="Argon2.QwordsInBlock"/>
        /// elements long.
        /// </param>
        public BlockValues(ulong[] memory, int blockIndex)
        {
            this.memory = memory;
            this.offset = blockIndex * Argon2.QwordsInBlock;
        }

        /// <summary>
        /// Gets or sets the ulong element at the specified index.
        /// </summary>
        /// <param name="i">
        /// The ulong element to get or set.
        /// </param>
        /// <returns>
        /// The requested ulong element.
        /// </returns>
        public ulong this[int i]
        {
            get => this.memory[this.offset + i];

            set => this.memory[this.offset + i] = value;
        }

        /// <summary>
        /// Copy <paramref name="other"/> into this.
        /// </summary>
        /// <param name="other">
        /// The <see cref="BlockValues"/> to copy.
        /// </param>
        public void Copy(BlockValues other)
        {
            Array.Copy(other.memory, other.offset, this.memory, this.offset, Argon2.QwordsInBlock);
        }

        /// <summary>
        /// XOR <paramref name="other"/> with this and store the result into this.
        /// </summary>
        /// <param name="other">
        /// The <see cref="BlockValues"/> to XOR.
        /// </param>
        public void Xor(BlockValues other)
        {
            for (int i = 0; i < Argon2.QwordsInBlock; ++i)
            {
                this[i] ^= other[i];
            }
        }

        /// <summary>
        /// Copy <paramref name="value"/> into every ulong of this.
        /// </summary>
        /// <param name="value">
        /// The value to copy into this.
        /// </param>
        public void Init(ulong value)
        {
            for (int i = 0; i < Argon2.QwordsInBlock; ++i)
            {
                this[i] = value;
            }
        }
    }
}