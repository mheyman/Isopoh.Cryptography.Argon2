// <copyright file="Blocks.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2;

using System.Collections.Generic;

/// <summary>
/// Break a byte array into blocks for Argon2 to use.
/// </summary>
public class Blocks
{
    /// <summary>
    /// The array of blocks broken into <see cref="BlockValues"/>
    /// which actually return the values in the original array.
    /// </summary>
    private readonly BlockValues[] blockValues;

    /// <summary>
    /// Initializes a new instance of the <see cref="Blocks"/> class.
    /// </summary>
    /// <param name="memories">
    /// The arrays to use under the blocks.
    /// </param>
    public Blocks(IEnumerable<ulong[]> memories)
    {
        var bvs = new List<BlockValues>();
        var blockIndex = 0;
        foreach (ulong[] memory in memories)
        {
            int maxBlockIndex = blockIndex + (memory.Length / Argon2.QwordsInBlock);
            for (int i = blockIndex; i < maxBlockIndex; ++i)
            {
                bvs.Add(new BlockValues(memory, i - blockIndex));
            }

            blockIndex = maxBlockIndex;
        }

        this.blockValues = bvs.ToArray();
    }

    /// <summary>
    /// Gets the total number of <see cref="BlockValues"/> in the <see cref="Blocks"/>.
    /// </summary>
    public int Length => this.blockValues.Length;

    /// <summary>
    /// Gets or sets the <see cref="BlockValues"/> element at the specified index.
    /// </summary>
    /// <param name="i">
    /// The <see cref="BlockValues"/> element to get or set.
    /// </param>
    /// <returns>
    /// The requested <see cref="BlockValues"/> element.
    /// </returns>
    public BlockValues this[int i] => this.blockValues[i];
}