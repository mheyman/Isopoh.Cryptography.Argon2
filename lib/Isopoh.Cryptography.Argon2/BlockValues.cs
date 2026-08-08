// <copyright file="BlockValues.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2;

using System;

/// <summary>
/// Gets the values from a ulong array. Block lengths are <see cref="Argon2.QwordsInBlock"/>
/// elements long.
/// </summary>
public sealed class BlockValues
{
    /// <summary>
    /// The span behind the block values.
    /// </summary>
    private readonly Memory<ulong> memory;

    /// <summary>
    /// Initializes a new instance of the <see cref="BlockValues"/> class.
    /// </summary>
    /// <param name="memory">
    /// The array of ulong elements the <see cref="BlockValues"/> will use.
    /// </param>
    public BlockValues(Memory<ulong> memory)
    {
        if (memory.Length != Argon2.QwordsInBlock)
        {
            throw new ArgumentException(
                $"Expected length of {Argon2.QwordsInBlock}, got {memory.Length}",
                nameof(memory));
        }

        this.memory = memory;
    }

    /// <summary>
    /// Gets or sets the ulong element at the specified index.
    /// </summary>
    /// <param name="i">
    ///     The ulong element to get or set.
    /// </param>
    /// <returns>
    /// The requested ulong element.
    /// </returns>
    public ulong this[int i]
    {
        get => this.memory.Span[i];
        set => this.memory.Span[i] = value;
    }

    /// <summary>
    /// Defines an implicit conversion of a <see cref="BlockValues"/> to a <see cref="ReadOnlyBlockValues"/>.
    /// </summary>
    /// <param name="blockValues">The value to convert.</param>
    public static implicit operator ReadOnlyBlockValues(BlockValues blockValues) => new(blockValues.memory.Span);

    /// <summary>
    /// Defines an implicit conversion of a <see cref="BlockValues"/> to a <see cref="ReadOnlyBlockValues"/>.
    /// </summary>
    /// <param name="blockValues">The value to convert.</param>
    public static implicit operator TempBlockValues(BlockValues blockValues) => new(blockValues.memory.Span);

    /// <summary>
    /// Copy <paramref name="other"/> into this.
    /// </summary>
    /// <param name="other">
    /// The <see cref="ReadOnlyBlockValues"/> to copy.
    /// </param>
    public void Copy(ReadOnlyBlockValues other)
    {
        other.ReadOnlySpan.CopyTo(this.memory.Span);
    }

    /// <summary>
    /// XOR <paramref name="other"/> with this and store the result into this.
    /// </summary>
    /// <param name="other">
    /// The <see cref="ReadOnlyBlockValues"/> to XOR.
    /// </param>
    public void Xor(ReadOnlyBlockValues other)
    {
        var otherSpan = other.ReadOnlySpan;
        for (var i = 0; i < Argon2.QwordsInBlock; ++i)
        {
            this.memory.Span[i] ^= otherSpan[i];
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
        this.memory.Span.Fill(value);
    }
}