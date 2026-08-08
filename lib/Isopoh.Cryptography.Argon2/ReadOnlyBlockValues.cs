// <copyright file="ReadOnlyBlockValues.cs" company="Isopoh">
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
public readonly ref struct ReadOnlyBlockValues
{
    /// <summary>
    /// The span behind the block values.
    /// </summary>
    private readonly ReadOnlySpan<ulong> span;

    /// <summary>
    /// Initializes a new instance of the <see cref="ReadOnlyBlockValues"/> struct.
    /// </summary>
    /// <param name="span">
    /// The array of ulong elements the <see cref="ReadOnlyBlockValues"/> will use.
    /// </param>
    public ReadOnlyBlockValues(ReadOnlySpan<ulong> span)
    {
        if (span.Length != Argon2.QwordsInBlock)
        {
            throw new ArgumentException(
                $"Expected length of {Argon2.QwordsInBlock}, got {span.Length}",
                nameof(span));
        }

        this.span = span;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ReadOnlyBlockValues"/> struct.
    /// </summary>
    /// <param name="span">
    /// The array of ulong elements the <see cref="ReadOnlyBlockValues"/> will use.
    /// </param>
    /// <param name="value">Initial value filled. Will modify <paramref name="span"/>.</param>
    public ReadOnlyBlockValues(Span<ulong> span, ulong value)
    {
        if (span.Length != Argon2.QwordsInBlock)
        {
            throw new ArgumentException(
                $"Expected length of {Argon2.QwordsInBlock}, got {span.Length}",
                nameof(span));
        }

        span.Fill(value);
        this.span = span;
    }

    /// <summary>
    /// Gets the <see cref="ReadOnlySpan{T}"/> of the block values.
    /// </summary>
    public ReadOnlySpan<ulong> ReadOnlySpan => this;

    /// <summary>
    /// Gets or sets the ulong element at the specified index.
    /// </summary>
    /// <param name="i">
    /// The ulong element to get or set.
    /// </param>
    /// <returns>
    /// The requested ulong element.
    /// </returns>
    public ulong this[int i] => this.span[i];

    /// <summary>
    /// Defines an implicit conversion of a <see cref="ReadOnlyBlockValues"/> to a <see cref="ReadOnlySpan{T}"/>.
    /// </summary>
    /// <param name="blockValues">The value to convert.</param>
    public static implicit operator ReadOnlySpan<ulong>(ReadOnlyBlockValues blockValues) => blockValues.span;
}