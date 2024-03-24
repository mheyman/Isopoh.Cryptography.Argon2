// <copyright file="Argon2.Blake2BLong.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2;

using System;
using Isopoh.Cryptography.Blake2b;
using Isopoh.Cryptography.SecureArray;

/// <summary>
/// Argon2 Hashing of passwords.
/// </summary>
public sealed partial class Argon2
{
    /// <summary>
    /// Does a Blake2 hash with the ability to truncate or extend the hash to any length.
    /// </summary>
    /// <param name="hash">
    /// The buffer to fill with the hash.
    /// </param>
    /// <param name="inputBuffer">
    /// What to hash.
    /// </param>
    /// <param name="workingBuffer">
    /// (2 * <see cref="Blake2B"/>.<see cref="Blake2B.OutputLength"/>) + <see cref="Blake2B"/>.<see cref="Blake2B.BufferMinimumTotalSize"/> bytes long.
    /// </param>
    private static void Blake2BLong(Span<byte> hash, Span<byte> inputBuffer, Memory<byte> workingBuffer)
    {
        var outputLengthBytes = new byte[4];
        if (workingBuffer.Length < (2 * Blake2B.OutputLength) + Blake2B.NoKeyBufferMinimumTotalSize)
        {
            throw new ArgumentException(
                $"Expected at least {(2 * Blake2B.OutputLength) + Blake2B.NoKeyBufferMinimumTotalSize} bytes, got {workingBuffer.Length}",
                nameof(workingBuffer));
        }

        var resultBuffer = workingBuffer.Slice(0, Blake2B.OutputLength);
        var toHash = workingBuffer.Slice(Blake2B.OutputLength, Blake2B.OutputLength);
        var blake2BWorkingBuffer = workingBuffer.Slice(2 * Blake2B.OutputLength, Blake2B.NoKeyBufferMinimumTotalSize);
        var blake2BConfig = new Blake2BConfig
        {
            Result64ByteBuffer = resultBuffer,
            OutputSizeInBytes = hash.Length > 64 ? 64 : hash.Length,
        };
        Store32(outputLengthBytes, hash.Length);
        using (Hasher blakeHash = Blake2B.Create(blake2BConfig, blake2BWorkingBuffer))
        {
            blakeHash.Update(outputLengthBytes);
            blakeHash.Update(inputBuffer);
            blakeHash.Finish();
        }

        if (hash.Length <= resultBuffer.Length)
        {
            // less than or equal to 64 bytes, just copy the hash result
            resultBuffer.Span.Slice(0, hash.Length).CopyTo(hash);
            return;
        }

        // greater than 64 bytes, copy a chain of half-hash results until the final up-to-full hash result
        const int b2B2 = Blake2B.OutputLength / 2;
        resultBuffer.Span.Slice(0, b2B2).CopyTo(hash.Slice(0, b2B2));
        int pos = b2B2;
        int lastHashIndex = hash.Length - Blake2B.OutputLength;
        while (pos < lastHashIndex)
        {
            resultBuffer.CopyTo(toHash);
            Blake2B.ComputeHash(toHash.Span, blake2BConfig, blake2BWorkingBuffer);
            resultBuffer.Span.Slice(0, b2B2).CopyTo(hash.Slice(pos, b2B2));
            pos += b2B2;
        }

        // between 33 and 64 bytes left to load
        resultBuffer.CopyTo(toHash);
        int remaining = hash.Length - pos;
        if (remaining < 64)
        {
            blake2BConfig = new Blake2BConfig
            {
                Result64ByteBuffer = resultBuffer,
                OutputSizeInBytes = hash.Length - pos,
            };
        }

        Blake2B.ComputeHash(toHash.Span, blake2BConfig, blake2BWorkingBuffer);
        resultBuffer.Span.Slice(0, hash.Length - pos).CopyTo(hash.Slice(pos));
    }
}