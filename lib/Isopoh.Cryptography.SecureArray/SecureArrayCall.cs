// <copyright file="SecureArrayCall.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray;

using System;

/// <summary>
/// Call used by <see cref="SecureArray"/> to secure the array.
/// </summary>
public class SecureArrayCall
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SecureArrayCall"/> class.
    /// </summary>
    /// <param name="zeroMemory">
    /// Call that zeroes memory in a way that does not get optimized away.
    /// </param>
    /// <param name="lockMemory">
    /// Call that locks the given memory so it doesn't get swapped out to disk.
    /// </param>
    /// <param name="unlockMemory">
    /// Call that unlocks memory previously locked by a call to <paramref name="lockMemory"/>.
    /// </param>
    /// <param name="os">The name of the operating system this <see cref="SecureArrayCall"/> is for.</param>
    public SecureArrayCall(
        Action<IntPtr, nuint> zeroMemory,
        Func<IntPtr, nuint, string?> lockMemory,
        Action<IntPtr, nuint> unlockMemory,
        string os)
    {
        this.ZeroMemory = zeroMemory;
        this.LockMemory = lockMemory;
        this.UnlockMemory = unlockMemory;
        this.Os = os;
    }

    /// <summary>
    /// Gets or sets a method that zeroes memory in a way that does not get optimized away.
    /// </summary>
    /// <remarks>
    /// On Linux, OSX, and UWP, simply calls memset() and hopes the P/Invoke
    /// mechanism does not have special handling for memset calls (and
    /// thus does not even think about optimizing the call away).
    /// </remarks>
    public Action<IntPtr, nuint> ZeroMemory { get; protected set; }

    /// <summary>
    /// Gets or sets a method that locks the given memory so it doesn't get swapped out to disk.
    /// </summary>
    /// <returns>
    /// Null on success; otherwise an error message.
    /// </returns>
    public Func<IntPtr, nuint, string?> LockMemory { get; protected set; }

    /// <summary>
    /// Gets or sets a method that unlocks memory previously locked by a call to <see cref="LockMemory"/>.
    /// </summary>
    public Action<IntPtr, nuint> UnlockMemory { get; protected set; }

    /// <summary>
    /// Gets or sets the operating system this <see cref="SecureArrayCall"/> works for.
    /// </summary>
    public string Os { get; set; }
}