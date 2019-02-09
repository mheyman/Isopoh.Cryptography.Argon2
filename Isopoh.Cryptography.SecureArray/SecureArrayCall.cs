// <copyright file="SecureArrayCall.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray
{
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
        public SecureArrayCall(
            Action<IntPtr, UIntPtr> zeroMemory,
            Func<IntPtr, UIntPtr, string> lockMemory,
            Action<IntPtr, UIntPtr> unlockMemory)
        {
            this.ZeroMemory = zeroMemory;
            this.LockMemory = lockMemory;
            this.UnlockMemory = unlockMemory;
        }

        /// <summary>
        /// Gets or sets a method that zeroes memory in a way that does not get optimized away.
        /// </summary>
        /// <remarks>
        /// On Linux and OSX, simply calls memset() and hopes the P/Invoke
        /// mechanism does not have special handling for memset calls (and
        /// thus does not even think about optimizing the call away).
        /// </remarks>
        public Action<IntPtr, UIntPtr> ZeroMemory { get; protected set; }

        /// <summary>
        /// Gets or sets a method that locks the given memory so it doesn't get swapped out to disk.
        /// </summary>
        /// <returns>
        /// Null on success; otherwise an error message.
        /// </returns>
        public Func<IntPtr, UIntPtr, string> LockMemory { get; protected set; }

        /// <summary>
        /// Gets or sets a method that unlocks memory previously locked by a call to <see cref="LockMemory"/>.
        /// </summary>
        public Action<IntPtr, UIntPtr> UnlockMemory { get; protected set; }
    }
}