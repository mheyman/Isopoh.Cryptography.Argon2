// <copyright file="SecureArrayType.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray
{
    /// <summary>
    /// The behavior of the secure array.
    /// </summary>
    public enum SecureArrayType
    {
        /// <summary>
        /// Zero the memory on disposal
        /// </summary>
        Zeroed,

        /// <summary>
        /// Pin the memory so the garbage collector doesn't move it around
        /// and zero the memory on disposal
        /// </summary>
        ZeroedAndPinned,

        /// <summary>
        /// Lock the memory into RAM, pin the memory so the garbage collector
        /// doesn't move it, and zero the memory on disposal.
        /// </summary>
        ZeroedPinnedAndNoSwap,
    }
}