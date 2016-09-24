// <copyright file="UnrollScheme.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2
{
    /// <summary>
    /// What kind of unrolling to do in the Blake2 portion of the inner block fill
    /// </summary>
    public enum UnrollScheme
    {
        /// <summary>
        /// No unrolling
        /// </summary>
        None,

        /// <summary>
        /// Partial unrolling
        /// </summary>
        Partial,

        /// <summary>
        /// Full unrolling
        /// </summary>
        Full
    }
}