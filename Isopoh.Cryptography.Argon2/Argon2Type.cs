// <copyright file="Argon2Type.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2
{
    /// <summary>
    /// Argon2 can hash in two different ways, data-depenedent and data-independent.
    /// </summary>
    /// <remarks>
    /// <para>
    /// From the Argon2 paper:
    /// </para>
    /// <para>
    /// Argon2 has two variants: Argon2d [data-dependent] and Argon2i [data-independent].
    /// Argon2d is faster and uses data-depending memory access, which makes it suitable
    /// for cryptocurrencies and applications with no threats from side-channel timing
    /// attacks. Argon2i uses data-independent memory access, which is preferred for
    /// password hashing and password-based key derivation. Argon2i is slower as it
    /// makes more passes over the memory to protect from tradeoff attacks.
    /// </para>
    /// <para>
    ///
    /// </para>
    /// </remarks>
    public enum Argon2Type
    {
        /// <summary>
        /// Use data-dependent addressing. This is faster but susceptible to
        /// side-channel attacks.
        /// </summary>
        DataDependentAddressing = 0,

        /// <summary>
        /// Use data-independent addressing. This is slower and recommended for password
        /// hashing and password-based key derivation.
        /// </summary>
        DataIndependentAddressing = 1,

        /// <summary>
        /// Use a hybrid of data-dependent and data-independent addressing.
        /// </summary>
        HybridAddressing = 2,
    }
}