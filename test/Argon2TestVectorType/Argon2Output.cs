// <copyright file="Argon2Output.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Argon2TestVectorType
{
    /// <summary>
    /// Type of output for the reference argon2 executable.
    /// </summary>
    public enum Argon2Output
    {
        /// <summary>
        /// The tag is output as a hexadecimal string.
        /// </summary>
        Raw,

        /// <summary>
        /// The tag is output as an Argon2-encoded string.
        /// </summary>
        /// <remarks>
        /// Not sure where the spec for this is but the reference implementation uses it.
        /// </remarks>
        Encoded,

        /// <summary>
        /// Multiline output with inputs as well as hexadecimal hash and encoded hash.
        /// </summary>
        Full,
    }
}