// <copyright file="Argon2Version.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2
{
    /// <summary>
    /// There are two versions, 16 and 19. 19 is 5%-15% slower but fixes a vulnerabilty
    /// where an attacker could take advantage of short time spans where memory blocks
    /// were not used to reduce the overall memory cost by up to a factor of about 3.5.
    /// </summary>
    public enum Argon2Version
    {
        /// <summary>
        /// For Argon2 versions 1.2.1 or earlier.
        /// </summary>
        Sixteen = 0x10,

        /// <summary>
        /// For Argon2 version 1.3.
        /// </summary>
        Nineteen = 0x13,
    }
}