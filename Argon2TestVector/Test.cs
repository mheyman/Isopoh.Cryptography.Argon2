// <copyright file="Test.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Argon2TestVector
{
    using System.Collections.Generic;
    using Argon2TestVectorType;

    /// <summary>
    /// Holds <see cref="Test.Argon2Vectors"/> generated from the reference C implementation.
    /// </summary>
    public partial class Test
    {
        /// <summary>
        /// Gets the list of vectors generated at compile time from C-language reference argon2 command line example code.
        /// </summary>
        public List<TestVector> Argon2Vectors => generatedVectors;
    }
}