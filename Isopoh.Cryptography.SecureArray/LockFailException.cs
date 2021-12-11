// <copyright file="LockFailException.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray
{
    using System;

    /// <summary>
    /// Represents errors that occur trying to lock a buffer into memory.
    /// </summary>
    public class LockFailException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="LockFailException"/> class.
        /// </summary>
        public LockFailException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="LockFailException"/> class.
        /// </summary>
        /// <param name="message">
        /// Text for the <see cref="Exception.Message" /> property.
        /// </param>
        public LockFailException(string? message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="LockFailException"/> class.
        /// </summary>
        /// <param name="message">
        /// Text for the <see cref="Exception.Message" /> property.
        /// </param>
        /// <param name="innerException">
        /// Exception that spawned this exception.
        /// </param>
        public LockFailException(string? message, Exception? innerException)
            : base(message, innerException)
        {
        }
    }
}