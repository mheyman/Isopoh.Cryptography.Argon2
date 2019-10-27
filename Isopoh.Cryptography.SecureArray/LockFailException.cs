// <copyright file="LockFailException.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray
{
    using System;

    /// <inheritdoc />
    /// <summary>
    /// Represents errors that occur trying to lock a buffer into memory.
    /// </summary>
    public class LockFailException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="LockFailException"/> class.
        /// </summary>
        /// <param name="message">
        /// Text for the <see cref="P:System.Exception.Message" /> property.
        /// </param>
        /// <param name="currentMax">
        /// Number of bytes currently available to lock. Don't assume you can
        /// actually lock this exact amount the next time you request to lock
        /// bytes into RAM - this value changes constantly.
        /// </param>
        // ReSharper disable once InheritdocConsiderUsage
        public LockFailException(string message, int currentMax)
            : base(message)
        {
            this.CurrentMax = currentMax;
        }

        /// <summary>
        /// Gets the current (as of when the exception was created) maximum number of
        /// bytes that can be locked.
        /// </summary>
        /// <remarks>
        /// Don't assume this amount of bytes will be lockable into RAM on the next
        /// attempt - this value changes constantly.
        /// </remarks>
        public int CurrentMax { get; }
    }
}