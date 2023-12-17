// <copyright file="LockFailException.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray;

using System;
using System.Runtime.Serialization;

/// <summary>
/// Represents errors that occur trying to lock a buffer into memory.
/// </summary>
[Serializable]
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

    /// <summary>
    /// Initializes a new instance of the <see cref="LockFailException"/> class with serialized data.
    /// </summary>
    /// <param name="info">
    /// The <see cref="T:System.Runtime.Serialization.SerializationInfo"></see> that holds the serialized object data about the exception being thrown.
    /// </param>
    /// <param name="context">
    /// The <see cref="T:System.Runtime.Serialization.StreamingContext"></see> that contains contextual information about the source or destination.
    /// </param>
    /// <exception cref="T:System.ArgumentNullException">
    /// The <paramref name="info">info</paramref> parameter is null.
    /// </exception>
    /// <exception cref="T:System.Runtime.Serialization.SerializationException">
    /// The class name is null or <see cref="P:System.Exception.HResult"></see> is zero (0).
    /// </exception>
    protected LockFailException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}