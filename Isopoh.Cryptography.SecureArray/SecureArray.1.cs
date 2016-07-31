// <copyright file="SecureArray.1.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray
{
    using System;

    /// <summary>
    /// Manage an array that holds sensitive information.
    /// </summary>
    /// <typeparam name="T">
    /// The type of the array. Limited to built in types.
    /// </typeparam>
    public sealed class SecureArray<T> : SecureArray, IDisposable
    {
        private readonly T[] buf;

        /// <summary>
        /// Initializes a new instance of the <see cref="SecureArray{T}"/> class.
        /// </summary>
        /// <param name="size">
        /// The number of elements in the secure array.
        /// </param>
        /// <param name="type">
        /// The type of secure array to initialize. Defaults to <see cref="SecureArrayType"/>.<see
        /// cref="SecureArrayType.ZeroedPinnedAndNoSwap"/>.
        /// </param>
        public SecureArray(int size, SecureArrayType type = SecureArrayType.ZeroedPinnedAndNoSwap)
        {
            this.buf = new T[size];
            this.Init(this.buf, type);
        }

        /// <summary>
        /// Gets the secure array.
        /// </summary>
        public T[] Buffer => this.buf;

        /// <summary>
        /// Gets or sets elements in the secure array.
        /// </summary>
        /// <param name="i">
        /// The index of the element.
        /// </param>
        /// <returns>
        /// The element.
        /// </returns>
        public T this[int i]
        {
            get
            {
                return this.buf[i];
            }

            set
            {
                this.buf[i] = value;
            }
        }

        /// <summary>
        /// Zero buffer and release resources.
        /// </summary>
        public void Dispose()
        {
            this.Cleanup(this.buf);
        }
    }
}
