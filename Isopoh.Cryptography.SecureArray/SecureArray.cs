// <copyright file="SecureArray.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime.InteropServices;

    /// <summary>
    /// Base class of all <see cref="SecureArray{T}"/> classes.
    /// </summary>
    public partial class SecureArray
    {
        /// <summary>
        /// Cannot find a way to do a compile-time verification that the
        /// array element type is one of these so this dictionary gets
        /// used to do it at runtime.
        /// </summary>
        private static readonly Dictionary<Type, int> TypeSizes =
            new Dictionary<Type, int>
                {
                    { typeof(sbyte), sizeof(sbyte) },
                    { typeof(byte), sizeof(byte) },
                    { typeof(short), sizeof(short) },
                    { typeof(ushort), sizeof(ushort) },
                    { typeof(int), sizeof(int) },
                    { typeof(uint), sizeof(uint) },
                    { typeof(long), sizeof(long) },
                    { typeof(ulong), sizeof(ulong) },
                    { typeof(char), sizeof(char) },
                    { typeof(float), sizeof(float) },
                    { typeof(double), sizeof(double) },
                    { typeof(decimal), sizeof(decimal) },
                    { typeof(bool), sizeof(bool) }
                };

        /// <summary>
        /// Call to zero memory in a way that does not get optimized away.
        /// </summary>
        /// <remarks>
        /// On Linux and OSX, simply calls memset() and hopes the P/Invoke
        /// mechanism does not have special handling for memset calls (and
        /// thus does not even think about optimizing the call away).
        /// </remarks>
        private static readonly Action<IntPtr, UIntPtr> ZeroMemory;

        /// <summary>
        /// Lock the given memory so it doesn't get swapped out to disk.
        /// </summary>
        /// <returns>
        /// Null on success; otherwise an error message.
        /// </returns>
        private static readonly Func<IntPtr, UIntPtr, string> LockMemory;

        /// <summary>
        /// Unlock memory previously locked by a call to <see cref="LockMemory"/>.
        /// </summary>
        private static readonly Action<IntPtr, UIntPtr> UnlockMemory;

        private GCHandle handle;

        private bool virtualLocked;

        static SecureArray()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                ZeroMemory = (m, l) => LinuxMemset(m, 0, l);
                LockMemory = LinuxLockMemory;
                UnlockMemory = (m, l) => LinuxMunlock(m, l);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                ZeroMemory = (m, l) => OsxMemset(m, 0, l);
                LockMemory = (m, l) => OsxMlock(m, l) != 0 ? $"mlock error code: {Marshal.GetLastWin32Error()}" : null;
                UnlockMemory = (m, l) => OsxMunlock(m, l);
            }
            else
            {
                ZeroMemory = RtlZeroMemory;
                LockMemory = WindowsLockMemory;
                UnlockMemory = (m, l) => VirtualUnlock(m, l);
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecureArray"/> class.
        /// </summary>
        /// <remarks>
        /// You cannot create a <see cref="SecureArray"/> directly, you must
        /// derive from this class like <see cref="SecureArray{T}"/> does.
        /// </remarks>
        protected SecureArray()
        {
        }

        /// <summary>
        /// Gets the size of the buffer element. Will throw a
        /// <see cref="NotSupportedException"/> if the element type is not
        /// a built in type.
        /// </summary>
        /// <typeparam name="T">
        /// The array element type to return the size of.
        /// </typeparam>
        /// <param name="buffer">
        /// The array.
        /// </param>
        /// <returns>
        /// The lengths in bytes of the size of the element in <paramref name="buffer"/>.
        /// </returns>
        public static int BuiltInTypeElementSize<T>(T[] buffer)
        {
            int elementSize;
            if (!TypeSizes.TryGetValue(typeof(T), out elementSize))
            {
                throw new NotSupportedException(
                    $"Type {typeof(T).Name} not a built in type. "
                    + $"Valid types: {string.Join(", ", TypeSizes.Keys.Select(t => t.Name))}");
            }

            return elementSize;
        }

        /// <summary>
        /// Zero the given buffer in a way that will not be optimized away.
        /// </summary>
        /// <typeparam name="T">
        /// The type of the elements in the buffer.
        /// </typeparam>
        /// <param name="buffer">
        /// The buffer to zero.
        /// </param>
        public static void Zero<T>(T[] buffer)
            where T : struct
        {
            var bufHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                IntPtr bufPtr = bufHandle.AddrOfPinnedObject();
                UIntPtr cnt = new UIntPtr((uint)buffer.Length * (uint)BuiltInTypeElementSize(buffer));
                ZeroMemory(bufPtr, cnt);
            }
            finally
            {
                bufHandle.Free();
            }
        }

        /// <summary>
        /// Zero <paramref name="buf"/> and release resources.
        /// </summary>
        /// <typeparam name="T">
        /// The type of the array elements in <paramref name="buf"/>.
        /// </typeparam>
        /// <param name="buf">
        /// The buffer to zero and whose resources to release. Should be
        /// the same as passed into <see cref="Init{T}"/>.
        /// </param>
        protected void Cleanup<T>(T[] buf)
        {
            var sizeInBytes = BuiltInTypeElementSize(buf) * buf.Length;
            if (this.handle == default(GCHandle))
            {
                this.handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
            }

            try
            {
                IntPtr bufPtr = this.handle.AddrOfPinnedObject();
                UIntPtr cnt = new UIntPtr((uint)sizeInBytes);
                ZeroMemory(bufPtr, cnt);
                if (this.virtualLocked)
                {
                    UnlockMemory(bufPtr, cnt);
                }
            }
            finally
            {
                this.handle.Free();
            }
        }

        /// <summary>
        /// Call this with the array to secure and the number of bytes in that
        /// array. The buffer will be zeroed and the handle freed when the
        /// instance is disposed.
        /// </summary>
        /// <typeparam name="T">
        /// The type of the array elements in <paramref name="buf"/>.
        /// </typeparam>
        /// <param name="buf">
        /// The array to secure.
        /// </param>
        /// <param name="type">
        /// The type of secure array to initialize.
        /// </param>
        /// <exception cref="LockFailException">
        /// Operating system did not allow the memory to be locked.
        /// </exception>
        protected void Init<T>(T[] buf, SecureArrayType type)
        {
            var sizeInBytes = BuiltInTypeElementSize(buf) * buf.Length;
            if (type == SecureArrayType.ZeroedAndPinned || type == SecureArrayType.ZeroedPinnedAndNoSwap)
            {
                this.handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
                if (type == SecureArrayType.ZeroedPinnedAndNoSwap)
                {
                    IntPtr bufPtr = this.handle.AddrOfPinnedObject();
                    UIntPtr cnt = new UIntPtr((uint)sizeInBytes);
                    ZeroMemory(bufPtr, cnt);
                    string err = LockMemory(bufPtr, cnt);
                    if (err != null)
                    {
                        int max = GetMaxLockable();
                        var msg = max > sizeInBytes ? $"Under current available value of {max} bytes (try again, it may work)" : $"Currently available: {max} bytes";
                        throw new LockFailException($"Failed to lock {sizeInBytes} bytes into RAM. {msg}. {err}.", max);
                    }

                    this.virtualLocked = true;
                }
            }
        }

        /// <summary>
        /// Perform a binary search to find the current max lockable memory amount. Used
        /// for error reporting.
        /// </summary>
        /// <returns>
        /// The current number of bytes that can be locked. This is likely to change on
        /// subsequent calls.
        /// </returns>
        private static int GetMaxLockable()
        {
            ulong low = 0;
            ulong high = int.MaxValue;
            while (low < high)
            {
                var cur = (high + low) / 2;
                if (cur == low)
                {
                    break;
                }

                try
                {
                    var buf = new byte[cur];
                    var handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
                    try
                    {
                        IntPtr bufPtr = handle.AddrOfPinnedObject();
                        var len = new UIntPtr(cur);
                        if (LockMemory(bufPtr, len) == null)
                        {
                            UnlockMemory(bufPtr, len);
                            low = cur;
                        }
                        else
                        {
                            // lock failed
                            high = cur - 1;
                        }
                    }
                    finally
                    {
                        handle.Free();
                    }
                }
                catch (OutOfMemoryException)
                {
                    // new failed. Act like lock failed
                    high = cur - 1;
                }
            }

            return (int)low;
        }
    }
}