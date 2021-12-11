// <copyright file="DefaultUwpSecureArrayCall.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray
{
    using System;
    using System.Runtime.InteropServices;
    using Isopoh.Cryptography.SecureArray.UwpNative;

    /// <summary>
    /// A <see cref="SecureArrayCall"/> with defaults for the Universal Windows Platform.
    /// </summary>
    public class DefaultUwpSecureArrayCall : SecureArrayCall
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultUwpSecureArrayCall"/> class.
        /// </summary>
        public DefaultUwpSecureArrayCall()
            : base(
                (m, l) => UnsafeNativeMethods.UwpMemset(m, 0, l),
                UwpLockMemory,
                UwpUnlockMemory,
                "UWP")
        {
            var buffer = new byte[1];
            var bufHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                IntPtr bufPtr = bufHandle.AddrOfPinnedObject();
                _ = UnsafeNativeMethods.UwpMemset(bufPtr, 0, (nuint)buffer.Length);
            }
            finally
            {
                bufHandle.Free();
            }
        }

        private static string? UwpLockMemory(IntPtr m, UIntPtr l)
        {
            // cannot prevent memory from swapping within UWP.
            return null;
        }

        private static void UwpUnlockMemory(IntPtr m, UIntPtr l)
        {
            // cannot prevent memory from swapping within UWP.
        }
    }
}
