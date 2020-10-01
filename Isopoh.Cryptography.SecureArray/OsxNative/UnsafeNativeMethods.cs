// <copyright file="UnsafeNativeMethods.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray.OsxNative
{
    using System;
    using System.Runtime.InteropServices;
    using System.Security;

    /// <summary>
    /// Contains "unsafe" native methods for the OSX operating system.
    /// </summary>
    [SuppressUnmanagedCodeSecurity]
    internal static class UnsafeNativeMethods
    {
        /// <summary>
        /// Lock part or all of the calling process's virtual address space
        /// into RAM, preventing that memory from being paged to the swap area.
        /// </summary>
        /// <param name="addr">Start of memory to lock into RAM.</param>
        /// <param name="len">Byte count of memory to lock into RAM.</param>
        /// <returns>0 on success; -1 on error.</returns>
        [DllImport("libSystem", SetLastError = true, EntryPoint = "mlock")]
        public static extern int OsxMlock(IntPtr addr, UIntPtr len);

        /// <summary>
        /// Unlocks pages in the address range starting at <paramref
        /// name="addr"/> and continuing for <paramref name="len"/> bytes.
        /// After this call, all pages that contain a part of the specified
        /// memory range can be moved to external swap space again by the kernel.
        /// </summary>
        /// <param name="addr">Start of memory to unlock from RAM.</param>
        /// <param name="len">Byte count of memory to unlock from RAM.</param>
        /// <returns>0 on success; -1 on error.</returns>
        [DllImport("libSystem", SetLastError = true, EntryPoint = "munlock")]
        public static extern int OsxMunlock(IntPtr addr, UIntPtr len);

        /// <summary>
        /// Fills the first <paramref name="n"/> bytes of <paramref
        /// name="addr"/> with the value <paramref name="c"/>.
        /// </summary>
        /// <param name="addr">The buffer to fill.</param>
        /// <param name="c">The byte value to fill with.</param>
        /// <param name="n">The number of bytes to fill.</param>
        /// <returns><paramref name="addr"/>.</returns>
        [DllImport("libSystem", EntryPoint = "memset")]
        public static extern IntPtr OsxMemset(IntPtr addr, int c, UIntPtr n);
    }
}
