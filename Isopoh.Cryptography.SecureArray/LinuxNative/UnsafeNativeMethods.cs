// <copyright file="UnsafeNativeMethods.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray.LinuxNative
{
    using System;
    using System.Runtime.InteropServices;
    using System.Security;

    /// <summary>
    /// Contains "unsafe" native methods for the Linux operating system.
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
        [DllImport("libc", SetLastError = true, EntryPoint = "mlock")]
        public static extern int LinuxMlock(IntPtr addr, nuint len);

        /// <summary>
        /// Unlocks pages in the address range starting at <paramref
        /// name="addr"/> and continuing for <paramref name="len"/> bytes.
        /// After this call, all pages that contain a part of the specified
        /// memory range can be moved to external swap space again by the kernel.
        /// </summary>
        /// <param name="addr">Start of memory to unlock from RAM.</param>
        /// <param name="len">Byte count of memory to unlock from RAM.</param>
        /// <returns>0 on success; -1 on error.</returns>
        [DllImport("libc", SetLastError = true, EntryPoint = "munlock")]
        public static extern int LinuxMunlock(IntPtr addr, nuint len);

        /// <summary>
        /// Fills the first <paramref name="n"/> bytes of <paramref
        /// name="addr"/> with the value <paramref name="c"/>.
        /// </summary>
        /// <param name="addr">The buffer to fill.</param>
        /// <param name="c">The byte value to fill with.</param>
        /// <param name="n">The number of bytes to fill.</param>
        /// <returns><paramref name="addr"/>.</returns>
        [DllImport("libc", EntryPoint = "memset")]
        public static extern IntPtr LinuxMemset(IntPtr addr, int c, nuint n);

        /// <summary>
        /// Gets resource limits.
        /// </summary>
        /// <param name="resource">The resource to get.</param>
        /// <param name="rlimit">Populated with the resource values.</param>
        /// <returns>0 on success; -1 on error and errno is set appropriately.</returns>
        [DllImport("libc", EntryPoint = "getrlimit", SetLastError = true)]
        public static extern int LinuxGetRLimit(int resource, ref LinuxRlimit rlimit);

        /// <summary>
        /// Sets resource limits.
        /// </summary>
        /// <param name="resource">The resource to set.</param>
        /// <param name="rlimit">Resource values to set.</param>
        /// <returns>0 on success; -1 on error and errno is set appropriately.</returns>
        [DllImport("libc", EntryPoint = "setrlimit", SetLastError = true)]
        public static extern int LinuxSetRLimit(int resource, ref LinuxRlimit rlimit);

        /// <summary>
        /// Fills <paramref name="buf"/> with error text based on <paramref name="errno"/>.
        /// </summary>
        /// <param name="errno">The error number to get text for.</param>
        /// <param name="buf">The buffer to fill.</param>
        /// <param name="buflen">The maximum length of the buffer to fill.</param>
        /// <returns>0 on success; a positive error number on failure.</returns>
        [DllImport("libc", EntryPoint = "strerror_r", CharSet = CharSet.Ansi)]
        public static extern IntPtr LinuxSterrorR(int errno, IntPtr buf, ulong buflen);

        /// <summary>
        /// The structure for the setrlimit() and getrlimit() calls.
        /// </summary>
        /// <remarks>
        /// On Linux, I found a comment in /usr/include/x64_32-linux-gnu/bits/typesizes.h
        /// that said "X32 kernel interface is 64-bit" and the code seemed to bare that out
        /// so this should work for both 32-bit and 64-bit kernels.
        /// </remarks>
        [StructLayout(LayoutKind.Sequential, Size = 16)]
        public struct LinuxRlimit
        {
            // ReSharper disable FieldCanBeMadeReadOnly.Local
            // ReSharper disable MemberCanBePrivate.Local

            /// <summary>
            /// Soft limit.
            /// </summary>
            public ulong RlimCur;

            /// <summary>
            /// Hard limit (ceiling for <see cref="RlimCur"/>.
            /// </summary>
            public ulong RlimMax;

            // ReSharper restore MemberCanBePrivate.Local
            // ReSharper restore FieldCanBeMadeReadOnly.Local
        }
    }
}
