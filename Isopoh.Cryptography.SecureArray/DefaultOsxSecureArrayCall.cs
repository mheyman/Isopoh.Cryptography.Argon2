// <copyright file="DefaultOsxSecureArrayCall.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray
{
    using System;
    using System.Runtime.InteropServices;

    /// <summary>
    /// A <see cref="SecureArrayCall"/> with defaults for the OSX operating system.
    /// </summary>
    public class DefaultOsxSecureArrayCall : SecureArrayCall
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultOsxSecureArrayCall"/> class.
        /// </summary>
        public DefaultOsxSecureArrayCall()
            : base(
                  (m, l) => OsxMemset(m, 0, l),
                  (m, l) => OsxMlock(m, l) != 0 ? $"mlock error code: {Marshal.GetLastWin32Error()}" : null,
                  (m, l) => OsxMunlock(m, l))
        {
        }

        [DllImport("libSystem", SetLastError = true, EntryPoint = "mlock")]
        private static extern int OsxMlock(IntPtr addr, UIntPtr len);

        [DllImport("libSystem", SetLastError = true, EntryPoint = "munlock")]
        private static extern int OsxMunlock(IntPtr addr, UIntPtr len);

        [DllImport("libSystem", EntryPoint = "memset")]
        private static extern IntPtr OsxMemset(IntPtr addr, int c, UIntPtr n);
    }
}
