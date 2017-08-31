// <copyright file="SecureArray.Osx.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray
{
    using System;
    using System.Runtime.InteropServices;

    /// <content>
    /// The OSX-specific parts of <see cref="SecureArray"/>.
    /// </content>
    public partial class SecureArray
    {
        [DllImport("libSystem", SetLastError = true, EntryPoint = "mlock")]
        private static extern int OsxMlock(IntPtr addr, UIntPtr len);

        [DllImport("libSystem", SetLastError = true, EntryPoint = "munlock")]
        private static extern int OsxMunlock(IntPtr addr, UIntPtr len);

        [DllImport("libSystem", EntryPoint = "memset")]
        private static extern IntPtr OsxMemset(IntPtr addr, int c, UIntPtr n);
    }
}