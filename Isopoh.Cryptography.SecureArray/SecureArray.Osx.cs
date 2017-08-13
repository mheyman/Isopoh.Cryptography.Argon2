namespace Isopoh.Cryptography.SecureArray
{
    using System;
    using System.Runtime.InteropServices;
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