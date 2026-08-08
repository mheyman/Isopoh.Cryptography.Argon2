// <copyright file="UnsafeNativeMethods.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray.UwpNative;

using System;
using System.Runtime.InteropServices;
using System.Security;

/// <summary>
/// Contains "unsafe" native methods for the Universal Windows Platform.
/// </summary>
[SuppressUnmanagedCodeSecurity]
internal static class UnsafeNativeMethods
{
    /// <summary>
    /// Fills the first <paramref name="n"/> bytes of <paramref
    /// name="addr"/> with the value <paramref name="c"/>.
    /// </summary>
    /// <param name="addr">The buffer to fill.</param>
    /// <param name="c">The byte value to fill with.</param>
    /// <param name="n">The number of bytes to fill.</param>
    /// <returns><paramref name="addr"/>.</returns>
    [DllImport("api-ms-win-crt-string-l1-1-0.dll", EntryPoint = "memset")]
    public static extern IntPtr UwpMemset(IntPtr addr, int c, nuint n);

    /////// <summary>
    /////// Fills <paramref name="buf"/> with error text based on <paramref name="errno"/>.
    /////// </summary>
    /////// <param name="buf">The buffer to fill.</param>
    /////// <param name="buflen">The maximum length of the buffer to fill.</param>
    /////// <param name="errno">The error number to get text for.</param>
    /////// <returns>0 on success; a positive error number on failure.</returns>
    ////[DllImport("ucrtbase.dll", EntryPoint = "strerror_s", CharSet = CharSet.Ansi)]
    ////public static extern int UwpSterrorS(IntPtr buf, ulong buflen, int errno);
}