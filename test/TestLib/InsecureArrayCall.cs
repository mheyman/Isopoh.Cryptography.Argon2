// <copyright file="InsecureArrayCall.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace TestLib;

using System;
using Isopoh.Cryptography.SecureArray;

/// <summary>
/// Does not zero or lock memory.
/// </summary>
/// <remarks>
/// Useful for benchmarking just the hash with no secure memory overhead.
/// </remarks>
public sealed class InsecureArrayCall : SecureArrayCall
{
    /// <summary>
    /// Initializes a new instance of the <see cref="InsecureArrayCall"/> class.
    /// </summary>
    public InsecureArrayCall()
        : base(NoZeroMemory, NoLockMemory, NoUnlockMemory, "No OS (insecure)")
    {
    }

    private static void NoZeroMemory(IntPtr buf, UIntPtr len)
    {
    }

    private static string? NoLockMemory(IntPtr buf, UIntPtr len)
    {
        return null;
    }

    private static void NoUnlockMemory(IntPtr buf, UIntPtr len)
    {
    }
}