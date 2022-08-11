// <copyright file="DefaultWebSecureArrayCall.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray
{
    using System;
    using System.Runtime.InteropServices;

    /// <summary>
    /// A <see cref="SecureArrayCall"/> with defaults for running in a browser.
    /// </summary>
    public class DefaultWebSecureArrayCall : SecureArrayCall
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultWebSecureArrayCall"/> class.
        /// </summary>
        public DefaultWebSecureArrayCall()
            : base(
                WebZero,
                WebLockMemory,
                WebUnlockMemory,
                "Web")
        {
            if (RuntimeInformation.OSDescription != "web" && RuntimeInformation.OSDescription != "Browser")
            {
                throw new DllNotFoundException($"Running on \"{RuntimeInformation.OSDescription}\", not \"web\" or \"Browser\".");
            }
        }

        #nullable enable
        private static string? WebLockMemory(IntPtr m, UIntPtr l)
        #nullable restore
        {
            // cannot prevent memory from swapping within the browser.
            return null;
        }

        private static void WebUnlockMemory(IntPtr m, UIntPtr l)
        {
            // cannot prevent memory from swapping within the browser.
        }

        private static void WebZero(IntPtr m, UIntPtr l)
        {
            Marshal.Copy(new byte[(int)l.ToUInt32()], 0, m, (int)l.ToUInt32());
        }
    }
}
