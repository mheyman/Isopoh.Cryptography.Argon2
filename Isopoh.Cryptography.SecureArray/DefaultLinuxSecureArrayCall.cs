// <copyright file="DefaultLinuxSecureArrayCall.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray
{
    using System;
    using System.Runtime.InteropServices;
    using Isopoh.Cryptography.SecureArray.LinuxNative;

    /// <summary>
    /// A <see cref="SecureArrayCall"/> with defaults for the Linux operating system.
    /// </summary>
    public class DefaultLinuxSecureArrayCall : SecureArrayCall
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultLinuxSecureArrayCall"/> class.
        /// </summary>
        public DefaultLinuxSecureArrayCall()
            : base((m, l) => UnsafeNativeMethods.LinuxMemset(m, 0, l), LinuxLockMemory, (m, l) =>
            {
                 _ = UnsafeNativeMethods.LinuxMunlock(m, l);
            })
        {
        }

        private static string? LinuxLockMemory(IntPtr m, UIntPtr l)
        {
            if (UnsafeNativeMethods.LinuxMlock(m, l) != 0)
            {
                var errorCode = Marshal.GetLastWin32Error();
                if (LinuxTryRaiseCurrentMlockLimit(out string? raiseError))
                {
                    if (UnsafeNativeMethods.LinuxMlock(m, l) == 0)
                    {
                        return null;
                    }

                    errorCode = Marshal.GetLastWin32Error();
                }

                return $"mlock error: {LinuxStrError(errorCode)}{(raiseError == null ? string.Empty : $" ({raiseError})")}";
            }

            return null;
        }

        private static bool LinuxTryRaiseCurrentMlockLimit(out string? error)
        {
            var rlimit = new UnsafeNativeMethods.LinuxRlimit { RlimCur = 0, RlimMax = 0 }; // not sure always 64-bit RlimCur and RLimMax values
            int rlimitMemlock = 8; // not sure RLIMIT_MEMLOCK is always 8
            bool ret = false;
            if (UnsafeNativeMethods.LinuxGetRLimit(rlimitMemlock, ref rlimit) != 0)
            {
                error = $"attempted getrlimit(RLIMIT_MEMLOCK), got error: {LinuxStrError(Marshal.GetLastWin32Error())}.";
                return false;
            }

            if (rlimit.RlimCur < rlimit.RlimMax)
            {
                rlimit.RlimCur = rlimit.RlimMax;
                if (UnsafeNativeMethods.LinuxSetRLimit(rlimitMemlock, ref rlimit) != 0)
                {
                    error = $"attempted setrlimit(RLIMIT_MEMLOCK, {{{rlimit.RlimCur}, {rlimit.RlimMax}}}), got error: {LinuxStrError(Marshal.GetLastWin32Error())}.";
                    return false;
                }

                ret = true;
            }

            // Go for broke
            var currentMax = rlimit.RlimMax;
            rlimit.RlimCur = ulong.MaxValue;
            rlimit.RlimMax = ulong.MaxValue;
            if (UnsafeNativeMethods.LinuxSetRLimit(rlimitMemlock, ref rlimit) == 0)
            {
                error = null;
                return true;
            }

            error = $"attempted setrlimit(RLIMIT_MEMLOCK, {{{rlimit.RlimCur}, {rlimit.RlimMax}}}) on current max {currentMax} bytes, got error: {LinuxStrError(Marshal.GetLastWin32Error())}.";
            return ret;
        }

        private static string LinuxStrError(int errno)
        {
            var buf = new byte[256];
            var bufHandle = GCHandle.Alloc(buf, GCHandleType.Pinned);
            try
            {
                IntPtr bufPtr = UnsafeNativeMethods.LinuxSterrorR(errno, bufHandle.AddrOfPinnedObject(), (ulong)buf.Length);
                return Marshal.PtrToStringAnsi(bufPtr) ?? $"Unknown error {errno}";
            }
            finally
            {
                bufHandle.Free();
            }
        }
    }
}
