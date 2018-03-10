// <copyright file="DefaultLinuxSecureArrayCall.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray
{
    using System;
    using System.Runtime.InteropServices;

    /// <summary>
    /// A <see cref="SecureArrayCall"/> with defaults for the Linux operating system.
    /// </summary>
    public class DefaultLinuxSecureArrayCall : SecureArrayCall
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultLinuxSecureArrayCall"/> class.
        /// </summary>
        public DefaultLinuxSecureArrayCall()
            : base((m, l) => LinuxMemset(m, 0, l), LinuxLockMemory, (m, l) => LinuxMunlock(m, l))
        {
        }

        private static string LinuxLockMemory(IntPtr m, UIntPtr l)
        {
            if (LinuxMlock(m, l) != 0)
            {
                var errcode = Marshal.GetLastWin32Error();
                if (LinuxTryRaiseCurrentMlockLimit(out string raiseError))
                {
                    if (LinuxMlock(m, l) == 0)
                    {
                        return null;
                    }

                    errcode = Marshal.GetLastWin32Error();
                }

                return $"mlock error: {LinuxStrError(errcode)}{(raiseError == null ? string.Empty : $" ({raiseError})")}";
            }

            return null;
        }

        private static bool LinuxTryRaiseCurrentMlockLimit(out string error)
        {
            var rlimit = new LinuxRlimit { RlimCur = 0, RlimMax = 0 }; // not sure always 64-bit RlimCur and RLimMax values
            int rlimitMemlock = 8; // not sure RLIMIT_MEMLOCK is always 8
            bool ret = false;
            if (LinuxGetRLimit(rlimitMemlock, ref rlimit) != 0)
            {
                error = $"attempted getrlimit(RLIMIT_MEMLOCK), got error: {LinuxStrError(Marshal.GetLastWin32Error())}.";
                return false;
            }

            if (rlimit.RlimCur < rlimit.RlimMax)
            {
                rlimit.RlimCur = rlimit.RlimMax;
                if (LinuxSetRLimit(rlimitMemlock, ref rlimit) != 0)
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
            if (LinuxSetRLimit(rlimitMemlock, ref rlimit) == 0)
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
                IntPtr bufPtr = LinuxSterrorR(errno, bufHandle.AddrOfPinnedObject(), (ulong)buf.Length);
                return Marshal.PtrToStringAnsi(bufPtr);
            }
            finally
            {
                bufHandle.Free();
            }
        }

        [DllImport("libc", SetLastError = true, EntryPoint = "mlock")]
        private static extern int LinuxMlock(IntPtr addr, UIntPtr len);

        [DllImport("libc", SetLastError = true, EntryPoint = "munlock")]
        private static extern int LinuxMunlock(IntPtr addr, UIntPtr len);

        [DllImport("libc", EntryPoint = "memset")]
        private static extern IntPtr LinuxMemset(IntPtr addr, int c, UIntPtr n);

        [DllImport("libc", EntryPoint = "getrlimit", SetLastError = true)]
        private static extern int LinuxGetRLimit(int resource, ref LinuxRlimit rlimit);

        [DllImport("libc", EntryPoint = "setrlimit", SetLastError = true)]
        private static extern int LinuxSetRLimit(int resource, ref LinuxRlimit rlimit);

        [DllImport("libc", EntryPoint = "strerror_r", CharSet = CharSet.Ansi)]
        private static extern IntPtr LinuxSterrorR(int errno, IntPtr buf, ulong buflen);

        /// <summary>
        /// The structure for the setrlimit() and getrlimit() calls.
        /// </summary>
        /// <remarks>
        /// On Linux, I found a comment in /usr/include/x64_32-linux-gnu/bits/typesizes.h
        /// that said "X32 kernel interface is 64-bit" and the code seemed to bare that out
        /// so this should work for both 32-bit and 64-bit kernels.
        /// </remarks>
        [StructLayout(LayoutKind.Sequential, Size = 16)]
        private struct LinuxRlimit
        {
            // ReSharper disable FieldCanBeMadeReadOnly.Local
            // ReSharper disable MemberCanBePrivate.Local
            public ulong RlimCur;
            public ulong RlimMax;

            // ReSharper restore MemberCanBePrivate.Local
            // ReSharper restore FieldCanBeMadeReadOnly.Local
        }
    }
}
