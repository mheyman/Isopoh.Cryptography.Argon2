// <copyright file="DefaultWindowsSecureArrayCall.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray
{
    using System;
    using System.Runtime.InteropServices;

    /// <summary>
    /// A <see cref="SecureArrayCall"/> with defaults for the Windows operating system.
    /// </summary>
    public class DefaultWindowsSecureArrayCall : SecureArrayCall
    {
        private static readonly object Is32BitSubsystemLock = new object();

        private static readonly object GetProcessWorkingSetSizeLock = new object();

        private static readonly object SetProcessWorkingSetSizeLock = new object();

        private static readonly object VirtualAllocLock = new object();

        private static bool? is32BitSubsystem;

        private static GetProcessWorkingSetSizeExDelegate getProcessWorkingSetSize;

        private static Func<IntPtr, ulong, ulong, uint, bool> setProcessWorkingSetSize;

        private static Func<IntPtr, ulong, uint, uint, IntPtr> virtualAlloc;

        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultWindowsSecureArrayCall"/> class.
        /// </summary>
        public DefaultWindowsSecureArrayCall()
            : base(RtlZeroMemory, null, (m, l) => VirtualUnlock(m, l))
        {
            this.LockMemory = this.WindowsLockMemory;
        }

        private delegate bool GetProcessWorkingSetSizeExDelegate(
            IntPtr processHandle,
            ref ulong minWorkingSetSize,
            ref ulong maxWorkingSetSize,
            ref uint flags);

        private static bool Is32BitSubsystem
        {
            get
            {
                if (!is32BitSubsystem.HasValue)
                {
                    lock (Is32BitSubsystemLock)
                    {
                        if (!is32BitSubsystem.HasValue)
                        {
                            if (IntPtr.Size == 4)
                            {
                                is32BitSubsystem = true;
                            }
                            else
                            {
                                IntPtr kernelModuleHandle = GetModuleHandle("kernel32");
                                if (kernelModuleHandle == IntPtr.Zero)
                                {
                                    // much worse problems then just saying it is 32-bit so it is okay to lie here
                                    is32BitSubsystem = true;
                                }
                                else
                                {
                                    if (GetProcAddress(kernelModuleHandle, "IsWow64Process") == IntPtr.Zero)
                                    {
                                        is32BitSubsystem = true; // kernel32.dll in 32-bit OS doesn't have IsWowProcess()
                                    }
                                    else
                                    {
                                        is32BitSubsystem =
                                            IsWow64Process(GetCurrentProcess(), out var isWow64Process)
                                            && isWow64Process;
                                    }
                                }
                            }
                        }
                    }
                }

                return is32BitSubsystem.Value;
            }
        }

        /// <summary>
        /// Gets a delegate VirtualAlloc() that works on 32-bit or 64-bit operating systems.
        /// </summary>
        private Func<IntPtr, ulong, uint, uint, IntPtr> VirtualAlloc
        {
            get
            {
                if (virtualAlloc == null)
                {
                    lock (VirtualAllocLock)
                    {
                        if (virtualAlloc == null)
                        {
                            virtualAlloc = Is32BitSubsystem
                                ? (lpAddress, size, allocationTypeFlags, protectFlags) =>
                                {
                                    if (size > uint.MaxValue)
                                    {
                                        SetLastError(8); // ERROR_NOT_ENOUGH_MEMORY
                                        return IntPtr.Zero;
                                    }

                                    return VirtualAlloc32(lpAddress, (uint)size, allocationTypeFlags, protectFlags);
                                }
                                : (Func<IntPtr, ulong, uint, uint, IntPtr>)VirtualAlloc64;
                        }
                    }
                }

                return virtualAlloc;
            }
        }

        /// <summary>
        /// Gets a delegate SetProcessWorkingSetSizeEx() that works on 32-bit or 64-bit operating systems.
        /// </summary>
        private Func<IntPtr, ulong, ulong, uint, bool> SetProcessWorkingSetSizeEx
        {
            get
            {
                if (setProcessWorkingSetSize == null)
                {
                    lock (SetProcessWorkingSetSizeLock)
                    {
                        if (setProcessWorkingSetSize == null)
                        {
                            setProcessWorkingSetSize = Is32BitSubsystem
                                ? ((processHandle, minWorkingSetSize, maxWorkingSetSize, flags) =>
                                {
                                    uint min = minWorkingSetSize > uint.MaxValue ? uint.MaxValue : (uint)minWorkingSetSize;
                                    uint max = maxWorkingSetSize > uint.MaxValue ? uint.MaxValue : (uint)maxWorkingSetSize;
                                    return SetProcessWorkingSetSizeEx32(
                                        processHandle,
                                        min,
                                        max,
                                        flags);
                                })
                                : (Func<IntPtr, ulong, ulong, uint, bool>)SetProcessWorkingSetSizeEx64;
                        }
                    }
                }

                return setProcessWorkingSetSize;
            }
        }

        /// <summary>
        /// Gets a delegate GetProcessWorkingSetSizeEx() that works on 32-bit or 64-bit operating systems.
        /// </summary>
        private GetProcessWorkingSetSizeExDelegate GetProcessWorkingSetSizeEx
        {
            get
            {
                if (getProcessWorkingSetSize == null)
                {
                    lock (GetProcessWorkingSetSizeLock)
                    {
                        if (getProcessWorkingSetSize == null)
                        {
                            getProcessWorkingSetSize =
                                Is32BitSubsystem
                                    ? GetProcessWorkingSetSizeEx32Wrapper
                                    : (GetProcessWorkingSetSizeExDelegate)GetProcessWorkingSetSizeEx64;
                        }
                    }
                }

                return getProcessWorkingSetSize;
            }
        }

        [DllImport("psapi.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        private static extern bool GetProcessMemoryInfo(IntPtr hProcess, out ProcessMemoryCounters counters, uint size);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport(
            "kernel32.dll",
            EntryPoint = "GetProcessWorkingSetSizeEx",
            CallingConvention = CallingConvention.Winapi,
            SetLastError = true)]
        private static extern bool GetProcessWorkingSetSizeEx64(
            IntPtr processHandle,
            ref ulong minWorkingSetSize,
            ref ulong maxWorkingSetSize,
            ref uint flags);

        [DllImport(
            "kernel32.dll",
            EntryPoint = "GetProcessWorkingSetSizeEx",
            CallingConvention = CallingConvention.Winapi,
            SetLastError = true)]
        private static extern bool GetProcessWorkingSetSizeEx32(
            IntPtr processHandle,
            ref uint minWorkingSetSize,
            ref uint maxWorkingSetSize,
            ref uint flags);

        private static bool GetProcessWorkingSetSizeEx32Wrapper(
            IntPtr processHandle,
            ref ulong minWorkingSetSize,
            ref ulong maxWorkingSetSize,
            ref uint flags)
        {
            uint min = minWorkingSetSize > uint.MaxValue ? uint.MaxValue : (uint)minWorkingSetSize;
            uint max = maxWorkingSetSize > uint.MaxValue ? uint.MaxValue : (uint)maxWorkingSetSize;
            bool ret = GetProcessWorkingSetSizeEx32(processHandle, ref min, ref max, ref flags);
            minWorkingSetSize = min;
            maxWorkingSetSize = max;
            return ret;
        }

        [DllImport(
            "kernel32.dll",
            EntryPoint = "SetProcessWorkingSetSizeEx",
            CallingConvention = CallingConvention.Winapi,
            SetLastError = true)]
        private static extern bool SetProcessWorkingSetSizeEx64(
            IntPtr processHandle,
            ulong minWorkingSetSize,
            ulong maxWorkingSetSize,
            uint flags);

        [DllImport(
            "kernel32.dll",
            EntryPoint = "SetProcessWorkingSetSizeEx",
            CallingConvention = CallingConvention.Winapi,
            SetLastError = true)]
        private static extern bool SetProcessWorkingSetSizeEx32(
            IntPtr processHandle,
            uint minWorkingSetSize,
            uint maxWorkingSetSize,
            uint flags);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern void RtlZeroMemory(IntPtr ptr, UIntPtr cnt);

        [DllImport(
            "kernel32.dll",
            EntryPoint = "VirtualAlloc",
            CallingConvention = CallingConvention.Winapi,
            SetLastError = true)]
        private static extern IntPtr VirtualAlloc64(
            IntPtr lpAddress,
            ulong size,
            uint allocationTypeFlags,
            uint protoectFlags);

        [DllImport(
            "kernel32.dll",
            EntryPoint = "VirtualAlloc",
            CallingConvention = CallingConvention.Winapi,
            SetLastError = true)]
        private static extern IntPtr VirtualAlloc32(
            IntPtr lpAddress,
            uint size,
            uint allocationTypeFlags,
            uint protoectFlags);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        private static extern bool VirtualLock(IntPtr lpAddress, UIntPtr dwSize);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        private static extern bool VirtualUnlock(IntPtr lpAddress, UIntPtr dwSize);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        private static extern void SetLastError(uint dwErrorCode);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr GetModuleHandle(string moduleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int VirtualQuery(IntPtr lpAddress, out MemoryBasicInformation lpBuffer, uint dwLength);

        private static ulong GetWorkingSetSize(IntPtr processHandle)
        {
            // ReSharper disable once InlineOutVariableDeclaration
            var memoryCounters =
                new ProcessMemoryCounters { Cb = (uint)Marshal.SizeOf<ProcessMemoryCounters>() };

            return GetProcessMemoryInfo(processHandle, out memoryCounters, memoryCounters.Cb)
                       ? memoryCounters.WorkingSetSize
                       : 0;
        }

        private string WindowsLockMemory(IntPtr m, UIntPtr l)
        {
            IntPtr processHandle = GetCurrentProcess();
            ulong prevMinVal = 0;
            ulong prevMaxVal = 0;
            uint prevFlags = 0;
            if (!this.GetProcessWorkingSetSizeEx(processHandle, ref prevMinVal, ref prevMaxVal, ref prevFlags))
            {
                return $"Failed to get process working set size: Error: code={Marshal.GetLastWin32Error()}.";
            }

            ulong prevCur = GetWorkingSetSize(processHandle);

            var newMaxWorkingSetSize = (ulong)((prevCur + l.ToUInt64()) * 1.2);
            if (!this.SetProcessWorkingSetSizeEx(processHandle, prevMinVal, newMaxWorkingSetSize, prevFlags))
            {
                var errcode = Marshal.GetLastWin32Error();
                return
                    $"Failed to set process working set size to {newMaxWorkingSetSize} (min={prevMinVal}, max={prevMaxVal}, flags={prevFlags}, cur={prevCur}) bytes at 0x{m.ToInt64():X8}. Error: code={errcode}.";
            }

            ulong cur = GetWorkingSetSize(processHandle);

            ulong minVal = 0;
            ulong maxVal = 0;
            uint flags = 0;
            if (!this.GetProcessWorkingSetSizeEx(processHandle, ref minVal, ref maxVal, ref flags))
            {
                var errcode = Marshal.GetLastWin32Error();
                return $"Failed to get process working set size: Error: code={errcode}.";
            }

            ////VirtualQuery(m, out MemoryBasicInformation mbi, (uint)Marshal.SizeOf<MemoryBasicInformation>());

            ////if (VirtualAlloc(m, l.ToUInt64(), 0x00001000, 0x04).ToInt64() == 0)
            ////{
            ////    var errcode = Marshal.GetLastWin32Error();
            ////    return $"Failed to commit {l.ToUInt64()} bytes at 0x{m.ToInt64():X8}: Error: code={errcode}.";
            ////}

            if (!VirtualLock(m, l))
            {
                var errcode = Marshal.GetLastWin32Error();
                var err = errcode == 1453 ? "Insufficient quota to complete the requested service" : $"code={errcode}";
                return $"Failed to securely lock {l.ToUInt64()} (prevMin={prevMinVal}, min={minVal}, "
                       + $"prevMax={prevMaxVal}, max={maxVal}, prevFlags={prevFlags}, flags={flags}, "
                       + $"prevCur={prevCur}, cur={cur}) bytes at 0x{m.ToInt64():X8}. Error: {err}.";
            }

            return null;
        }

        /// <summary>
        /// Contains the memory statistics for a process.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Size = 72)]
        public struct ProcessMemoryCounters
        {
            // ReSharper disable FieldCanBeMadeReadOnly.Local
            // ReSharper disable MemberCanBePrivate.Local

            /// <summary>
            /// The size of the structure in bytes.
            /// </summary>
            public uint Cb;

            /// <summary>
            /// The number of page faults.
            /// </summary>
            public uint PageFaultCount;

            /// <summary>
            /// The peak working set size, in bytes.
            /// </summary>
            public ulong PeakWorkingSetSize;

            /// <summary>
            /// The current working set size, in bytes.
            /// </summary>
            public ulong WorkingSetSize;

            /// <summary>
            /// The peak paged pool usage, in bytes.
            /// </summary>
            public ulong QuotaPeakPagedPoolUsage;

            /// <summary>
            /// The current paged pool usage, in bytes.
            /// </summary>
            public ulong QuotaPagedPoolUsage;

            /// <summary>
            /// The peak non-paged pool usage, in bytes.
            /// </summary>
            public ulong QuotaPeakNonPagedPoolUsage;

            /// <summary>
            /// The current non-paged pool usage, in bytes.
            /// </summary>
            public ulong QuotaNonPagedPoolUsage;

            /// <summary>
            /// The commit charge value in bytes for this process. Commit charge is
            /// the total amount of memory that the memory manager has committed for
            /// a running process.
            /// </summary>
            public ulong PagefileUsage;

            /// <summary>
            /// The peak value in bytes of the commit charge during the lifetime of this process.
            /// </summary>
            public ulong PeakPagefileUsage;

            // ReSharper restore MemberCanBePrivate.Local
            // ReSharper restore FieldCanBeMadeReadOnly.Local
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MemoryBasicInformation
        {
            // ReSharper disable FieldCanBeMadeReadOnly.Local
            // ReSharper disable MemberCanBePrivate.Local
            public IntPtr BaseAddress;

            public IntPtr AllocationBase;

            public uint AllocationProtect;

            public IntPtr RegionSize;

            public uint State;

            public uint Protect;

            public uint Type;

            // ReSharper restore MemberCanBePrivate.Local
            // ReSharper restore FieldCanBeMadeReadOnly.Local
        }
    }
}
