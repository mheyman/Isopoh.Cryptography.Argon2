// <copyright file="SecureArray.Windows.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray
{
    using System;
    using System.Runtime.InteropServices;
    using System.Threading;

    /// <content>
    /// The Windows-specific parts of <see cref="SecureArray"/>.
    /// </content>
    public partial class SecureArray
    {
        private delegate bool GetProcessWorkingSetSizeExDelegate(IntPtr processHandle, ref ulong minWorkingSetSize, ref ulong maxWorkingSetSize, ref uint flags);

        private static bool Is32BitSubsystem { get; } = new Lazy<bool>(
            () =>
                {
                    if (IntPtr.Size == 4)
                    {
                        return true;
                    }

                    IntPtr kernelModuleHandle = GetModuleHandle("kernel32");
                    if (kernelModuleHandle == IntPtr.Zero)
                    {
                        return true; // much worse problems then just saying it is 32-bit so it is okay to lie here
                    }

                    if (GetProcAddress(kernelModuleHandle, "IsWow64Process") == IntPtr.Zero)
                    {
                        return true; // kernel32.dll in 32-bit OS doesn't have IsWowProcess()
                    }

                    bool isWow64Process;
                    bool ret = IsWow64Process(GetCurrentProcess(), out isWow64Process) && isWow64Process;
                    return ret;
                },
            LazyThreadSafetyMode.ExecutionAndPublication).Value;

        /// <summary>
        /// Gets a delegate GetProcessWorkingSetSizeEx() that works on 32-bit or 64-bit operating systems
        /// </summary>
        private static GetProcessWorkingSetSizeExDelegate GetProcessWorkingSetSizeEx { get; } = new Lazy<GetProcessWorkingSetSizeExDelegate>(
            () => Is32BitSubsystem ? (GetProcessWorkingSetSizeExDelegate)GetProcessWorkingSetSizeEx64 : GetProcessWorkingSetSizeEx32Wrapper,
            LazyThreadSafetyMode.ExecutionAndPublication).Value;

        /// <summary>
        /// Gets a delegate SetProcessWorkingSetSizeEx() that works on 32-bit or 64-bit operating systems
        /// </summary>
        private static Func<IntPtr, ulong, ulong, uint, bool> SetProcessWorkingSetSizeEx { get; } = new Lazy<Func<IntPtr, ulong, ulong, uint, bool>>(
            () => Is32BitSubsystem ?
                      (Func<IntPtr, ulong, ulong, uint, bool>)SetProcessWorkingSetSizeEx64 :
                      ((processHandle, minWorkingSetSize, maxWorkingSetSize, flags) =>
                          {
                              uint min = minWorkingSetSize > uint.MaxValue ? uint.MaxValue : (uint)minWorkingSetSize;
                              uint max = maxWorkingSetSize > uint.MaxValue ? uint.MaxValue : (uint)maxWorkingSetSize;
                              return SetProcessWorkingSetSizeEx32(processHandle, min, max, flags);
                          }), LazyThreadSafetyMode.ExecutionAndPublication).Value;

        /// <summary>
        /// Gets a delegate VirtualAlloc() that works on 32-bit or 64-bit operating systems
        /// </summary>
        private static Func<IntPtr, ulong, uint, uint, IntPtr> VirtualAlloc { get; } =
            new Lazy<Func<IntPtr, ulong, uint, uint, IntPtr>>(
                () => Is32BitSubsystem
                          ? (Func<IntPtr, ulong, uint, uint, IntPtr>)VirtualAlloc64
                          : (lpAddress, size, allocationTypeFlags, protectFlags) =>
                              {
                                  if (size > uint.MaxValue)
                                  {
                                      SetLastError(8); // ERROR_NOT_ENOUGH_MEMORY
                                      return IntPtr.Zero;
                                  }

                                  return VirtualAlloc32(lpAddress, (uint)size, allocationTypeFlags, protectFlags);
                              }, LazyThreadSafetyMode.ExecutionAndPublication).Value;

        private static string WindowsLockMemory(IntPtr m, UIntPtr l)
        {
            IntPtr processHandle = GetCurrentProcess();
            ulong prevMinVal = 0;
            ulong prevMaxVal = 0;
            uint prevFlags = 0;
            if (!GetProcessWorkingSetSizeEx(processHandle, ref prevMinVal, ref prevMaxVal, ref prevFlags))
            {
                return $"Failed to get process working set size: Error: code={Marshal.GetLastWin32Error()}.";
            }

            ulong prevCur = GetWorkingSetSize(processHandle);

            var newMaxWorkingSetSize = (ulong)((prevCur + l.ToUInt64()) * 1.2);
            if (!SetProcessWorkingSetSizeEx(processHandle, prevMinVal, newMaxWorkingSetSize, prevFlags))
            {
                var errcode = Marshal.GetLastWin32Error();
                return $"Failed to set process working set size to {newMaxWorkingSetSize} (min={prevMinVal}, max={prevMaxVal}, flags={prevFlags}, cur={prevCur}) bytes at 0x{m.ToInt64():X8}. Error: code={errcode}.";
            }

            ulong cur = GetWorkingSetSize(processHandle);

            ulong minVal = 0;
            ulong maxVal = 0;
            uint flags = 0;
            if (!GetProcessWorkingSetSizeEx(processHandle, ref minVal, ref maxVal, ref flags))
            {
                var errcode = Marshal.GetLastWin32Error();
                return $"Failed to get process working set size: Error: code={errcode}.";
            }

            if (VirtualAlloc(m, l.ToUInt64(), 0x00001000, 0x04).ToInt64() == 0)
            {
                var errcode = Marshal.GetLastWin32Error();
                return $"Failed to commit {l.ToUInt64()} bytes at 0x{m.ToInt64():X8}: Error: code={errcode}.";
            }

            if (!VirtualLock(m, l))
            {
                var errcode = Marshal.GetLastWin32Error();
                var err = errcode == 1453
                                ? "Insufficient quota to complete the requested service"
                                : $"code={errcode}";
                return
                    $"Failed to securely lock {l.ToUInt64()} (prevMin={prevMinVal}, min={minVal}, "
                    + $"prevMax={prevMaxVal}, max={maxVal}, prevFlags={prevFlags}, flags={flags}, "
                    + $"prevCur={prevCur}, cur={cur}) bytes at 0x{m.ToInt64():X8}. Error: {err}.";
            }

            return null;
        }

        private static ulong GetWorkingSetSize(IntPtr processHandle)
        {
            // ReSharper disable once InlineOutVariableDeclaration
            var memoryCounters = new ProcessMemoryCounters()
            {
                Cb = (uint)Marshal.SizeOf(typeof(ProcessMemoryCounters))
            };

            return GetProcessMemoryInfo(processHandle, out memoryCounters, memoryCounters.Cb) ? memoryCounters.WorkingSetSize : 0;
        }

        [DllImport("psapi.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        private static extern bool GetProcessMemoryInfo(IntPtr hProcess, out ProcessMemoryCounters counters, uint size);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", EntryPoint = "GetProcessWorkingSetSizeEx", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        private static extern bool GetProcessWorkingSetSizeEx64(IntPtr processHandle, ref ulong minWorkingSetSize, ref ulong maxWorkingSetSize, ref uint flags);

        [DllImport("kernel32.dll", EntryPoint = "GetProcessWorkingSetSizeEx", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        private static extern bool GetProcessWorkingSetSizeEx32(IntPtr processHandle, ref uint minWorkingSetSize, ref uint maxWorkingSetSize, ref uint flags);

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

        [DllImport("kernel32.dll", EntryPoint = "SetProcessWorkingSetSizeEx", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        private static extern bool SetProcessWorkingSetSizeEx64(IntPtr processHandle, ulong minWorkingSetSize, ulong maxWorkingSetSize, uint flags);

        [DllImport("kernel32.dll", EntryPoint = "SetProcessWorkingSetSizeEx", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        private static extern bool SetProcessWorkingSetSizeEx32(IntPtr processHandle, uint minWorkingSetSize, uint maxWorkingSetSize, uint flags);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern void RtlZeroMemory(IntPtr ptr, UIntPtr cnt);

        [DllImport("kernel32.dll", EntryPoint = "VirtualAlloc", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        private static extern IntPtr VirtualAlloc64(IntPtr lpAddress, ulong size, uint allocationTypeFlags, uint protoectFlags);

        [DllImport("kernel32.dll", EntryPoint = "VirtualAlloc", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        private static extern IntPtr VirtualAlloc32(IntPtr lpAddress, uint size, uint allocationTypeFlags, uint protoectFlags);

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

        [StructLayout(LayoutKind.Sequential, Size = 72)]
        private struct ProcessMemoryCounters
        {
            // ReSharper disable FieldCanBeMadeReadOnly.Local
            // ReSharper disable MemberCanBePrivate.Local
            public uint Cb;
            public uint PageFaultCount;
            public ulong PeakWorkingSetSize;
            public ulong WorkingSetSize;
            public ulong QuotaPeakPagedPoolUsage;
            public ulong QuotaPagedPoolUsage;
            public ulong QuotaPeakNonPagedPoolUsage;
            public ulong QuotaNonPagedPoolUsage;
            public ulong PagefileUsage;
            public ulong PeakPagefileUsage;

            // ReSharper restore MemberCanBePrivate.Local
            // ReSharper restore FieldCanBeMadeReadOnly.Local
        }
    }
}