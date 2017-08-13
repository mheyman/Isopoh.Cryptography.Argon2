namespace Isopoh.Cryptography.SecureArray
{
    using System;
    using System.Runtime.InteropServices;

    public partial class SecureArray
    {
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
            var memoryCounters = new ProcessMemoryCounters()
            {
                Cb = (uint)Marshal.SizeOf(typeof(ProcessMemoryCounters))
            };

            if (GetProcessMemoryInfo(processHandle, out memoryCounters, memoryCounters.Cb))
            {
                return memoryCounters.WorkingSetSize;
            }

            return 0;
        }

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool GetProcessMemoryInfo(IntPtr hProcess, out ProcessMemoryCounters counters, uint size);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessWorkingSetSizeEx(IntPtr processHandle, ref ulong minWorkingSetSize, ref ulong maxWorkingSetSize, ref uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetProcessWorkingSetSizeEx(IntPtr processHandle, ulong minWorkingSetSize, ulong maxWorkingSetSize, uint flags);

        [DllImport("kernel32.dll")]
        private static extern void RtlZeroMemory(IntPtr ptr, UIntPtr cnt);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, ulong size, uint allocationTypeFlags, uint protoectFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualLock(IntPtr lpAddress, UIntPtr dwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualUnlock(IntPtr lpAddress, UIntPtr dwSize);

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