// <copyright file="UnsafeNativeMethods.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray.WindowsNative
{
    using System;
    using System.Runtime.InteropServices;
    using System.Security;

    /// <summary>
    /// Contains "unsafe" native methods for the OSX operating system.
    /// </summary>
    [SuppressUnmanagedCodeSecurity]
    internal static class UnsafeNativeMethods
    {
        /// <summary>
        /// Retrieves information about the memory usage of the specified process.
        /// </summary>
        /// <param name="hProcess">A handle to the process. The handle must have
        /// the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION
        /// access right.</param>
        /// <param name="counters">A pointer to the PROCESS_MEMORY_COUNTERS or
        /// PROCESS_MEMORY_COUNTERS_EX structure that receives information about
        /// the memory usage of the process.</param>
        /// <param name="size">The size of the <paramref name="counters"/>
        /// structure in bytes.</param>
        /// <returns>Non zero on success; otherwise zero.</returns>
        [DllImport("psapi.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        public static extern bool GetProcessMemoryInfo(IntPtr hProcess, out ProcessMemoryCounters counters, uint size);

        /// <summary>
        /// Retrieves a pseudo handle for the current process.
        /// </summary>
        /// <returns>A pseudo handle for the current process.</returns>
        [DllImport("kernel32.dll", CallingConvention = CallingConvention.Winapi)]
        public static extern IntPtr GetCurrentProcess();

        /// <summary>
        /// Retrieves the minimum and maximum working set sizes of the specified process.
        /// </summary>
        /// <param name="processHandle">Process to query.</param>
        /// <param name="minWorkingSetSize">Receives the minimum working set size of <paramref name="processHandle"/>.</param>
        /// <param name="maxWorkingSetSize">Receives the maximum working set size of <paramref name="processHandle"/>.</param>
        /// <param name="flags">Receives the flags that control the enforcement of the working set sizes.</param>
        /// <returns>None.</returns>
        [DllImport(
            "kernel32.dll",
            EntryPoint = "GetProcessWorkingSetSizeEx",
            CallingConvention = CallingConvention.Winapi,
            SetLastError = true)]
        public static extern bool GetProcessWorkingSetSizeEx64(
            IntPtr processHandle,
            ref ulong minWorkingSetSize,
            ref ulong maxWorkingSetSize,
            ref uint flags);

        /// <summary>
        /// Retrieves the minimum and maximum working set sizes of the specified process.
        /// </summary>
        /// <param name="processHandle">Process to query.</param>
        /// <param name="minWorkingSetSize">Receives the minimum working set size of <paramref name="processHandle"/>.</param>
        /// <param name="maxWorkingSetSize">Receives the maximum working set size of <paramref name="processHandle"/>.</param>
        /// <param name="flags">Receives the flags that control the enforcement of the working set sizes.</param>
        /// <returns>None.</returns>
        [DllImport(
            "kernel32.dll",
            EntryPoint = "GetProcessWorkingSetSizeEx",
            CallingConvention = CallingConvention.Winapi,
            SetLastError = true)]

        public static extern bool GetProcessWorkingSetSizeEx32(
            IntPtr processHandle,
            ref uint minWorkingSetSize,
            ref uint maxWorkingSetSize,
            ref uint flags);

        /// <summary>
        /// Sets the minimum and maximum working set sizes of the specified process.
        /// </summary>
        /// <param name="processHandle">Process to query.</param>
        /// <param name="minWorkingSetSize">Minimum working set size of <paramref name="processHandle"/>.</param>
        /// <param name="maxWorkingSetSize">Maximum working set size of <paramref name="processHandle"/>.</param>
        /// <param name="flags">Flags that control the enforcement of the working set sizes.</param>
        /// <returns>Nonzero on success; otherwise zero.</returns>
        [DllImport(
            "kernel32.dll",
            EntryPoint = "SetProcessWorkingSetSizeEx",
            CallingConvention = CallingConvention.Winapi,
            SetLastError = true)]
        public static extern bool SetProcessWorkingSetSizeEx64(
            IntPtr processHandle,
            ulong minWorkingSetSize,
            ulong maxWorkingSetSize,
            uint flags);

        /// <summary>
        /// Sets the minimum and maximum working set sizes of the specified process.
        /// </summary>
        /// <param name="processHandle">Process to query.</param>
        /// <param name="minWorkingSetSize">Minimum working set size of <paramref name="processHandle"/>.</param>
        /// <param name="maxWorkingSetSize">Maximum working set size of <paramref name="processHandle"/>.</param>
        /// <param name="flags">Flags that control the enforcement of the working set sizes.</param>
        /// <returns>Nonzero on success; otherwise zero.</returns>
        [DllImport(
            "kernel32.dll",
            EntryPoint = "SetProcessWorkingSetSizeEx",
            CallingConvention = CallingConvention.Winapi,
            SetLastError = true)]
        public static extern bool SetProcessWorkingSetSizeEx32(
            IntPtr processHandle,
            uint minWorkingSetSize,
            uint maxWorkingSetSize,
            uint flags);

        /// <summary>
        /// Fill a block of memory with zeros.
        /// </summary>
        /// <param name="ptr">A pointer to the memory block to be filled with zeros.</param>
        /// <param name="cnt">The number of bytes to fill with zeros.</param>
        [DllImport("ntdll.dll", CallingConvention = CallingConvention.Winapi)]
        public static extern void RtlZeroMemory(IntPtr ptr, UIntPtr cnt);

        /// <summary>
        /// Reserves, commits, or changes the state of a region of pages in the
        /// virtual address space of the calling process. Memory allocated by
        /// this function is automatically initialized to zero.
        /// </summary>
        /// <param name="lpAddress">The starting address of the region to allocate.</param>
        /// <param name="size">The size of the region in bytes.</param>
        /// <param name="allocationTypeFlags">The type of memory allocation.</param>
        /// <param name="protectFlags">The memory protection of the region.</param>
        /// <returns>Address of the region on success; otherwise null.</returns>
        [DllImport(
            "kernel32.dll",
            EntryPoint = "VirtualAlloc",
            CallingConvention = CallingConvention.Winapi,
            SetLastError = true)]
        public static extern IntPtr VirtualAlloc64(
            IntPtr lpAddress,
            ulong size,
            uint allocationTypeFlags,
            uint protectFlags);

        /// <summary>
        /// Reserves, commits, or changes the state of a region of pages in the
        /// virtual address space of the calling process. Memory allocated by
        /// this function is automatically initialized to zero.
        /// </summary>
        /// <param name="lpAddress">The starting address of the region to allocate.</param>
        /// <param name="size">The size of the region in bytes.</param>
        /// <param name="allocationTypeFlags">The type of memory allocation.</param>
        /// <param name="protectFlags">The memory protection of the region.</param>
        /// <returns>Address of the region on success; otherwise null.</returns>
        [DllImport(
            "kernel32.dll",
            EntryPoint = "VirtualAlloc",
            CallingConvention = CallingConvention.Winapi,
            SetLastError = true)]
        public static extern IntPtr VirtualAlloc32(
            IntPtr lpAddress,
            uint size,
            uint allocationTypeFlags,
            uint protectFlags);

        /// <summary>
        /// Locks the specified region of the process's virtual address space
        /// into physical memory, ensuring that subsequent access to the region
        /// will not incur a page fault.
        /// </summary>
        /// <param name="lpAddress">A pointer to the base address of the region of pages to be locked.</param>
        /// <param name="dwSize">The size of the region to be locked, in bytes. The region of affected pages
        /// includes all pages that contain one or more bytes.</param>
        /// <returns>Non-zero on success; otherwise zero.</returns>
        [DllImport("kernel32.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        public static extern bool VirtualLock(IntPtr lpAddress, UIntPtr dwSize);

        /// <summary>
        /// Unlocks a specified range of pages in the virtual address space of
        /// a process, enabling the system to swap the pages out to the paging
        /// file if necessary.
        /// </summary>
        /// <param name="lpAddress">A pointer to the base address of the region of pages to be locked.</param>
        /// <param name="dwSize">The size of the region to be locked, in bytes. The region of affected pages
        /// includes all pages that contain one or more bytes.</param>
        /// <returns>Non-zero on success; otherwise zero.</returns>
        [DllImport("kernel32.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        public static extern bool VirtualUnlock(IntPtr lpAddress, UIntPtr dwSize);

        /// <summary>
        /// Sets the last error for the calling thread.
        /// </summary>
        /// <param name="dwErrorCode">The last error code for the thread.</param>
        [DllImport("kernel32.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        public static extern void SetLastError(uint dwErrorCode);

        /// <summary>
        /// Retrieves a module handle for the specified module. The
        /// module must have been loaded by the calling process.
        /// </summary>
        /// <param name="moduleName">
        /// The name of the loaded module (either a .dll or .exe file). If the
        /// file name extension is omitted, the default library extension .dll
        /// is appended. The file name string can include a trailing point
        /// character (.) to indicate that the module name has no extension.
        /// The string does not have to specify a path. When specifying a path,
        /// be sure to use backslashes (\), not forward slashes (/). The name
        /// is compared (case independently) to the names of modules currently
        /// mapped into the address space of the calling process.
        /// </param>
        /// <returns>The handle to the specified module on success; otherwise null.</returns>
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr GetModuleHandle(string moduleName);

        /// <summary>
        /// Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL).
        /// </summary>
        /// <param name="hModule">The handle to the DLL module.</param>
        /// <param name="procName">The function or variable name or the function's ordinal value.</param>
        /// <returns>The address of the exported function or variable on success; otherwise null.</returns>
        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        /// <summary>
        /// Determines whether the specified process is running under WOW64 or
        /// an Intel64 of x64 processor.
        /// </summary>
        /// <param name="hProcess">A handle to the process.</param>
        /// <param name="wow64Process">
        /// A pointer to a value that is set to TRUE if the process is running
        /// under WOW64 on an Intel64 or x64 processor. If the process is
        /// running under 32-bit Windows, the value is set to FALSE. If the
        /// process is a 32-bit application running under 64-bit Windows 10 on
        /// ARM, the value is set to FALSE. If the process is a 64-bit
        /// application running under 64-bit Windows, the value is also set to
        /// FALSE.
        /// </param>
        /// <returns>Nonzero on success; otherwise zero.</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

        // ReSharper disable once UnusedMember.Local

        /// <summary>
        /// Retrieves information about a range of pages in the virtual address space of the calling process.
        /// </summary>
        /// <param name="lpAddress">The base address of the region to be queried.</param>
        /// <param name="lpBuffer">
        /// A pointer to a <see cref="MemoryBasicInformation"/> structure in
        /// which information about the specified page range is returned.
        /// </param>
        /// <param name="dwLength">The size of the buffer pointed to by <paramref name="lpBuffer"/>.</param>
        /// <returns>Actual number of bytes returned in <paramref name="lpBuffer"/> on success; otherwise zero.</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQuery(IntPtr lpAddress, out MemoryBasicInformation lpBuffer, uint dwLength);

        /// <summary>
        /// Contains the memory statistics for a process.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Size = 72)]
        public struct ProcessMemoryCounters
        {
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
        }

        /// <summary>
        /// Contains information about a range of pages in the virtual address
        /// space of a process. The VirtualQuery and VirtualQueryEx functions
        /// use this structure.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MemoryBasicInformation
        {
            /// <summary>
            /// A pointer to the base address of the region of pages.
            /// </summary>
            public IntPtr BaseAddress;

            /// <summary>
            /// A pointer to the base address of a range of pages allocated by
            /// the VirtualAlloc function. The page pointed to by the <see
            /// cref="BaseAddress"/> member is contained within this
            /// allocation range.
            /// </summary>
            public IntPtr AllocationBase;

            /// <summary>
            /// The memory protection option when the region was initially
            /// allocated. This member can be one of the memory protection
            /// constants or 0 if the caller does not have access.
            /// </summary>
            public uint AllocationProtect;

            /// <summary>
            /// The size of the region beginning at the base address in which
            /// all pages have identical attributes, in bytes.
            /// </summary>
            public IntPtr RegionSize;

            /// <summary>
            /// The state of the pages in the region.
            /// </summary>
            public uint State;

            /// <summary>
            /// The access protection of the pages in the region. This member
            /// is one of the values listed for the <see cref="AllocationProtect"/>
            /// member.
            /// </summary>
            public uint Protect;

            /// <summary>
            /// The type of pages in the region.
            /// </summary>
            public uint Type;
        }
    }
}
