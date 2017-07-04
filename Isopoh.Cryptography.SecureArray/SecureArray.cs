// <copyright file="SecureArray.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime.InteropServices;

    /// <summary>
    /// Base class of all <see cref="SecureArray{T}"/> classes.
    /// </summary>
    public class SecureArray
    {
        /// <summary>
        /// Cannot find a way to do a compile-time verification that the
        /// array element type is one of these so this dictionary gets
        /// used to do it at runtime.
        /// </summary>
        private static readonly Dictionary<Type, int> TypeSizes =
            new Dictionary<Type, int>
                {
                    { typeof(sbyte), sizeof(sbyte) },
                    { typeof(byte), sizeof(byte) },
                    { typeof(short), sizeof(short) },
                    { typeof(ushort), sizeof(ushort) },
                    { typeof(int), sizeof(int) },
                    { typeof(uint), sizeof(uint) },
                    { typeof(long), sizeof(long) },
                    { typeof(ulong), sizeof(ulong) },
                    { typeof(char), sizeof(char) },
                    { typeof(float), sizeof(float) },
                    { typeof(double), sizeof(double) },
                    { typeof(decimal), sizeof(decimal) },
                    { typeof(bool), sizeof(bool) }
                };

        /// <summary>
        /// Call to zero memory in a way that does not get optimized away.
        /// </summary>
        /// <remarks>
        /// On Linux and OSX, simply calls memset() and hopes the P/Invoke
        /// mechanism does not have special handling for memset calls (and
        /// thus does not even think about optimizing the call away).
        /// </remarks>
        private static readonly Action<IntPtr, UIntPtr> ZeroMemory;

        /// <summary>
        /// Lock the given memory so it doesn't get swapped out to disk.
        /// </summary>
        /// <exception cref="UnauthorizedAccessException">
        /// Operating system did not allow the memory to be locked.
        /// </exception>
        private static readonly Action<IntPtr, UIntPtr> LockMemory;

        /// <summary>
        /// Unlock memory previously locked by a call to <see cref="LockMemory"/>.
        /// </summary>
        private static readonly Action<IntPtr, UIntPtr> UnlockMemory;

        private GCHandle handle;

        private bool virtualLocked;

        static SecureArray()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                ZeroMemory = (m, l) => LinuxMemset(m, 0, l);
                LockMemory = (m, l) =>
                    {
                        if (LinuxMlock(m, l) != 0)
                        {
                            throw new UnauthorizedAccessException($"Failed to securely lock memory. Error code: {Marshal.GetLastWin32Error()}");
                        }
                    };
                UnlockMemory = (m, l) => LinuxMunlock(m, l);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                ZeroMemory = (m, l) => OsxMemset(m, 0, l);
                LockMemory = (m, l) =>
                    {
                        if (OsxMlock(m, l) != 0)
                        {
                            throw new UnauthorizedAccessException($"Failed to securely lock memory. Error code: {Marshal.GetLastWin32Error()}");
                        }
                    };
                UnlockMemory = (m, l) => OsxMunlock(m, l);
            }
            else
            {
                ZeroMemory = RtlZeroMemory;
                LockMemory = (m, l) =>
                    {
                        IntPtr processHandle = GetCurrentProcess();
                        ulong prevMinVal = 0;
                        ulong prevMaxVal = 0;
                        uint prevFlags = 0;
                        if (!GetProcessWorkingSetSizeEx(processHandle, ref prevMinVal, ref prevMaxVal, ref prevFlags))
                        {
                            var errcode = Marshal.GetLastWin32Error();
                            throw new UnauthorizedAccessException($"Failed to get process working set size: Error: code={errcode}.");
                        }

                        ulong prevCur = GetWorkingSetSize(processHandle);

                        var newMaxWorkingSetSize = (ulong)((prevCur + l.ToUInt64()) * 1.2);
                        if (!SetProcessWorkingSetSizeEx(processHandle, prevMinVal, newMaxWorkingSetSize, prevFlags))
                        {
                            var errcode = Marshal.GetLastWin32Error();
                            throw new UnauthorizedAccessException($"Failed to set process working set size to {newMaxWorkingSetSize} (min={prevMinVal}, max={prevMaxVal}, flags={prevFlags}, cur={prevCur}) bytes at 0x{m.ToInt64():X8}. Error: code={errcode}.");
                        }

                        ulong cur = GetWorkingSetSize(processHandle);

                        ulong minVal = 0;
                        ulong maxVal = 0;
                        uint flags = 0;
                        if (!GetProcessWorkingSetSizeEx(processHandle, ref minVal, ref maxVal, ref flags))
                        {
                            var errcode = Marshal.GetLastWin32Error();
                            throw new UnauthorizedAccessException($"Failed to get process working set size: Error: code={errcode}.");
                        }

                        if (VirtualAlloc(m, l.ToUInt64(), 0x00001000, 0x04).ToInt64() == 0)
                        {
                            var errcode = Marshal.GetLastWin32Error();
                            throw new UnauthorizedAccessException($"Failed to commit {l.ToUInt64()} bytes at 0x{m.ToInt64():X8}: Error: code={errcode}.");
                        }

                        if (!VirtualLock(m, l))
                        {
                            var errcode = Marshal.GetLastWin32Error();
                            var err = errcode == 1453
                                          ? "Insufficient quota to complete the requested service"
                                          : $"code={errcode}";
                            throw new UnauthorizedAccessException(
                                $"Failed to securely lock {l.ToUInt64()} (prevMin={prevMinVal}, min={minVal}, "
                                + $"prevMax={prevMaxVal}, max={maxVal}, prevFlags={prevFlags}, flags={flags}, "
                                + $"prevCur={prevCur}, cur={cur}) bytes at 0x{m.ToInt64():X8}. Error: {err}.");
                        }
                    };
                UnlockMemory = (m, l) => VirtualUnlock(m, l);
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecureArray"/> class.
        /// </summary>
        /// <remarks>
        /// You cannot create a <see cref="SecureArray"/> directly, you must
        /// derive from this class like <see cref="SecureArray{T}"/> does.
        /// </remarks>
        protected SecureArray()
        {
        }

        /// <summary>
        /// Gets the size of the buffer element. Will throw a
        /// <see cref="NotSupportedException"/> if the element type is not
        /// a built in type.
        /// </summary>
        /// <typeparam name="T">
        /// The array element type to return the size of.
        /// </typeparam>
        /// <param name="buffer">
        /// The array.
        /// </param>
        /// <returns>
        /// The lengths in bytes of the size of the element in <paramref name="buffer"/>.
        /// </returns>
        public static int BuiltInTypeElementSize<T>(T[] buffer)
        {
            int elementSize;
            if (!TypeSizes.TryGetValue(typeof(T), out elementSize))
            {
                throw new NotSupportedException(
                    $"Type {typeof(T).Name} not a built in type. "
                    + $"Valid types: {string.Join(", ", TypeSizes.Keys.Select(t => t.Name))}");
            }

            return elementSize;
        }

        /// <summary>
        /// Zero the given buffer in a way that will not be optimized away.
        /// </summary>
        /// <typeparam name="T">
        /// The type of the elements in the buffer.
        /// </typeparam>
        /// <param name="buffer">
        /// The buffer to zero.
        /// </param>
        public static void Zero<T>(T[] buffer)
            where T : struct
        {
            var bufHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                IntPtr bufPtr = bufHandle.AddrOfPinnedObject();
                UIntPtr cnt = new UIntPtr((uint)buffer.Length * (uint)BuiltInTypeElementSize(buffer));
                ZeroMemory(bufPtr, cnt);
            }
            finally
            {
                bufHandle.Free();
            }
        }

        /// <summary>
        /// Zero <paramref name="buf"/> and release resources.
        /// </summary>
        /// <typeparam name="T">
        /// The type of the array elements in <paramref name="buf"/>.
        /// </typeparam>
        /// <param name="buf">
        /// The buffer to zero and whose resources to release. Should be
        /// the same as passed into <see cref="Init{T}"/>.
        /// </param>
        protected void Cleanup<T>(T[] buf)
        {
            var sizeInBytes = BuiltInTypeElementSize(buf) * buf.Length;
            if (this.handle == default(GCHandle))
            {
                this.handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
            }

            try
            {
                IntPtr bufPtr = this.handle.AddrOfPinnedObject();
                UIntPtr cnt = new UIntPtr((uint)sizeInBytes);
                ZeroMemory(bufPtr, cnt);
                if (this.virtualLocked)
                {
                    UnlockMemory(bufPtr, cnt);
                }
            }
            finally
            {
                this.handle.Free();
            }
        }

        /// <summary>
        /// Call this with the array to secure and the number of bytes in that
        /// array. The buffer will be zeroed and the handle freed when the
        /// instance is disposed.
        /// </summary>
        /// <typeparam name="T">
        /// The type of the array elements in <paramref name="buf"/>.
        /// </typeparam>
        /// <param name="buf">
        /// The array to secure.
        /// </param>
        /// <param name="type">
        /// The type of secure array to initialize.
        /// </param>
        /// <exception cref="UnauthorizedAccessException">
        /// Operating system did not allow the memory to be locked.
        /// </exception>
        protected void Init<T>(T[] buf, SecureArrayType type)
        {
            var sizeInBytes = BuiltInTypeElementSize(buf) * buf.Length;
            if (type == SecureArrayType.ZeroedAndPinned || type == SecureArrayType.ZeroedPinnedAndNoSwap)
            {
                this.handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
                if (type == SecureArrayType.ZeroedPinnedAndNoSwap)
                {
                    IntPtr bufPtr = this.handle.AddrOfPinnedObject();
                    UIntPtr cnt = new UIntPtr((uint)sizeInBytes);
                    ZeroMemory(bufPtr, cnt);
                    LockMemory(bufPtr, cnt);
                    this.virtualLocked = true;
                }
            }
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

        [DllImport("libc", SetLastError = true, EntryPoint = "mlock")]
        private static extern int LinuxMlock(IntPtr addr, UIntPtr len);

        [DllImport("libc", SetLastError = true, EntryPoint = "munlock")]
        private static extern int LinuxMunlock(IntPtr addr, UIntPtr len);

        [DllImport("libc", EntryPoint = "memset")]
        private static extern IntPtr LinuxMemset(IntPtr addr, int c, UIntPtr n);

        [DllImport("libSystem", SetLastError = true, EntryPoint = "mlock")]
        private static extern int OsxMlock(IntPtr addr, UIntPtr len);

        [DllImport("libSystem", SetLastError = true, EntryPoint = "munlock")]
        private static extern int OsxMunlock(IntPtr addr, UIntPtr len);

        [DllImport("libSystem", EntryPoint = "memset")]
        private static extern IntPtr OsxMemset(IntPtr addr, int c, UIntPtr n);

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