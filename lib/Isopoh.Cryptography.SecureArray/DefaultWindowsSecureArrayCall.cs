// <copyright file="DefaultWindowsSecureArrayCall.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray;

using System;
using System.Runtime.InteropServices;
using Isopoh.Cryptography.SecureArray.WindowsNative;

/// <summary>
/// A <see cref="SecureArrayCall"/> with defaults for the Windows operating system.
/// </summary>
public class DefaultWindowsSecureArrayCall : SecureArrayCall
{
    private static readonly object Is32BitSubsystemLock = new();

    private static readonly object GetProcessWorkingSetSizeLock = new();

    private static readonly object SetProcessWorkingSetSizeLock = new();

    private static readonly object VirtualAllocLock = new();

    private static bool? is32BitSubsystem;

    private static GetProcessWorkingSetSizeExDelegate? getProcessWorkingSetSize;

    private static Func<IntPtr, ulong, ulong, uint, bool>? setProcessWorkingSetSize;

    private static Func<IntPtr, ulong, uint, uint, IntPtr>? virtualAlloc;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultWindowsSecureArrayCall"/> class.
    /// </summary>
    public DefaultWindowsSecureArrayCall()
        : base(
            (m, l) => UnsafeNativeMethods.WindowsMemset(m, 0, l),
            (_, _) => "ERROR: This temporary \"lock memory\" method should never be called.",
            (m, l) => UnsafeNativeMethods.VirtualUnlock(m, l),
            "Windows")
    {
        this.LockMemory = WindowsLockMemory;
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
                            IntPtr kernelModuleHandle = UnsafeNativeMethods.GetModuleHandle("kernel32");
                            if (kernelModuleHandle == IntPtr.Zero)
                            {
                                // much worse problems than just saying it is 32-bit, so it is okay to lie here
                                is32BitSubsystem = true;
                            }
                            else
                            {
                                if (UnsafeNativeMethods.GetProcAddress(kernelModuleHandle, "IsWow64Process") == IntPtr.Zero)
                                {
                                    is32BitSubsystem = true; // kernel32.dll in 32-bit OS doesn't have IsWowProcess()
                                }
                                else
                                {
                                    is32BitSubsystem =
                                        UnsafeNativeMethods.IsWow64Process(UnsafeNativeMethods.GetCurrentProcess(), out bool isWow64Process)
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

    // ReSharper disable once UnusedMember.Local

    /// <summary>
    /// Gets a delegate VirtualAlloc() that works on 32-bit or 64-bit operating systems.
    /// </summary>
    private static Func<IntPtr, ulong, uint, uint, IntPtr> VirtualAlloc
    {
        get
        {
            if (virtualAlloc == null)
            {
                lock (VirtualAllocLock)
                {
                    virtualAlloc ??= Is32BitSubsystem
                        ? (lpAddress, size, allocationTypeFlags, protectFlags) =>
                        {
                            if (size > uint.MaxValue)
                            {
                                UnsafeNativeMethods.SetLastError(8); // ERROR_NOT_ENOUGH_MEMORY
                                return IntPtr.Zero;
                            }

                            return UnsafeNativeMethods.VirtualAlloc32(lpAddress, (uint)size, allocationTypeFlags, protectFlags);
                        }
                    : UnsafeNativeMethods.VirtualAlloc64;
                }
            }

            return virtualAlloc;
        }
    }

    /// <summary>
    /// Gets a delegate SetProcessWorkingSetSizeEx() that works on 32-bit or 64-bit operating systems.
    /// </summary>
    private static Func<IntPtr, ulong, ulong, uint, bool> SetProcessWorkingSetSizeEx
    {
        get
        {
            if (setProcessWorkingSetSize == null)
            {
                lock (SetProcessWorkingSetSizeLock)
                {
                    setProcessWorkingSetSize ??= Is32BitSubsystem
                        ? ((processHandle, minWorkingSetSize, maxWorkingSetSize, flags) =>
                        {
#pragma warning disable S3358 // Ternary operators should not be nested
                            uint min = minWorkingSetSize > uint.MaxValue ? uint.MaxValue : (uint)minWorkingSetSize;
                            uint max = maxWorkingSetSize > uint.MaxValue ? uint.MaxValue : (uint)maxWorkingSetSize;
#pragma warning restore S3358 // Ternary operators should not be nested
                            return UnsafeNativeMethods.SetProcessWorkingSetSizeEx32(
                                processHandle,
                                min,
                                max,
                                flags);
                        })
                        : UnsafeNativeMethods.SetProcessWorkingSetSizeEx64;
                }
            }

            return setProcessWorkingSetSize;
        }
    }

    /// <summary>
    /// Gets a delegate GetProcessWorkingSetSizeEx() that works on 32-bit or 64-bit operating systems.
    /// </summary>
    private static GetProcessWorkingSetSizeExDelegate GetProcessWorkingSetSizeEx
    {
        get
        {
            if (getProcessWorkingSetSize == null)
            {
                lock (GetProcessWorkingSetSizeLock)
                {
                    getProcessWorkingSetSize ??= Is32BitSubsystem
                        ? GetProcessWorkingSetSizeEx32Wrapper
                        : UnsafeNativeMethods.GetProcessWorkingSetSizeEx64;
                }
            }

            return getProcessWorkingSetSize;
        }
    }

    private static bool GetProcessWorkingSetSizeEx32Wrapper(
        IntPtr processHandle,
        ref ulong minWorkingSetSize,
        ref ulong maxWorkingSetSize,
        ref uint flags)
    {
        uint min = minWorkingSetSize > uint.MaxValue ? uint.MaxValue : (uint)minWorkingSetSize;
        uint max = maxWorkingSetSize > uint.MaxValue ? uint.MaxValue : (uint)maxWorkingSetSize;
        bool ret = UnsafeNativeMethods.GetProcessWorkingSetSizeEx32(processHandle, ref min, ref max, ref flags);
        minWorkingSetSize = min;
        maxWorkingSetSize = max;
        return ret;
    }

    private static ulong GetWorkingSetSize(IntPtr processHandle)
    {
        var memoryCounters =
            new UnsafeNativeMethods.ProcessMemoryCounters
            {
                Cb = (uint)Marshal.SizeOf<UnsafeNativeMethods.ProcessMemoryCounters>(),
            };

        return UnsafeNativeMethods.GetProcessMemoryInfo(processHandle, out memoryCounters, memoryCounters.Cb)
            ? memoryCounters.WorkingSetSize
            : 0;
    }

    private static string? WindowsLockMemory(IntPtr m, UIntPtr l)
    {
        IntPtr processHandle = UnsafeNativeMethods.GetCurrentProcess();
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
            int errorCode = Marshal.GetLastWin32Error();
            return
                $"Failed to set process working set size to {newMaxWorkingSetSize} (min={prevMinVal}, max={prevMaxVal}, flags={prevFlags}, cur={prevCur}) bytes at 0x{m.ToInt64():X8}. Error: code={errorCode}.";
        }

        ulong cur = GetWorkingSetSize(processHandle);

        ulong minVal = 0;
        ulong maxVal = 0;
        uint flags = 0;
        if (!GetProcessWorkingSetSizeEx(processHandle, ref minVal, ref maxVal, ref flags))
        {
            int errorCode = Marshal.GetLastWin32Error();
            return $"Failed to get process working set size: Error: code={errorCode}.";
        }

        ////VirtualQuery(m, out MemoryBasicInformation mbi, (uint)Marshal.SizeOf<MemoryBasicInformation>());

        ////if (VirtualAlloc(m, l.ToUInt64(), 0x00001000, 0x04).ToInt64() == 0)
        ////{
        ////    var errorCode = Marshal.GetLastWin32Error();
        ////    return $"Failed to commit {l.ToUInt64()} bytes at 0x{m.ToInt64():X8}: Error: code={errorCode}.";
        ////}

        if (!UnsafeNativeMethods.VirtualLock(m, l))
        {
            int errorCode = Marshal.GetLastWin32Error();
            string err = errorCode == 1453 ? "Insufficient quota to complete the requested service" : $"code={errorCode}";
            return $"Failed to securely lock {l.ToUInt64()} (prevMin={prevMinVal}, min={minVal}, "
                + $"prevMax={prevMaxVal}, max={maxVal}, prevFlags={prevFlags}, flags={flags}, "
                + $"prevCur={prevCur}, cur={cur}) bytes at 0x{m.ToInt64():X8}. Error: {err}.";
        }

        return null;
    }
}