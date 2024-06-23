// <copyright file="SecureArray.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.SecureArray;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

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
        new()
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
            { typeof(bool), sizeof(bool) },
        };

    private static readonly List<Tuple<string, Func<SecureArrayCall>>> SecureArrayCalls =
    [
        new Tuple<string, Func<SecureArrayCall>>("OSX", () => new DefaultOsxSecureArrayCall()),
        new Tuple<string, Func<SecureArrayCall>>("Linux", () => new DefaultLinuxSecureArrayCall()),
        new Tuple<string, Func<SecureArrayCall>>("Windows", () => new DefaultWindowsSecureArrayCall()),
        new Tuple<string, Func<SecureArrayCall>>("UWP", () => new DefaultUwpSecureArrayCall()),
        new Tuple<string, Func<SecureArrayCall>>("Web", () => new DefaultWebSecureArrayCall()),
        new Tuple<string, Func<SecureArrayCall>>("Not Found", () => throw new NotSupportedException(
            "No SecureArray.DefaultCall support for current operating system (whatever " +
            $"that is, maybe \"{RuntimeInformation.OSDescription}\", I think I know Windows, " +
            "UWP, Linux, OSX, and web - and maybe iOS...). You  don't have to use the default " +
            "SecureArrayCall - you can pass in a version of the calls that work for your " +
            "operating system.")),
    ];

    private static readonly object DefaultCallLock = new();

    private static SecureArrayCall? defaultCall = DefaultCall;

    private GCHandle handle;

    private bool virtualLocked;

    static SecureArray()
    {
        //// Console.WriteLine("SecureArray static constructor");
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureArray"/> class.
    /// </summary>
    /// <param name="call">
    /// The methods that get called to secure the array. A null value defaults
    /// to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
    /// </param>
    /// <remarks>
    /// You cannot create a <see cref="SecureArray"/> directly, you must
    /// derive from this class like <see cref="SecureArray{T}"/> does.
    /// </remarks>
    protected SecureArray(SecureArrayCall? call)
    {
        this.Call = call ?? DefaultCall;
    }

    /// <summary>
    /// Gets or sets a value indicating whether the maximum lockable memory
    /// will be reported in the exception message upon lock failure.
    /// </summary>
    /// <remarks>
    /// Only turn this on if you need this information because this
    /// calculation can take a lot of time (over 90% of the time for
    /// something like typical Argon2 hashing).
    /// </remarks>
    public static bool ReportMaxLockableOnLockFail { get; set; }

    /// <summary>
    /// Gets the default methods that get called to secure the array.
    /// </summary>
    public static SecureArrayCall DefaultCall
    {
        get
        {
            if (defaultCall != null)
            {
                return defaultCall;
            }

            lock (DefaultCallLock)
            {
                if (defaultCall != null)
                {
                    return defaultCall;
                }

                var buf = new byte[1];
                GCHandle tmpHandle = GCHandle.Alloc(buf, GCHandleType.Pinned);
                IntPtr bufPtr = tmpHandle.AddrOfPinnedObject();
                var cnt = new UIntPtr(1);
                try
                {
                    foreach ((string name, Func<SecureArrayCall> secureArrayCall) in SecureArrayCalls)
                    {
                        try
                        {
                            SecureArrayCall tmp = secureArrayCall();
                            tmp.ZeroMemory(bufPtr, cnt); // verify that it works.
                            Thread.MemoryBarrier();
                            defaultCall = tmp;
                            break;
                        }
                        catch (DllNotFoundException e)
                        {
                            // try next SecureArrayCall default
                            Debug.WriteLine($"{name}: DllNotFoundException: {e.Message}");
                        }
                        catch (TypeLoadException e)
                        {
                            // try next SecureArrayCall default
                            Debug.WriteLine($"{name}: TypeLoadException: {e.Message}");
                        }
                    }
                }
                finally
                {
                    tmpHandle.Free();
                }
            }

#pragma warning disable CS8603
            return defaultCall;
#pragma warning restore CS8603
        }
    }

    /// <summary>
    /// Gets the <see cref="SecureArrayType"/> of protection this <see cref="SecureArray"/> has.
    /// </summary>
    public SecureArrayType ProtectionType => this.virtualLocked
        ? SecureArrayType.ZeroedPinnedAndNoSwap
        : this.handle == default
            ? SecureArrayType.Zeroed
            : SecureArrayType.ZeroedAndPinned;

    /// <summary>
    /// Gets or sets the methods that get called to secure the array.
    /// </summary>
    public SecureArrayCall Call { get; set; }

    /// <summary>
    /// Gets the size of the buffer element. Will throw a
    /// <see cref="NotSupportedException"/> if the element type is not
    /// a built-in type.
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
        if (!TypeSizes.TryGetValue(typeof(T), out int elementSize))
        {
            throw new NotSupportedException(
                $"Type {typeof(T).Name} not a built in type. "
                + $"Valid types: {string.Join(", ", TypeSizes.Keys.Select(t => t.Name))}");
        }

        return elementSize;
    }

    /// <summary>
    /// Gets the size of the buffer element. Will throw a
    /// <see cref="NotSupportedException"/> if the element type is not
    /// a built-in type.
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
    public static int BuiltInTypeElementSize<T>(Span<T> buffer)
    {
        if (!TypeSizes.TryGetValue(typeof(T), out int elementSize))
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
    /// <param name="call">
    /// The methods to call to secure the array. Defaults to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
    /// </param>
    public static void Zero<T>(T[] buffer, SecureArrayCall? call = null)
        where T : struct
    {
        if (buffer == null)
        {
            throw new ArgumentNullException(nameof(buffer));
        }

        GCHandle bufHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            IntPtr bufPtr = bufHandle.AddrOfPinnedObject();
            var cnt = new UIntPtr((uint)buffer.Length * (uint)BuiltInTypeElementSize(buffer));
            (call?.ZeroMemory ?? DefaultCall.ZeroMemory)(bufPtr, cnt);
        }
        finally
        {
            bufHandle.Free();
        }
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
    /// <param name="call">
    /// The methods to call to secure the array. Defaults to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
    /// </param>
    public static void Zero<T>(Span<T> buffer, SecureArrayCall? call = null)
        where T : struct
    {
        if (buffer == null)
        {
            throw new ArgumentNullException(nameof(buffer));
        }

        GCHandle bufHandle = GCHandle.Alloc(buffer.GetPinnableReference(), GCHandleType.Pinned);
        try
        {
            IntPtr bufPtr = bufHandle.AddrOfPinnedObject();
            var cnt = new UIntPtr((uint)buffer.Length * (uint)BuiltInTypeElementSize(buffer));
            (call?.ZeroMemory ?? DefaultCall.ZeroMemory)(bufPtr, cnt);
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
        if (buf == null)
        {
            throw new ArgumentNullException(nameof(buf));
        }

        int sizeInBytes = BuiltInTypeElementSize(buf) * buf.Length;
        if (this.handle == default)
        {
            this.handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
        }

        try
        {
            IntPtr bufPtr = this.handle.AddrOfPinnedObject();
            var cnt = new UIntPtr((uint)sizeInBytes);
            this.Call.ZeroMemory(bufPtr, cnt);
            if (this.virtualLocked)
            {
                this.Call.UnlockMemory(bufPtr, cnt);
            }
        }
        finally
        {
            this.handle.Free();
            this.handle = default(GCHandle);
        }
    }

    /// <summary>
    /// Call this with the array to secure and the number of bytes in that
    /// array. The buffer will be zeroed and the handle freed when the
    /// instance is disposed.
    /// </summary>
    /// <typeparam name="T">
    /// The type of the array elements in <paramref name="buffer"/>.
    /// </typeparam>
    /// <param name="buffer">
    /// The array to secure.
    /// </param>
    /// <param name="type">
    /// The type of secure array to initialize.
    /// </param>
    /// <exception cref="LockFailException">
    /// Operating system did not allow the memory to be locked.
    /// </exception>
    protected void Init<T>(T[] buffer, SecureArrayType type)
    {
        if (buffer == null)
        {
            throw new ArgumentNullException(nameof(buffer));
        }

        if (type is SecureArrayType.ZeroedAndPinned or SecureArrayType.ZeroedPinnedAndNoSwap)
        {
            GCHandle tmpHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                if (type == SecureArrayType.ZeroedPinnedAndNoSwap)
                {
                    int sizeInBytes = BuiltInTypeElementSize(buffer) * buffer.Length;
                    IntPtr bufPtr = tmpHandle.AddrOfPinnedObject();
                    var cnt = new UIntPtr((uint)sizeInBytes);
                    this.Call.ZeroMemory(bufPtr, cnt);
                    string? err = this.Call.LockMemory(bufPtr, cnt);
                    if (err != null)
                    {
                        string msg;
                        if (ReportMaxLockableOnLockFail)
                        {
                            int max = this.GetMaxLockable();
                            msg = max > sizeInBytes ? $"Under current available value of {max} bytes (try again, it may work)" : $"Currently available: {max} bytes";
                        }
                        else
                        {
                            msg = "Set SecureArray.ReportMaxLockableOnLockFail=true to enable reporting";
                        }

                        throw new LockFailException($"Failed to lock {sizeInBytes} bytes into RAM. {msg}. {err}.");
                    }

                    this.virtualLocked = true;
                    this.handle = tmpHandle;
                    tmpHandle = default;
                }
            }
            finally
            {
                if (tmpHandle != default)
                {
                    tmpHandle.Free();
                }
            }
        }
    }

    /// <summary>
    /// Perform a binary search to find the current max lockable memory amount. Used
    /// for error reporting.
    /// </summary>
    /// <returns>
    /// The current number of bytes that can be locked. This is likely to change on
    /// subsequent calls.
    /// </returns>
    private int GetMaxLockable()
    {
        ulong low = 0;
        ulong high = int.MaxValue;
        while (low < high)
        {
            ulong cur = (high + low) / 2;
            if (cur == low)
            {
                break;
            }

            try
            {
                var buf = new byte[cur];
                GCHandle maxLockableHandle = GCHandle.Alloc(buf, GCHandleType.Pinned);
                try
                {
                    IntPtr bufPtr = maxLockableHandle.AddrOfPinnedObject();
                    var len = new UIntPtr(cur);
                    if (this.Call.LockMemory(bufPtr, len) == null)
                    {
                        this.Call.UnlockMemory(bufPtr, len);
                        low = cur;
                    }
                    else
                    {
                        // lock failed
#pragma warning disable S3949
                        high = cur - 1;
#pragma warning restore S3949
                    }
                }
                finally
                {
                    maxLockableHandle.Free();
                }
            }
            catch (OutOfMemoryException)
            {
                // new failed. Act like lock failed
#pragma warning disable S3949
                high = cur - 1;
#pragma warning restore S3949
            }
        }

        return (int)low;
    }
}