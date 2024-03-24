﻿// BLAKE2 reference source code package - C# implementation

// Written in 2012 by Christian Winnerlein  <codesinchaos@gmail.com>
// Modified in 2016 by Michael Heyman for sensitive information

// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.

// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
namespace Isopoh.Cryptography.Blake2b;

using System;
using System.Runtime.InteropServices;
using Isopoh.Cryptography.SecureArray;

/// <summary>
/// Init/Update/Final for Blake2 hash.
/// </summary>
public class Blake2BHasher : Hasher
{
    /// <summary>
    /// Gets the minimum total size in bytes of the <see cref="Blake2BHasher"/> buffer.
    /// This length plus the length of the optional <see cref="Blake2BConfig"/>.<see cref="Blake2BConfig.Key"/>
    /// field is the total required size.
    /// </summary>
    public const int NoKeyBufferMinimumTotalSize = Blake2BCore.BufferTotalSize + (sizeof(ulong) * 8);

    /// <summary>
    /// Gets the minimum total size in bytes of the <see cref="Blake2BHasher"/> buffer.
    /// This length plus the length of the optional <see cref="Blake2BConfig"/>.<see cref="Blake2BConfig.Key"/>
    /// field is the total required size.
    /// </summary>
    public const int BufferMinimumTotalSize = NoKeyBufferMinimumTotalSize + 128;

    private static readonly Blake2BConfig DefaultConfig = new();

    private readonly int keyLength;

    private readonly SecureArray<byte>? backingBuffer;

    private readonly Memory<byte> backingMemory;

    private readonly Blake2BCore core;

    private readonly Memory<byte>? defaultOutputBuffer;

    private readonly int outputSizeInBytes;

    private bool disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="Blake2BHasher"/> class.
    /// </summary>
    /// <param name="config">The configuration to use; may be null to use the default Blake2 configuration.</param>
    /// <param name="blake2BHasherBuffer">Must be at least <see cref="BufferMinimumTotalSize"/> + (<paramref name="config"/>?.Key.Length ?? 0).</param>
    /// <exception cref="ArgumentException"><see paramref="blake2BHasherBuffer"/>.Length too small.</exception>
    public Blake2BHasher(Blake2BConfig? config, Memory<byte> blake2BHasherBuffer)
        : this(GetArg(config, null, blake2BHasherBuffer))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Blake2BHasher"/> class.
    /// </summary>
    /// <param name="config">The configuration to use; may be null to use the default Blake2 configuration.</param>
    /// <param name="secureArrayCall">Used to create <see cref="SecureArray"/> instances.</param>
    public Blake2BHasher(Blake2BConfig? config, SecureArrayCall secureArrayCall)
        : this(GetArg(config, secureArrayCall, null))
    {
    }

    private Blake2BHasher((Blake2BConfig Config, Memory<byte>? Memory, SecureArray<byte>? SecureArray) arg)
    {
        switch (arg)
        {
            case { SecureArray: null, Memory: null }:
                throw new ArgumentException(
                    $"Only one of {nameof(arg)} {nameof(arg.SecureArray)} and {nameof(arg.Memory)} can be null");
            case { SecureArray: not null, Memory: not null }:
                throw new ArgumentException(
                    $"Only one of {nameof(arg)} {nameof(arg.SecureArray)} and {nameof(arg.Memory)} can be non-null");
        }

        Span<byte> configKey = arg.Config.Key == null ? default : arg.Config.Key.Value.Span;
        this.keyLength = configKey.Length == 0 ? 0 : 128;
        this.backingBuffer = arg.SecureArray;
        this.backingMemory = arg.Memory ?? this.backingBuffer!.Buffer;
        this.core = new Blake2BCore(this.CoreBuffer);
        Blake2IvBuilder.Set(arg.Config, null, this.MyIv);

        if (this.keyLength > 0)
        {
            if (configKey.Length < this.keyLength)
            {
                configKey.CopyTo(this.MyKey.Slice(0, configKey.Length));
                this.MyKey.Slice(configKey.Length).Clear();
            }
            else
            {
                configKey.Slice(0, this.keyLength).CopyTo(this.MyKey);
            }
        }

        this.outputSizeInBytes = arg.Config.OutputSizeInBytes;
        this.defaultOutputBuffer = arg.Config.Result64ByteBuffer;
        this.Init();
    }

    /// <summary>
    /// Gets the initialization vector used for the Blake2B hash.
    /// </summary>
    public ReadOnlySpan<ulong> Iv => !this.disposed ? MemoryMarshal.Cast<byte, ulong>(this.Backing.Slice(Blake2BCore.BufferTotalSize, 8 * sizeof(ulong))) : throw new ObjectDisposedException("Attempt to get Iv of disposed Blake2BHasher.");

    /// <summary>
    /// Gets the key used for the Blake2B hash.
    /// </summary>
    public ReadOnlySpan<byte> Key => !this.disposed ? this.Backing.Slice(Blake2BCore.BufferTotalSize + (8 * sizeof(ulong)), this.keyLength) : throw new ObjectDisposedException("Attempt to get Key of disposed Blake2BHasher.");

    private Span<byte> Backing => !this.disposed ? this.backingMemory.Span : throw new ObjectDisposedException("Attempt to get Backing memory of disposed Blake2BHasher.");

    private Memory<byte> CoreBuffer => !this.disposed ? this.backingMemory.Slice(0, Blake2BCore.BufferTotalSize) : throw new ObjectDisposedException("Attempt to get CoreBuffer of disposed Blake2BHasher.");

    private Span<ulong> MyIv => !this.disposed ? MemoryMarshal.Cast<byte, ulong>(this.Backing.Slice(Blake2BCore.BufferTotalSize, 8 * sizeof(ulong))) : throw new ObjectDisposedException("Attempt to get Iv of disposed Blake2BHasher.");

    private Span<byte> MyKey => !this.disposed ? this.Backing.Slice(Blake2BCore.BufferTotalSize + (8 * sizeof(ulong)), this.keyLength) : throw new ObjectDisposedException("Attempt to get Key of disposed Blake2BHasher.");

    /// <summary>
    /// Initialize the hasher. The hasher is initialized upon construction but this can be used
    /// to reinitialize in order to reuse the hasher.
    /// </summary>
    /// <exception cref="ObjectDisposedException">When called after being disposed.</exception>
    public sealed override void Init()
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException("Called Blake2BHasher.Init() on disposed object");
        }

        this.core.Initialize(this.Iv);
        if (this.Key.Length > 0)
        {
            this.core.HashCore(this.Key);
        }
    }

    /// <summary>
    /// Update the hasher with more bytes of data.
    /// </summary>
    /// <param name="data">Buffer holding the data to update with.</param>
    /// <exception cref="ObjectDisposedException">When called after being disposed.</exception>
    public override void Update(ReadOnlySpan<byte> data)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException("Called Blake2BHasher.Update() on disposed object");
        }

        this.core.HashCore(data);
    }

    /// <summary>
    /// Either returns <see cref="Blake2BConfig"/>.<see cref="Blake2BConfig.Result64ByteBuffer"/>
    /// or a new buffer of <see cref="Blake2BConfig"/>.<see cref="Blake2BConfig.OutputSizeInBytes"/>
    /// if no <see cref="Blake2BConfig.Result64ByteBuffer"/> was given.
    /// </summary>
    /// <returns>
    /// Either the final Blake2 hash or the <see cref="Blake2BConfig.Result64ByteBuffer"/>. If
    /// <see cref="Blake2BConfig.Result64ByteBuffer"/> is non-null and <see cref="Blake2BConfig"/>.<see
    /// cref="Blake2BConfig.OutputSizeInBytes"/> is less than 64, then the actual Blake2 hash
    /// is the first <see cref="Blake2BConfig.OutputSizeInBytes"/> of the <see
    /// cref="Blake2BConfig.Result64ByteBuffer"/> buffer.
    /// </returns>
    public override Memory<byte> Finish()
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException("Called Blake2BHasher.Finish() on disposed object");
        }

        if (this.defaultOutputBuffer != null)
        {
            this.core.HashFinal(this.defaultOutputBuffer.Value.Span);
            return this.defaultOutputBuffer.Value.Slice(0, this.outputSizeInBytes);
        }

        byte[] fullResult = this.core.HashFinal();
        if (this.outputSizeInBytes != fullResult.Length)
        {
            var result = new byte[this.outputSizeInBytes];
            Array.Copy(fullResult, result, result.Length);
            return result;
        }

        return fullResult;
    }

    /// <summary>
    /// Finishes the hash and stores the results into <paramref name="hash"/>. If a
    /// <see cref="Blake2BConfig.Result64ByteBuffer"/>.<see cref="Blake2BConfig.Result64ByteBuffer"/>
    /// was given, that will be loaded with the full hash. If the given <paramref name="hash"/>
    /// is longer than <see cref="Blake2B"/>.<see cref="Blake2B.OutputLength"/>, it will be padded
    /// with zeros.
    /// </summary>
    /// <param name="hash">Loaded with the hash value.</param>
    /// <returns>
    /// The passed in <paramref name="hash"/>.
    /// </returns>
    public override Span<byte> Finish(Span<byte> hash)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException("Called Blake2BHasher.Finish() on disposed object");
        }

        Span<byte> res = this.defaultOutputBuffer != null
            ? this.defaultOutputBuffer.Value.Span
            : hash.Length >= Blake2B.OutputLength
                ? hash.Slice(0, Blake2B.OutputLength)
                : new Span<byte>(new byte[Blake2B.OutputLength]);
        this.core.HashFinal(res);
        if (hash.Length < res.Length)
        {
            res.Slice(0, hash.Length).CopyTo(hash);
        }
        else
        {
            if (!res.Overlaps(hash))
            {
                res.CopyTo(hash);
            }

            hash.Slice(res.Length).Clear();
        }

        return hash;
    }

    /// <summary>
    /// Disposes resources if <paramref name="disposing"/> is true.
    /// </summary>
    /// <param name="disposing">
    /// Set to true if disposing.
    /// </param>
    protected override void Dispose(bool disposing)
    {
        if (this.disposed)
        {
            return;
        }

        this.backingBuffer?.Dispose();
        this.core.Dispose();
        this.disposed = true;
        base.Dispose(disposing);
    }

    private static (Blake2BConfig Config, Memory<byte>? Memory, SecureArray<byte>? SecureArray) GetArg(Blake2BConfig? config, SecureArrayCall? secureArrayCall, Memory<byte>? memory)
    {
        config ??= DefaultConfig;
        Span<byte> configKey = config.Key == null ? default : config.Key.Value.Span;
        int keyLength128 = configKey.Length == 0 ? 0 : 128;
        int bufferTotalSize = NoKeyBufferMinimumTotalSize + keyLength128;
        if (secureArrayCall != null)
        {
            return (config, null, SecureArray<byte>.Create(bufferTotalSize, secureArrayCall, config.LockMemoryPolicy));
        }

        if (memory!.Value.Length < bufferTotalSize)
        {
            throw new ArgumentOutOfRangeException(
                $"{nameof(memory)} must be at least {bufferTotalSize} in length.");
        }

        return (config, memory, null);
    }
}