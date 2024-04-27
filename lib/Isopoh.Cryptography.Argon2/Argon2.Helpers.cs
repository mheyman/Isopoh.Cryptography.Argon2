// <copyright file="Argon2.Helpers.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

using System;

namespace Isopoh.Cryptography.Argon2;

using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Isopoh.Cryptography.SecureArray;

/// <summary>
/// Argon2 Hashing of passwords.
/// </summary>
public sealed partial class Argon2
{
    /// <summary>
    /// Hash the given password to an Argon2 hash string.
    /// </summary>
    /// <param name="configToHash">
    /// Contains all the information used to create the hash returned.
    /// </param>
    /// <returns>
    /// The Argon2 hash of the given password.
    /// </returns>
    public static string Hash(Argon2Config configToHash)
    {
        using var argon2 = new Argon2(configToHash);
        Span<byte> hash = argon2.Hash();
        return argon2.Config.EncodeString(hash);
    }

    /// <summary>
    /// Hash the given password to an Argon2 hash string.
    /// </summary>
    /// <param name="memory">
    /// The memory, including the <see cref="Argon2Config"/> containing the password, to use to create the hash.
    /// </param>
    /// <returns>
    /// The Argon2 hash of the given password.
    /// </returns>
    public static string Hash(Argon2Memory memory)
    {
        using var argon2 = new Argon2(memory);
        Span<byte> hash = argon2.Hash();
        return argon2.Config.EncodeString(hash);
    }

    /// <summary>
    /// Hash the given password to an Argon2 hash string.
    /// </summary>
    /// <param name="password">
    /// The password to hash. Gets UTF-8 encoded before hashing.
    /// </param>
    /// <param name="secret">
    /// The secret to use in creating the hash.
    /// </param>
    /// <param name="timeCost">
    /// The time cost to use. Defaults to 3.
    /// </param>
    /// <param name="memoryCost">
    /// The target memory cost to use. Defaults to 65536 (65536 * 1024 = 64MB). <see
    /// cref="Argon2Config.MemoryCost"/> for detail on calculating the actual memory
    /// used from this value.
    /// </param>
    /// <param name="parallelism">
    /// The parallelism to use. Default to 1 (single threaded).
    /// </param>
    /// <param name="type">
    /// Data-dependent, data-independent, or hybrid. Defaults to hybrid
    /// (as recommended for password hashing).
    /// </param>
    /// <param name="hashLength">
    /// The length of the hash in bytes. Note, the string returned base-64
    /// encodes this with other parameters so the resulting string is
    /// significantly longer.
    /// </param>
    /// <param name="secureArrayCall">
    /// The methods that get called to secure arrays. A null value defaults to <see
    /// cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
    /// </param>
    /// <returns>
    /// The Argon2 hash of the given password.
    /// </returns>
    public static string Hash(
        byte[] password,
        byte[]? secret,
        int timeCost = 3,
        int memoryCost = 65536,
        int parallelism = 1,
        Argon2Type type = Argon2Type.HybridAddressing,
        int hashLength = 32,
        SecureArrayCall? secureArrayCall = null)
    {
        var salt = new byte[16];
        GetSalt(salt);

        return Hash(
            new Argon2Config
            {
                TimeCost = timeCost,
                MemoryCost = memoryCost,
                Threads = parallelism,
                Lanes = parallelism,
                Password = password,
                Secret = secret,
                Salt = salt,
                HashLength = hashLength,
                Version = Argon2Version.Nineteen,
                Type = type,
                SecureArrayCall = secureArrayCall ?? SecureArray.DefaultCall,
            });
    }


    /// <summary>
    /// Hash the given password to an Argon2 hash string.
    /// </summary>
    /// <param name="password">
    /// The password to hash. Gets UTF-8 encoded before hashing.
    /// </param>
    /// <param name="secret">
    /// The secret to use in creating the hash. UTF-8 encoded before hashing. May be null. A
    /// <c>string.Empty</c> is treated the same as null.
    /// </param>
    /// <param name="timeCost">
    /// The time cost to use. Defaults to 3.
    /// </param>
    /// <param name="memoryCost">
    /// The target memory cost to use. Defaults to 65536 (65536 * 1024 = 64MB). <see
    /// cref="Argon2Config.MemoryCost"/> for detail on calculating the actual memory
    /// used from this value.
    /// </param>
    /// <param name="parallelism">
    /// The parallelism to use. Default to 1 (single threaded).
    /// </param>
    /// <param name="type">
    /// Data-dependent, data-independent, or hybrid. Defaults to hybrid
    /// (as recommended for password hashing).
    /// </param>
    /// <param name="hashLength">
    /// The length of the hash in bytes. Note, the string returned base-64
    /// encodes this with other parameters so the resulting string is
    /// significantly longer.
    /// </param>
    /// <param name="secureArrayCall">
    /// The methods that get called to secure arrays. A null value defaults to <see
    /// cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
    /// </param>
    /// <returns>
    /// The Argon2 hash of the given password.
    /// </returns>
    public static string Hash(
        string password,
        string? secret,
        int timeCost = 3,
        int memoryCost = 65536,
        int parallelism = 1,
        Argon2Type type = Argon2Type.HybridAddressing,
        int hashLength = 32,
        SecureArrayCall? secureArrayCall = null)
    {
        if (password == null)
        {
            throw new System.ArgumentNullException(nameof(password));
        }

        SecureArray<byte>? secretBuf = string.IsNullOrEmpty(secret)
            ? null
            : SecureArray<byte>.Best(Encoding.UTF8.GetByteCount(secret), secureArrayCall);
        try
        {
            if (secretBuf != null)
            {
                Encoding.UTF8.GetBytes(secret!, 0, secret!.Length, secretBuf.Buffer, 0);
            }

            using SecureArray<byte> passwordBuf = SecureArray<byte>.Best(Encoding.UTF8.GetByteCount(password), secureArrayCall);
            Encoding.UTF8.GetBytes(password, 0, password.Length, passwordBuf.Buffer, 0);
            return Hash(
                passwordBuf.Buffer,
                secretBuf?.Buffer,
                timeCost,
                memoryCost,
                parallelism,
                type,
                hashLength,
                secureArrayCall);
        }
        finally
        {
            secretBuf?.Dispose();
        }
    }

    /// <summary>
    /// Hash the given password to an Argon2 hash string.
    /// </summary>
    /// <param name="password">
    /// The password to hash. Gets UTF-8 encoded before hashing.
    /// </param>
    /// <param name="timeCost">
    /// The time cost to use. Defaults to 3.
    /// </param>
    /// <param name="memoryCost">
    /// The target memory cost to use. Defaults to 65536 (65536 * 1024 = 64MB). <see
    /// cref="Argon2Config.MemoryCost"/> for detail on calculating the actual memory
    /// used from this value.
    /// </param>
    /// <param name="parallelism">
    /// The parallelism to use. Defaults to 1 (single threaded).
    /// </param>
    /// <param name="type">
    /// Data-dependent, data-independent, or hybrid. Defaults to hybrid
    /// (as recommended for password hashing).
    /// </param>
    /// <param name="hashLength">
    /// The length of the hash in bytes. Note, the string returned base-64
    /// encodes this with other parameters so the resulting string is
    /// significantly longer.
    /// </param>
    /// <param name="secureArrayCall">
    /// The methods that get called to secure arrays. A null value defaults to <see
    /// cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
    /// </param>
    /// <returns>
    /// The Argon2 hash of the given password.
    /// </returns>
    public static string Hash(
        string password,
        int timeCost = 3,
        int memoryCost = 65536,
        int parallelism = 1,
        Argon2Type type = Argon2Type.HybridAddressing,
        int hashLength = 32,
        SecureArrayCall? secureArrayCall = null)
    {
        return Hash(password, null, timeCost, memoryCost, parallelism, type, hashLength, secureArrayCall);
    }

    /// <summary>
    /// Verify the given Argon2 hash as being that of the given password.
    /// </summary>
    /// <param name="encoded">
    /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
    /// </param>
    /// <param name="configToVerify">
    /// The configuration that contains the values used to created <paramref name="encoded"/>.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    public static bool Verify(
        string encoded,
        Argon2Config configToVerify)
    {
        SecureArray<byte>? hash = null;
        try
        {
            if (!configToVerify.DecodeString(encoded, out hash) || hash == null)
            {
                return false;
            }

            using var hasherToVerify = new Argon2(configToVerify);
            Span<byte> hashToVerify = hasherToVerify.Hash();
            return FixedTimeEquals(hash.Buffer, hashToVerify);
        }
        finally
        {
            hash?.Dispose();
        }
    }

    /// <summary>
    /// Verify the given Argon2 hash as being that of the given password.
    /// </summary>
    /// <param name="encoded">
    /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
    /// </param>
    /// <param name="password">
    /// The password to verify.
    /// </param>
    /// <param name="secret">
    /// The secret hashed into the password.
    /// </param>
    /// <param name="secureArrayCall">
    /// The methods that get called to secure arrays. A null value defaults to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    public static bool Verify(
        string encoded,
        byte[] password,
        byte[]? secret,
        SecureArrayCall? secureArrayCall = null)
    {
        var configToVerify = new Argon2Config
        {
            Password = password,
            Secret = secret,
            SecureArrayCall = secureArrayCall ?? SecureArray.DefaultCall,
        };

        return Verify(encoded, configToVerify);
    }

    /// <summary>
    /// Verify the given Argon2 hash as being that of the given password.
    /// </summary>
    /// <param name="encoded">
    /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
    /// </param>
    /// <param name="password">
    /// The password to verify.
    /// </param>
    /// <param name="secret">
    /// The secret hashed into the password.
    /// </param>
    /// <param name="threads">
    /// The number of threads to use. Setting this to a higher number than
    /// the "p=" parameter in the <paramref name="encoded"/> string doesn't
    /// cause even more parallelism.
    /// </param>
    /// <param name="secureArrayCall">
    /// The methods that get called to secure arrays. A null value defaults to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    public static bool Verify(
        string encoded,
        byte[] password,
        byte[]? secret,
        int threads,
        SecureArrayCall? secureArrayCall = null)
    {
        var configToVerify = new Argon2Config
        {
            Password = password,
            Secret = secret,
            Threads = threads,
            SecureArrayCall = secureArrayCall ?? SecureArray.DefaultCall,
        };

        return Verify(encoded, configToVerify);
    }

    // ReSharper disable once UnusedMember.Global

    /// <summary>
    /// Verify the given Argon2 hash as being that of the given password.
    /// </summary>
    /// <param name="encoded">
    /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
    /// </param>
    /// <param name="password">
    /// The password to verify.
    /// </param>
    /// <param name="secureArrayCall">
    /// The methods that get called to secure arrays. A null value defaults to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    public static bool Verify(
        string encoded,
        byte[] password,
        SecureArrayCall? secureArrayCall = null)
    {
        return Verify(encoded, password, null, secureArrayCall);
    }

    // ReSharper disable once UnusedMember.Global

    /// <summary>
    /// Verify the given Argon2 hash as being that of the given password.
    /// </summary>
    /// <param name="encoded">
    /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
    /// </param>
    /// <param name="password">
    /// The password to verify.
    /// </param>
    /// <param name="threads">
    /// The number of threads to use. Setting this to a higher number than
    /// the "p=" parameter in the <paramref name="encoded"/> string doesn't
    /// cause even more parallelism.
    /// </param>
    /// <param name="secureArrayCall">
    /// The methods that get called to secure arrays. A null value defaults to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    public static bool Verify(
        string encoded,
        byte[] password,
        int threads,
        SecureArrayCall? secureArrayCall = null)
    {
        return Verify(encoded, password, null, threads, secureArrayCall);
    }

    /// <summary>
    /// Verify the given Argon2 hash as being that of the given password.
    /// </summary>
    /// <param name="encoded">
    /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
    /// </param>
    /// <param name="password">
    /// The password to verify. This gets UTF-8 encoded.
    /// </param>
    /// <param name="secret">
    /// The secret used in the creation of <paramref name="encoded"/>. UTF-8 encoded to create the byte-buffer actually used in the verification.
    /// May be null for no secret. <c>string.Empty</c> is treated as null.
    /// </param>
    /// <param name="secureArrayCall">
    /// The methods that get called to secure arrays. A null value defaults to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    public static bool Verify(
        string encoded,
        string password,
        string? secret,
        SecureArrayCall? secureArrayCall = null)
    {
        if (password == null)
        {
            throw new System.ArgumentNullException(nameof(password));
        }

        SecureArray<byte>? secretBuf = string.IsNullOrEmpty(secret)
            ? null
            : SecureArray<byte>.Best(Encoding.UTF8.GetByteCount(secret), secureArrayCall);

        try
        {
            if (secretBuf != null)
            {
                Encoding.UTF8.GetBytes(secret!, 0, secret!.Length, secretBuf.Buffer, 0);
            }

            using SecureArray<byte> passwordBuf = SecureArray<byte>.Best(Encoding.UTF8.GetByteCount(password), secureArrayCall);
            Encoding.UTF8.GetBytes(password, 0, password.Length, passwordBuf.Buffer, 0);
            return Verify(encoded, passwordBuf.Buffer, secretBuf?.Buffer, secureArrayCall);
        }
        finally
        {
            secretBuf?.Dispose();
        }
    }

    /// <summary>
    /// Verify the given Argon2 hash as being that of the given password.
    /// </summary>
    /// <param name="encoded">
    /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
    /// </param>
    /// <param name="password">
    /// The password to verify. This gets UTF-8 encoded.
    /// </param>
    /// <param name="secret">
    /// The secret used in the creation of <paramref name="encoded"/>. UTF-8 encoded to create the byte-buffer actually used in the verification.
    /// May be null for no secret. <c>string.Empty</c> is treated as null.
    /// </param>
    /// <param name="threads">
    /// The number of threads to use. Setting this to a higher number than
    /// the "p=" parameter in the <paramref name="encoded"/> string doesn't
    /// cause even more parallelism.
    /// </param>
    /// <param name="secureArrayCall">
    /// The methods that get called to secure arrays. A null value defaults to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    public static bool Verify(
        string encoded,
        string password,
        string? secret,
        int threads,
        SecureArrayCall? secureArrayCall = null)
    {
        if (password == null)
        {
            throw new System.ArgumentNullException(nameof(password));
        }

        SecureArray<byte>? secretBuf = string.IsNullOrEmpty(secret)
            ? null
            : SecureArray<byte>.Best(Encoding.UTF8.GetByteCount(secret), secureArrayCall);

        try
        {
            if (secretBuf != null)
            {
                Encoding.UTF8.GetBytes(secret!, 0, secret!.Length, secretBuf.Buffer, 0);
            }

            using SecureArray<byte> passwordBuf = SecureArray<byte>.Best(Encoding.UTF8.GetByteCount(password), secureArrayCall);
            Encoding.UTF8.GetBytes(password, 0, password.Length, passwordBuf.Buffer, 0);
            return Verify(encoded, passwordBuf.Buffer, secretBuf?.Buffer, threads, secureArrayCall);
        }
        finally
        {
            secretBuf?.Dispose();
        }
    }

    // ReSharper disable once UnusedMember.Global

    /// <summary>
    /// Verify the given Argon2 hash as being that of the given password.
    /// </summary>
    /// <param name="encoded">
    /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
    /// </param>
    /// <param name="password">
    /// The password to verify. This gets UTF-8 encoded.
    /// </param>
    /// <param name="secureArrayCall">
    /// The methods that get called to secure arrays. A null value defaults to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    public static bool Verify(
        string encoded,
        string password,
        SecureArrayCall? secureArrayCall = null)
    {
        return Verify(encoded, password, null, secureArrayCall);
    }

    // ReSharper disable once UnusedMember.Global

    /// <summary>
    /// Verify the given Argon2 hash as being that of the given password.
    /// </summary>
    /// <param name="encoded">
    /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
    /// </param>
    /// <param name="password">
    /// The password to verify. This gets UTF-8 encoded.
    /// </param>
    /// <param name="threads">
    /// The number of threads to use. Setting this to a higher number than
    /// the "p=" parameter in the <paramref name="encoded"/> string doesn't
    /// cause even more parallelism.
    /// </param>
    /// <param name="secureArrayCall">
    /// The methods that get called to secure arrays. A null value defaults to <see cref="SecureArray"/>.<see cref="SecureArray.DefaultCall"/>.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    public static bool Verify(
        string encoded,
        string password,
        int threads,
        SecureArrayCall? secureArrayCall = null)
    {
        return Verify(encoded, password, null, threads, secureArrayCall);
    }

    /// <summary>
    /// Compare two SecureArrays without leaking timing information.
    /// </summary>
    /// <param name="left">The first SecureArray to compare.</param>
    /// <param name="right">The second SecureArray to compare.</param>
    /// <returns>true if left and right have the same values for Length and the same contents; otherwise, false.</returns>
    /// <remarks>
    /// Uses <see
    /// href="https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.cryptographicoperations.fixedtimeequals"
    /// >System.Security.Cryptography.CryptographicOperations.FixedTimeEquals()</see>
    /// when available; otherwise implements a similar algorithm.
    /// </remarks>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
#if NETCOREAPP2_1 || NETCOREAPP2_2 || NETCOREAPP3_0 || NETCOREAPP3_1 || NETSTANDARD2_1
        return CryptographicOperations.FixedTimeEquals(left, right);
#else
        if (left.Length != right.Length)
        {
                return false;
        }

        int length = left.Length;
        var accumulator = 0;

        for (var i = 0; i < length; i++)
        {
            accumulator |= left[i] - right[i];
        }

        return accumulator == 0;
#endif
    }

    private static void GetSalt(byte[] salt)
    {
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        randomNumberGenerator.GetBytes(salt);
    }
}