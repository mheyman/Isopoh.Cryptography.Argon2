// <copyright file="DecodeExtension.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>
namespace Isopoh.Cryptography.Argon2;

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Isopoh.Cryptography.SecureArray;

/// <summary>
/// Extension to decode Argon2 hash strings.
/// </summary>
public static class DecodeExtension
{
    /// <summary>
    /// Regular expression to match an Argon2 string. Note: this accepts the
    /// '=' at the end of the B64 encoded values. These values are not supposed
    /// to be there according to spec but some implementations include them.
    ///
    /// No validation of length of keyid (0-8 bytes or 0-11 characters), data
    /// (0-32 bytes or 0-43 characters), salt (0-48 bytes or 11-64 characters -
    /// note this is shorter than allowed by the Argon2 algorithm but is
    /// limited by the phc-sf-spec string specification), hash (12-64 bytes or
    /// 16-86 characters - note Argon2 can actually output any length).
    /// </summary>
    private const string Argon2Match =
        @"^
            \$argon2(?<type>i|d|id)
            (?:\$v=(?<version>16|19))?
            \$m=(?<memory>\d+)
            ,t=(?<time>\d+)
            ,p=(?<parallel>\d+)
            (?:,keyid=(?<keyid>(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw](?:==)?|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=?)))?
            (?:,data=(?<data>(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw](?:==)?|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=?)))?
            (?:\$(?<salt>(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw](?:==)?|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=?)?)
                 (?:\$(?<digest>(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw](==)?|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=?)?))?)?
        $";

    private const string IndependentHashTag = "i";
    private const string DependentHashTag = "d";
    private const string Version19 = "19";

    private static readonly Regex Argon2Regex = new (Argon2Match, RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnorePatternWhitespace);

    /// <summary>
    /// Finds the buffer lengths required given an Argon2 hash string.
    /// </summary>
    /// <param name="str">The Argon2 hash string.</param>
    /// <returns>A tuple of required buffer lengths for: key id, associated data, salt, and hash.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="str"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="str"/> cannot be parsed.</exception>
    public static (
        int KeyIdLength,
        int AssociatedDataLength,
        int SaltLength,
        int HashLength) Argon2RequiredBufferLengths(this string str)
    {
        if (str == null)
        {
            throw new ArgumentNullException(nameof(str));
        }

        var match = Argon2Regex.Match(str);
        if (!match.Success)
        {
            throw new ArgumentException("Invalid Argon2 hash string. Should be of format $argon2(i|d|id)[$v=(16|19)]$m=<num>,t=<num>,p=<num>[,keyid=<b64>][,data=<b64>][$<b64>[$<b64>]] - the last two optional values are salt and hash.");
        }

        return (match.Groups["keyid"].Success ? Base64Length(match.Groups["keyid"].Value.ToCharArray()) : 0,
            match.Groups["data"].Success ? Base64Length(match.Groups["data"].Value.ToCharArray()) : 0,
            match.Groups["salt"].Success ? Base64Length(match.Groups["salt"].Value.ToCharArray()) : 0,
            match.Groups["digest"].Success ? Base64Length(match.Groups["hash"].Value.ToCharArray()) : 0);
    }

    /// <summary>
    /// Decodes an Argon2 hash string into an Argon2 class instance.
    /// </summary>
    /// <param name="memory">
    /// The <see cref="Argon2Memory"/>> to populate with the data found in <paramref name="hash"/>.
    /// </param>
    /// <param name="hash">
    /// The string to decode.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    /// <remarks>
    /// <para>
    /// Expected format:
    /// </para>
    /// <para>
    /// $argon2&lt;T>[$v=&lt;(16|19)>]$m=&lt;num>,t=&lt;num>,p=&lt;num>[,keyid=&lt;bin>][,data=&lt;bin>][$&lt;bin>[$&lt;bin>]].
    /// </para>
    /// <para>
    /// where &lt;T> is either 'd', 'i', or 'id'. &lt;num> is a decimal integer
    /// (positive, fits in an 'unsigned long'), and &lt;bin> is Base64-encoded
    /// data (no '=' padding characters, no newline or whitespace). The 'keyid'
    /// is a binary identifier for a key (recommended up to 8 bytes); 'data' is
    /// associated data (recommended up to 32 bytes). When the 'keyid' is
    /// empty, then it is omitted from the output. Same for 'data'.
    /// </para>
    /// <para>
    /// The last two binary chunks (encoded in Base64) are, in that order, the
    /// salt and the output. Both are optional, but you cannot have an output
    /// without a salt. The binary salt length is recommended to be between 8
    /// and 48 bytes. The output length recommended to always be exactly 32
    /// bytes.
    /// </para>
    /// <para>
    /// Lengths for keyid, data, salt, and output are recommended as per the
    /// pfc-sf-spec, in actuality, Argon2 allows any lengths for those values
    /// although verifiers that verify against the pfc-sf-spec will fail
    /// out-of-specification lengths.
    /// </para>
    /// </remarks>
    public static void DecodeString(this Argon2Memory memory, string hash)
    {
        if (hash == null)
        {
            throw new ArgumentNullException(nameof(hash));
        }

        var match = Argon2Regex.Match(hash);
        if (!match.Success)
        {
            throw new ArgumentException($"Invalid Argon2 hash string. Should be of format $argon2(i|d|id)[$v=<num>]$m=<num>,t=<num>,p=<num>[,keyid=<b64>][,data=<b64>][$<b64>[$<b64>]] - the last two optional values are salt and hash.");
        }

        var typeGroup = match.Groups["type"]!;
        var optionalVersionGroup = match.Groups["version"];
        var (keyIdLength, associatedDataLength, saltLength, hashLength) = hash.Argon2RequiredBufferLengths();
        var keyIdBytes = new byte[keyIdLength];
        if (match.Groups["keyid"].Success)
        {
            FromBase64(keyIdBytes, match.Groups["keyid"].Value, 0);
        }

        var associatedDataBytes = new byte[associatedDataLength];
        if (match.Groups["data"].Success)
        {
            FromBase64(associatedDataBytes, match.Groups["data"].Value, 0);
        }

        var saltBytes = new byte[saltLength];
        if (match.Groups["salt"].Success)
        {
            FromBase64(saltBytes, match.Groups["salt"].Value, 0);
        }

        var hashBytes = new byte[hashLength];
        if (match.Groups["digest"].Success)
        {
            FromBase64(hashBytes, match.Groups["digest"].Value, 0);
        }

        var parallelism = int.Parse(match.Groups["parallel"].Value);

        var config = new Argon2Config
        {
            Version = optionalVersionGroup == null || optionalVersionGroup.Value == Version19
                ? Argon2Version.Nineteen
                : Argon2Version.Sixteen,
            Type = typeGroup.Value == IndependentHashTag ? Argon2Type.DataIndependentAddressing :
                typeGroup.Value == DependentHashTag ? Argon2Type.DataIndependentAddressing :
                Argon2Type.HybridAddressing,
            HashLength = match.Groups["digest"].Success ? Base64Length(match.Groups["hash"].Value.ToCharArray()) : 0,
            Salt = saltBytes,
            AssociatedData = associatedDataBytes,
            KeyIdentifier = keyIdBytes,
            TimeCost = int.Parse(match.Groups["time"].Value),
            MemoryCost = int.Parse(match.Groups["memory"].Value),
            Lanes = parallelism,
            Threads = parallelism
        };

        memory.Reset(config);
        hashBytes.AsSpan().CopyTo(memory.Hash);
    }

    /// <summary>
    /// Decodes an Argon2 hash string into an Argon2 class instance.
    /// </summary>
    /// <param name="config">
    /// The configuration to populate with the data found in <paramref name="str"/>.
    /// </param>
    /// <param name="str">
    /// The string to decode.
    /// </param>
    /// <param name="hash">
    /// Loaded with the hash found in <paramref name="str"/>; set to null if
    /// <paramref name="str"/> does not contain a hash.
    /// </param>
    /// <returns>
    /// True on success; false otherwise. <paramref name="hash"/> set to
    /// null on failure.
    /// </returns>
    /// <remarks>
    /// <para>
    /// Expected format:
    /// </para>
    /// <para>
    /// $argon2&lt;T>[$v=&lt;(16|19)>]$m=&lt;num>,t=&lt;num>,p=&lt;num>[,keyid=&lt;bin>][,data=&lt;bin>][$&lt;bin>[$&lt;bin>]].
    /// </para>
    /// <para>
    /// where &lt;T> is either 'd', 'i', or 'id'. &lt;num> is a decimal integer
    /// (positive, fits in an 'unsigned long'), and &lt;bin> is Base64-encoded
    /// data (no '=' padding characters, no newline or whitespace). The 'keyid'
    /// is a binary identifier for a key (recommended up to 8 bytes); 'data' is
    /// associated data (recommended up to 32 bytes). When the 'keyid' is
    /// empty, then it is omitted from the output. Same for 'data'.
    /// </para>
    /// <para>
    /// The last two binary chunks (encoded in Base64) are, in that order, the
    /// salt and the output. Both are optional, but you cannot have an output
    /// without a salt. The binary salt length is recommended to be between 8
    /// and 48 bytes. The output length recommended to always be exactly 32
    /// bytes.
    /// </para>
    /// <para>
    /// Lengths for keyid, data, salt, and output are recommended as per the
    /// pfc-sf-spec, in actuality, Argon2 allows any lengths for those values
    /// although verifiers that verify against the pfc-sf-spec will fail
    /// out-of-specification lengths.
    /// </para>
    /// </remarks>
    public static bool DecodeString(
        this Argon2Config config,
        string str,
        out SecureArray<byte>? hash)
    {
        if (config == null)
        {
            throw new ArgumentNullException(nameof(config));
        }

        if (str == null)
        {
            throw new ArgumentNullException(nameof(str));
        }

        int pos;
        Argon2Type type;
        if (str.StartsWith("$argon2id", StringComparison.Ordinal))
        {
            type = Argon2Type.HybridAddressing;
            pos = 9;
        }
        else if (str.StartsWith("$argon2i", StringComparison.Ordinal))
        {
            type = Argon2Type.DataIndependentAddressing;
            pos = 8;
        }
        else if (str.StartsWith("$argon2d", StringComparison.Ordinal))
        {
            type = Argon2Type.DataDependentAddressing;
            pos = 8;
        }
        else
        {
            hash = null;
            return false;
        }

        /* Reading the version number if the default is suppressed */
        if (!TryGetVersion(str, ref pos, out Argon2Version version))
        {
            hash = null;
            return false;
        }

        pos = DecodeDecimal(out uint memoryCost, "$m=", str, pos);
        if (pos < 0)
        {
            hash = null;
            return false;
        }

        pos = DecodeDecimal(out uint timeCost, ",t=", str, pos);
        if (pos < 0)
        {
            hash = null;
            return false;
        }

        pos = DecodeDecimal(out uint lanes, ",p=", str, pos);
        if (pos < 0)
        {
            hash = null;
            return false;
        }

        if (!TryGetAssociatedData(
            str,
            ref pos,
            out byte[]? associatedData))
        {
            hash = null;
            return false;
        }

        if (pos == str.Length)
        {
            config.Type = type;
            config.TimeCost = (int)timeCost;
            config.MemoryCost = (int)memoryCost;
            config.Lanes = (int)lanes;
            config.Threads = (int)lanes;
            config.AssociatedData = associatedData;
            config.Version = version;
            hash = null;
            return true;
        }

        pos = DecodeBase64(out byte[]? salt, "$", str, pos);
        if (pos < 0)
        {
            hash = null;
            return false;
        }

        if (pos == str.Length)
        {
            config.Type = type;
            config.TimeCost = (int)timeCost;
            config.MemoryCost = (int)memoryCost;
            config.Lanes = (int)lanes;
            config.Threads = (int)lanes;
            config.Salt = salt;
            config.AssociatedData = associatedData;
            config.Version = version;
            hash = null;
            return true;
        }

        if (str[pos] != '$')
        {
            hash = null;
            return false;
        }

        ++pos;
        int hashLength = Base64Length(str, pos);
        if (hashLength < 0)
        {
            hash = null;
            return false;
        }

        SecureArray<byte> output = SecureArray<byte>.Best(hashLength, config.SecureArrayCall);

        var success = false;
        try
        {
            pos = FromBase64(output.Buffer, str, pos);
            if (pos < 0)
            {
                hash = null;
                return false;
            }

            if (pos != str.Length)
            {
                hash = null;
                return false;
            }

            config.Type = type;
            config.HashLength = hashLength;
            config.TimeCost = (int)timeCost;
            config.MemoryCost = (int)memoryCost;
            config.Lanes = (int)lanes;
            config.Threads = (int)lanes;
            config.Salt = salt;
            config.AssociatedData = associatedData;
            config.Version = version;
            hash = output;
            success = true;
            return true;
        }
        finally
        {
            if (!success)
            {
                output.Dispose();
            }
        }
    }

    private static bool TryGetAssociatedData(
        string str,
        ref int pos,
        out byte[]? associatedData)
    {
        const string check = ",data=";
        if (string.Compare(str, pos, check, 0, check.Length, StringComparison.Ordinal) == 0)
        {
            pos += check.Length;
            pos = FromBase64(out associatedData, str, pos);
            if (pos < 0)
            {
                return false;
            }
        }

        associatedData = null;
        return true;
    }

    private static bool TryGetVersion(string str, ref int i, out Argon2Version argon2Version)
    {
        const string check = "$v=";
        argon2Version = Argon2Version.Sixteen;
        switch (string.Compare(str, i, check, 0, check.Length, StringComparison.Ordinal))
        {
            case 0:
            {
                i += check.Length;
                i = DecodeDecimal(str, i, out uint decX);
                if (i < 0)
                {
                    return false;
                }

                argon2Version = (Argon2Version)decX;
                break;
            }
        }

        return true;
    }

    private static int DecodeBase64(
        out byte[]? dst,
        string check,
        string str,
        int pos)
    {
        if (string.Compare(str, pos, check, 0, check.Length, StringComparison.Ordinal) != 0)
        {
            dst = null;
            return -1;
        }

        pos += check.Length;
        return FromBase64(out dst, str, pos);
    }

    /// <summary>
    /// Decode Base64 chars into bytes.
    /// </summary>
    /// <param name="dst">results stored here.</param>
    /// <param name="src">to decode.</param>
    /// <param name="pos">where to start decoding from.</param>
    /// <returns>
    /// Next position in src to look at.
    /// </returns>
    /// <remarks>
    /// Decoding stops when a non-Base64 character is encountered. If an
    /// error occurred then -1 is returned; otherwise, the returned index
    /// points to the first non-Base64 character in the source stream.
    /// </remarks>
    private static int FromBase64(
        out byte[]? dst,
        string src,
        int pos)
    {
        int i = pos;
        var buf = new List<byte>();
        uint acc = 0;
        uint accLen = 0;
        while (true)
        {
            if (i == src.Length)
            {
                break;
            }

            uint d = Base64CharToByte(src[i]);
            if (d == 0xFF)
            {
                // ReSharper disable once GrammarMistakeInComment
                // scan past trailing '=' (could calculate expected number of '='s)
                while (i < src.Length && src[i] == '=')
                {
                    ++i;
                }

                break;
            }

            ++i;
            acc = (acc << 6) + d;
            accLen += 6;

            // ReSharper disable once InvertIf
            if (accLen >= 8)
            {
                accLen -= 8;
                buf.Add((byte)((acc >> (int)accLen) & 0xFF));
            }
        }

        // If the input length is equal to 1 modulo 4 (which is
        // invalid), then there will remain 6 unprocessed bits;
        // otherwise, only 0, 2 or 4 bits are buffered. The buffered
        // bits must also all be zero.
        if (accLen > 4 || (acc & ((1U << (int)accLen) - 1)) != 0)
        {
            dst = null;
            return -1;
        }

        dst = buf.ToArray();
        return i;
    }

    /// <summary>
    /// Decode Base64 chars into bytes.
    /// </summary>
    /// <param name="dst">results stored here.</param>
    /// <param name="src">to decode.</param>
    /// <param name="pos">where to start decoding from.</param>
    /// <returns>
    /// Next position in src to look at.
    /// </returns>
    /// <remarks>
    /// Decoding stops when a non-Base64 character is encountered. If an
    /// error occurred then -1 is returned; otherwise, the returned index
    /// points to the first non-Base64 character in the source stream.
    /// </remarks>
    private static int FromBase64(Span<byte> dst, string src, int pos)
    {
        int i = pos;
        var destPos = 0;
        uint acc = 0;
        uint accLen = 0;
        while (true)
        {
            if (i == src.Length)
            {
                break;
            }

            uint d = Base64CharToByte(src[i]);
            if (d == 0xFF)
            {
                // ReSharper disable once GrammarMistakeInComment
                // scan past trailing '=' (could calculate expected number of '='s)
                while (i < src.Length && src[i] == '=')
                {
                    ++i;
                }

                break;
            }

            ++i;
            acc = (acc << 6) + d;
            accLen += 6;

            // ReSharper disable once InvertIf
            if (accLen >= 8)
            {
                accLen -= 8;
                if (destPos == dst.Length)
                {
                    return -1;
                }

                dst[destPos] = (byte)((acc >> (int)accLen) & 0xFF);
                ++destPos;
            }
        }

        // If the input length is equal to 1 modulo 4 (which is
        // invalid), then there will remain 6 unprocessed bits;
        // otherwise, only 0, 2 or 4 bits are buffered. The buffered
        // bits must also all be zero.
        if (accLen > 4 || (acc & ((1U << (int)accLen) - 1)) != 0)
        {
            return -1;
        }

        return i;
    }

    /// <summary>
    /// Decode Base64 chars into bytes.
    /// </summary>
    /// <param name="src">to decode.</param>
    /// <returns>
    /// The length of the buffer needed to hold the decoded value.
    /// </returns>
    /// <remarks>
    /// Decoding stops when a non-Base64 character is encountered. If an
    /// error occurred then -1 is returned; otherwise, the returned index
    /// points to the first non-Base64 character in the source stream.
    /// </remarks>
    private static int Base64Length(ReadOnlySpan<char> src)
    {
        var ret = 0;
        int i = 0;
        uint acc = 0;
        uint accLen = 0;
        while (true)
        {
            if (i == src.Length)
            {
                break;
            }

            uint d = Base64CharToByte(src[i]);
            if (d == 0xFF)
            {
                // ReSharper disable once GrammarMistakeInComment
                // scan past trailing '=' (could calculate expected number of '='s)
                while (i < src.Length && src[i] == '=')
                {
                    ++i;
                }

                break;
            }

            ++i;
            acc = (acc << 6) + d;
            accLen += 6;

            // ReSharper disable once InvertIf
            if (accLen >= 8)
            {
                accLen -= 8;
                ++ret;
            }
        }

        // If the input length is equal to 1 modulo 4 (which is
        // invalid), then there will remain 6 unprocessed bits;
        // otherwise, only 0, 2 or 4 bits are buffered. The buffered
        // bits must also all be zero.
        if (accLen > 4 || (acc & ((1U << (int)accLen) - 1)) != 0)
        {
            return -1;
        }

        return ret;
    }

    /// <summary>
    /// Decode Base64 chars into bytes.
    /// </summary>
    /// <param name="src">to decode.</param>
    /// <param name="pos">where to start decoding from.</param>
    /// <returns>
    /// The length of the buffer needed to hold the decoded value.
    /// </returns>
    /// <remarks>
    /// Decoding stops when a non-Base64 character is encountered. If an
    /// error occurred then -1 is returned; otherwise, the returned index
    /// points to the first non-Base64 character in the source stream.
    /// </remarks>
    private static int Base64Length(string src, int pos)
    {
        var ret = 0;
        int i = pos;
        uint acc = 0;
        uint accLen = 0;
        while (true)
        {
            if (i == src.Length)
            {
                break;
            }

            uint d = Base64CharToByte(src[i]);
            if (d == 0xFF)
            {
                // ReSharper disable once GrammarMistakeInComment
                // scan past trailing '=' (could calculate expected number of '='s)
                while (i < src.Length && src[i] == '=')
                {
                    ++i;
                }

                break;
            }

            ++i;
            acc = (acc << 6) + d;
            accLen += 6;

            // ReSharper disable once InvertIf
            if (accLen >= 8)
            {
                accLen -= 8;
                ++ret;
            }
        }

        // If the input length is equal to 1 modulo 4 (which is
        // invalid), then there will remain 6 unprocessed bits;
        // otherwise, only 0, 2 or 4 bits are buffered. The buffered
        // bits must also all be zero.
        if (accLen > 4 || (acc & ((1U << (int)accLen) - 1)) != 0)
        {
            return -1;
        }

        return ret;
    }

    /// <summary>
    /// Convert character c to the corresponding 6-bit value. If
    /// character c is not a Base64 character, then 0xFF (255) is returned.
    /// </summary>
    /// <param name="c">to convert.</param>
    /// <returns>converted value.</returns>
    private static uint Base64CharToByte(int c)
    {
        // constant time (although I don't think that is important here)
        uint x = ((((((uint)c - 'A') >> 8) & 0xFF) ^ 0xFF) & (((('Z' - (uint)c) >> 8) & 0xFF) ^ 0xFF)
                & (uint)(c - 'A'))
            | ((((((uint)c - 'a') >> 8) & 0xFF) ^ 0xFF) & (((('z' - (uint)c) >> 8) & 0xFF) ^ 0xFF)
                & (uint)(c - ('a' - 26)))
            | ((((((uint)c - '0') >> 8) & 0xFF) ^ 0xFF) & (((('9' - (uint)c) >> 8) & 0xFF) ^ 0xFF)
                & (uint)(c - ('0' - 52))) | (((((0U - ((uint)c ^ '+')) >> 8) & 0xFF) ^ 0xFF) & 62U)
            | (((((0U - ((uint)c ^ '/')) >> 8) & 0xFF) ^ 0xFF) & 63U);
        return x
            | (((((0U - (x ^ 0)) >> 8) & 0xFF) ^ 0xFF)
                & (((((0U - ((uint)c ^ 'A')) >> 8) & 0xFF) ^ 0xFF) ^ 0xFF));
    }

    /// <summary>
    /// Decode decimal integer from <paramref name="str"/> with the given prefix <paramref name="check"/>.
    /// </summary>
    /// <param name="dst">the decoded value.</param>
    /// <param name="check">the expected prefix.</param>
    /// <param name="str">where to decode from.</param>
    /// <param name="pos">where to start decoding.</param>
    /// <returns>the next position to look at; -1 on failure.</returns>
    private static int DecodeDecimal(out uint dst, string check, string str, int pos)
    {
        if (string.Compare(str, pos, check, 0, check.Length, StringComparison.Ordinal) != 0)
        {
            dst = 0;
            return -1;
        }

        pos += check.Length;
        return DecodeDecimal(str, pos, out dst);
    }

    /// <summary>
    /// Decode decimal integer from <paramref name="str"/>.
    /// </summary>
    /// <param name="str">where to decode from.</param>
    /// <param name="pos">where to start decoding.</param>
    /// <param name="val">the decoded value.</param>
    /// <returns>the next position to look at; -1 on failure.</returns>
    private static int DecodeDecimal(string str, int pos, out uint val)
    {
        int i = pos;

        val = 0;
        while (true)
        {
            uint c = str[i];
            if (c is < '0' or > '9')
            {
                break;
            }

            c -= '0';
            if (val > (int.MaxValue / 10))
            {
                val = 0;
                return -1;
            }

            val *= 10;
            if (c > (int.MaxValue - val))
            {
                val = 0;
                return -1;
            }

            val += c;
            ++i;
        }

        // ReSharper disable once InvertIf
        if (i == pos)
        {
            val = 0;
            return -1;
        }

        return i;
    }
}