// <copyright file="DecodeExtension.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2
{
    using System;
    using System.Collections.Generic;
    using Isopoh.Cryptography.SecureArray;

    /// <summary>
    /// Extension to decode Argon2 hash strings.
    /// </summary>
    public static class DecodeExtension
    {
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
        /// $argon2&lt;T>[$v=&lt;num>]$m=&lt;num>,t=&lt;num>,p=&lt;num>[,keyid=&lt;bin>][,data=&lt;bin>][$&lt;bin>[$&lt;bin>]].
        /// </para>
        /// <para>
        /// where &lt;T> is either 'd' or 'i', &lt;num> is a decimal integer (positive, fits in
        /// an 'unsigned long'), and &lt;bin> is Base64-encoded data (no '=' padding
        /// characters, no newline or whitespace).
        /// The "keyid" is a binary identifier for a key (up to 8 bytes);
        /// "data" is associated data (up to 32 bytes). When the 'keyid'
        /// (resp. the 'data') is empty, then it is ommitted from the output.
        /// </para>
        /// <para>
        /// The last two binary chunks (encoded in Base64) are, in that order,
        /// the salt and the output. Both are optional, but you cannot have an
        /// output without a salt. The binary salt length is between 8 and 48 bytes.
        /// The output length is always exactly 32 bytes.
        /// </para>
        /// </remarks>
        public static bool DecodeString(this Argon2Config config, string str, out SecureArray<byte> hash)
        {
            int pos;
            Argon2Type type;
            if (str.StartsWith("$argon2id"))
            {
                type = Argon2Type.HybridAddressing;
                pos = 9;
            }
            else if (str.StartsWith("$argon2i"))
            {
                type = Argon2Type.DataIndependentAddressing;
                pos = 8;
            }
            else if (str.StartsWith("$argon2d"))
            {
                type = Argon2Type.DataDependentAddressing;
                pos = 8;
            }
            else
            {
                hash = null;
                return false;
            }

            var version = Argon2Version.Sixteen;
            /* Reading the version number if the default is suppressed */
            {
                var check = "$v=";
                if (string.Compare(str, pos, check, 0, check.Length) == 0)
                {
                    pos += check.Length;
                    pos = DecodeDecimal(str, pos, out var decX);
                    if (pos < 0)
                    {
                        hash = null;
                        return false;
                    }

                    version = (Argon2Version)decX;
                }
            }

            pos = DecodeDecimal(out var memoryCost, "$m=", str, pos);
            if (pos < 0)
            {
                hash = null;
                return false;
            }

            pos = DecodeDecimal(out var timeCost, ",t=", str, pos);
            if (pos < 0)
            {
                hash = null;
                return false;
            }

            pos = DecodeDecimal(out var lanes, ",p=", str, pos);
            if (pos < 0)
            {
                hash = null;
                return false;
            }

            byte[] associatedData = null;
            {
                var check = ",data=";
                if (string.Compare(str, pos, check, 0, check.Length) == 0)
                {
                    pos += check.Length;
                    pos = FromBase64(out associatedData, str, pos);
                    if (pos < 0)
                    {
                        hash = null;
                        return false;
                    }
                }
            }

            var validator = new Argon2Config();
            if (pos == str.Length)
            {
                try
                {
                    validator.Type = type;
                    validator.TimeCost = (int)timeCost;
                    validator.MemoryCost = (int)memoryCost;
                    validator.Lanes = (int)lanes;
                    validator.AssociatedData = associatedData;
                    validator.Version = version;
                }
                catch (Exception)
                {
                    hash = null;
                    return false;
                }

                config.Type = type;
                config.TimeCost = (int)timeCost;
                config.MemoryCost = (int)memoryCost;
                config.Lanes = (int)lanes;
                config.AssociatedData = associatedData;
                config.Version = version;
                hash = null;
                return true;
            }

            pos = DecodeBase64(out var salt, "$", str, pos);
            if (pos < 0)
            {
                hash = null;
                return false;
            }

            if (pos == str.Length)
            {
                try
                {
                    validator.Type = type;
                    validator.TimeCost = (int)timeCost;
                    validator.MemoryCost = (int)memoryCost;
                    validator.Lanes = (int)lanes;
                    validator.Salt = salt;
                    validator.AssociatedData = associatedData;
                    validator.Version = version;
                }
                catch (Exception)
                {
                    hash = null;
                    return false;
                }

                config.Type = type;
                config.TimeCost = (int)timeCost;
                config.MemoryCost = (int)memoryCost;
                config.Lanes = (int)lanes;
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
            int hashlen = Base64Length(str, pos);
            if (hashlen < 0)
            {
                hash = null;
                return false;
            }

            SecureArray<byte> output;
            try
            {
                output = new SecureArray<byte>(hashlen, SecureArrayType.ZeroedPinnedAndNoSwap, config.SecureArrayCall);
            }
            catch (LockFailException)
            {
                output = new SecureArray<byte>(hashlen, SecureArrayType.ZeroedAndPinned, config.SecureArrayCall);
            }

            bool success = false;
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

                try
                {
                    validator.Type = type;
                    validator.TimeCost = (int)timeCost;
                    validator.MemoryCost = (int)memoryCost;
                    validator.Lanes = (int)lanes;
                    validator.Salt = salt;
                    validator.AssociatedData = associatedData;
                    validator.Version = version;
                }
                catch (Exception)
                {
                    hash = null;
                    return false;
                }

                config.Type = type;
                config.TimeCost = (int)timeCost;
                config.MemoryCost = (int)memoryCost;
                config.Lanes = (int)lanes;
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

        private static int DecodeBase64(out byte[] dst, string check, string str, int pos)
        {
            if (string.Compare(str, pos, check, 0, check.Length) != 0)
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
        private static int FromBase64(out byte[] dst, string src, int pos)
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

                var d = Base64CharToByte(src[i]);
                if (d == 0xFF)
                {
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
                if (accLen >= 8)
                {
                    accLen -= 8;
                    buf.Add((byte)((acc >> (int)accLen) & 0xFF));
                }
            }

            /*
             * If the input length is equal to 1 modulo 4 (which is
             * invalid), then there will remain 6 unprocessed bits;
             * otherwise, only 0, 2 or 4 bits are buffered. The buffered
             * bits must also all be zero.
             */
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
        private static int FromBase64(byte[] dst, string src, int pos)
        {
            int i = pos;
            int dstpos = 0;
            uint acc = 0;
            uint accLen = 0;
            while (true)
            {
                if (i == src.Length)
                {
                    break;
                }

                var d = Base64CharToByte(src[i]);
                if (d == 0xFF)
                {
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
                if (accLen >= 8)
                {
                    accLen -= 8;
                    if (dstpos == dst.Length)
                    {
                        return -1;
                    }

                    dst[dstpos] = (byte)((acc >> (int)accLen) & 0xFF);
                    ++dstpos;
                }
            }

            /*
             * If the input length is equal to 1 modulo 4 (which is
             * invalid), then there will remain 6 unprocessed bits;
             * otherwise, only 0, 2 or 4 bits are buffered. The buffered
             * bits must also all be zero.
             */
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
            int ret = 0;
            int i = pos;
            uint acc = 0;
            uint accLen = 0;
            while (true)
            {
                if (i == src.Length)
                {
                    break;
                }

                var d = Base64CharToByte(src[i]);
                if (d == 0xFF)
                {
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
                if (accLen >= 8)
                {
                    accLen -= 8;
                    ++ret;
                }
            }

            /*
             * If the input length is equal to 1 modulo 4 (which is
             * invalid), then there will remain 6 unprocessed bits;
             * otherwise, only 0, 2 or 4 bits are buffered. The buffered
             * bits must also all be zero.
             */
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
            if (string.Compare(str, pos, check, 0, check.Length) != 0)
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
            for (; ; ++i)
            {
                uint c = str[i];
                if (c < '0' || c > '9')
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
            }

            if (i == pos)
            {
                val = 0;
                return -1;
            }

            return i;
        }
    }
}
