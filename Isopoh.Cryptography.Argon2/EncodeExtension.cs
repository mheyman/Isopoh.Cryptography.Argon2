// <copyright file="EncodeExtension.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2
{
    using System;
    using System.Text;

    /// <summary>
    /// Extension to encode an Argon2 hash string.
    /// </summary>
    public static class EncodeExtension
    {
        private static readonly int[] B64Extra = { 0, 2, 3 };
        private static readonly char[] B64Chars =
        {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
            'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
            'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
            'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
            'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
            'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', '+', '/',
        };

        /// <summary>
        /// Encodes an Argon2 instance into a string.
        /// </summary>
        /// <param name="config">
        /// To encode.
        /// </param>
        /// <param name="hash">
        /// The hash to put in the encoded string. May be null.
        /// </param>
        /// <returns>
        /// The encoded Argon2 instance.
        /// </returns>
        /// <remarks>
        /// <para>
        /// Resulting format:
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
        public static string EncodeString(this Argon2Config config, byte[] hash)
        {
            var dst = new StringBuilder();
            if (config.Type == Argon2Type.DataIndependentAddressing)
            {
                dst.Append("$argon2i$v=");
            }
            else if (config.Type == Argon2Type.DataDependentAddressing)
            {
                dst.Append("$argon2d$v=");
            }
            else if (config.Type == Argon2Type.HybridAddressing)
            {
                dst.Append("$argon2id$v=");
            }
            else
            {
                throw new ArgumentException(
                    $"Expected one of {Argon2Type.DataDependentAddressing}, "
                    + $"{Argon2Type.DataIndependentAddressing}, or {Argon2Type.HybridAddressing}, "
                    + $"got {config.Type}", nameof(config));
            }

            dst.AppendFormat("{0:D}", (int)config.Version);
            dst.Append("$m=");
            dst.AppendFormat("{0:D}", config.MemoryCost);
            dst.Append(",t=");
            dst.AppendFormat("{0:D}", config.TimeCost);
            dst.Append(",p=");
            dst.AppendFormat("{0:D}", config.Lanes);
            if (config.AssociatedData != null && config.AssociatedData.Length > 0)
            {
                dst.Append(",data=");
                dst.Append(config.AssociatedData.ToB64String());
            }

            if (config.Salt == null || config.Salt.Length == 0)
            {
                return dst.ToString();
            }

            dst.Append("$");
            dst.Append(config.Salt.ToB64String());

            if (hash == null || hash.Length == 0)
            {
                return dst.ToString();
            }

            dst.Append("$");
            dst.Append(hash.ToB64String());
            return dst.ToString();
        }

        /// <summary>
        /// Make an Argon2 B64 string which is an RFC 4648 Base64 string without the trailing '=' padding.
        /// </summary>
        /// <param name="buf">The buffer to convert to a string.</param>
        /// <returns>The Argon2 B64 string.</returns>
        public static string ToB64String(this byte[] buf)
        {
            var lengthMod3 = buf.Length % 3;
            var chunkCount = buf.Length / 3;
            var bufFullChunkLength = chunkCount * 3;
            var b64len = (chunkCount * 4) + B64Extra[lengthMod3];
            var ret = new StringBuilder(b64len);
            int i = 0;
            for (; i < bufFullChunkLength; ++i)
            {
                int c1 = buf[i];
                int c2 = buf[++i];
                int c3 = buf[++i];
                ret.Append(B64Chars[(c1 & 0xFC) >> 2]);
                ret.Append(B64Chars[((c1 & 0x03) << 4) | ((c2 & 0xF0) >> 4)]);
                ret.Append(B64Chars[((c2 & 0xF) << 2) | ((c3 & 0xC0) >> 6)]);
                ret.Append(B64Chars[c3 & 0x3F]);
            }

            switch (lengthMod3)
            {
                case 2:
                    int c1 = buf[i];
                    int c2 = buf[++i];
                    ret.Append(B64Chars[(c1 & 0xFC) >> 2]);
                    ret.Append(B64Chars[((c1 & 0x03) << 4) | ((c2 & 0xF0) >> 4)]);
                    ret.Append(B64Chars[(c2 & 0xF) << 2]);
                    break;
                case 1:
                    c1 = buf[i];
                    ret.Append(B64Chars[(c1 & 0xFC) >> 2]);
                    ret.Append(B64Chars[(c1 & 0x03) << 4]);
                    break;
            }

            return ret.ToString();
        }
    }
}
