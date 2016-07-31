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
        /// $argon2&lt;T>[$v=&lt;num>]$m=&lt;num>,t=&lt;num>,p=&lt;num>[,keyid=&lt;bin>][,data=&lt;bin>][$&lt;bin>[$&lt;bin>]]
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
            else
            {
                throw new ArgumentException(
                    $"Expected one of {config.Type == Argon2Type.DataIndependentAddressing} or "
                    + $"{config.Type == Argon2Type.DataDependentAddressing}, got {config.Type}", nameof(config));
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
                dst.Append(Convert.ToBase64String(config.AssociatedData));
            }

            if (config.Salt == null || config.Salt.Length == 0)
            {
                return dst.ToString();
            }

            dst.Append("$");
            dst.Append(Convert.ToBase64String(config.Salt));

            if (hash == null || hash.Length == 0)
            {
                return dst.ToString();
            }

            dst.Append("$");
            dst.Append(Convert.ToBase64String(hash));
            return dst.ToString();
        }
    }
}
