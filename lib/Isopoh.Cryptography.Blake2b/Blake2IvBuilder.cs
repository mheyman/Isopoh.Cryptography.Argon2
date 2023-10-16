// BLAKE2 reference source code package - C# implementation

// Written in 2012 by Christian Winnerlein  <codesinchaos@gmail.com>
// Modified in 2016 by Michael Heyman for sensitive information

// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.

// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
namespace Isopoh.Cryptography.Blake2b
{
    using System;

    /// <summary>
    /// Utilities to create the Blake2 initialization vector.
    /// </summary>
    internal static class Blake2IvBuilder
    {
        private static readonly Blake2BTreeConfig SequentialTreeConfig = new() { IntermediateHashSize = 0, LeafSize = 0, FanOut = 1, MaxHeight = 1 };

        /// <summary>
        /// Create a raw Blake2 configuration from the given configurations.
        /// </summary>
        /// <param name="config">The <see cref="Blake2BConfig"/>.</param>
        /// <param name="treeConfig">The <see cref="Blake2BTreeConfig"/>.</param>
        /// <param name="iv">8-element span to get populated.</param>
        /// <exception cref="ArgumentOutOfRangeException">When <paramref name="config"/>.<see cref="Blake2BConfig.OutputSizeInBytes"/> is not between 0 and 64.</exception>
        /// <exception cref="ArgumentException">When <paramref name="config"/>.<see cref="Blake2BConfig.Key"/> length is > 64.</exception>
        /// <exception cref="ArgumentException">When <paramref name="iv"/>.Length is not 8.</exception>
        public static void ConfigB(
            Blake2BConfig config,
            Blake2BTreeConfig? treeConfig,
            Span<ulong> iv)
        {
            Blake2BTreeConfig myTreeConfig = treeConfig ?? SequentialTreeConfig;
            if (iv.Length != 8)
            {
                throw new ArgumentException(
                    nameof(iv),
                    $"Expected {nameof(iv)}.Length == 8, got {iv.Length}");
            }

            // digest length
            if (config.OutputSizeInBytes is <= 0 or > 64)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(config),
                    $"Expected 0 < config.OutputSizeInBytes <= 64, got {config.OutputSizeInBytes}");
            }

            iv[0] |= (uint)config.OutputSizeInBytes;

            // Key length
            if (config.Key != null)
            {
                if (config.Key.Value.Length > 64)
                {
                    throw new ArgumentException($"Expected key length <= 64, got {config.Key.Value.Length}", nameof(config));
                }

                iv[0] |= (uint)config.Key.Value.Length << 8;
            }

            // FanOut
            iv[0] |= (uint)myTreeConfig.FanOut << 16;

            // Depth
            iv[0] |= (uint)myTreeConfig.MaxHeight << 24;

            // Leaf length
            iv[0] |= ((ulong)(uint)myTreeConfig.LeafSize) << 32;

            // Inner length
            if (!ReferenceEquals(myTreeConfig, SequentialTreeConfig) && myTreeConfig.IntermediateHashSize is <= 0 or > 64)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(treeConfig),
                    $"Expected 0 < treeConfig.IntermediateHashSize <= 64, got {myTreeConfig.IntermediateHashSize}");
            }

            iv[2] |= (uint)myTreeConfig.IntermediateHashSize << 8;

            // Salt
            if (config.Salt != null)
            {
                if (config.Salt.Value.Length != 16)
                {
                    throw new ArgumentException("config.Salt has invalid length");
                }

                iv[4] = Blake2BCore.BytesToUInt64(config.Salt.Value.Span, 0);
                iv[5] = Blake2BCore.BytesToUInt64(config.Salt.Value.Span, 8);
            }

            // Personalization
            if (config.Personalization != null)
            {
                if (config.Personalization.Value.Length != 16)
                {
                    throw new ArgumentException(
                        $"Expected config.Personalization == 16, got {config.Personalization.Value.Length}",
                        nameof(config));
                }

                iv[6] = Blake2BCore.BytesToUInt64(config.Personalization.Value.Span, 0);
                iv[7] = Blake2BCore.BytesToUInt64(config.Personalization.Value.Span, 8);
            }
        }

        /// <summary>
        /// Update the Blake2 raw configuration for the given depth and node offset.
        /// </summary>
        /// <param name="iv">The configuration to update.</param>
        /// <param name="depth">The new depth value.</param>
        /// <param name="nodeOffset">The new node offset value.</param>
        // ReSharper disable once UnusedMember.Global
        public static void ConfigBSetNode(Span<ulong> iv, byte depth, ulong nodeOffset)
        {
            iv[1] = nodeOffset;
            iv[2] = (iv[2] & ~0xFFul) | depth;
        }
    }
}
