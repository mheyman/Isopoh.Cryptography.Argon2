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

    using Isopoh.Cryptography.SecureArray;

    /// <summary>
    /// Utilities to create the Blake2 initialization vector.
    /// </summary>
    internal static class Blake2IvBuilder
    {
        private static readonly Blake2BTreeConfig SequentialTreeConfig = new Blake2BTreeConfig { IntermediateHashSize = 0, LeafSize = 0, FanOut = 1, MaxHeight = 1 };

        /// <summary>
        /// Create a raw Blake2 configuration from the given configurations.
        /// </summary>
        /// <param name="config">The <see cref="Blake2BConfig"/>.</param>
        /// <param name="treeConfig">The <see cref="Blake2BTreeConfig"/>.</param>
        /// <param name="secureArrayCall">Used to create <see cref="SecureArray"/> instances.</param>
        /// <returns>The raw Blake2 configuration.</returns>
        /// <exception cref="ArgumentOutOfRangeException">When <paramref name="config"/>.<see cref="Blake2BConfig.OutputSizeInBytes"/> is not between 0 and 64.</exception>
        /// <exception cref="ArgumentException">When <paramref name="config"/>.<see cref="Blake2BConfig.Key"/> length is > 64.</exception>
        public static SecureArray<ulong> ConfigB(Blake2BConfig config, Blake2BTreeConfig? treeConfig, SecureArrayCall secureArrayCall)
        {
            bool isSequential = treeConfig == null;
            Blake2BTreeConfig myTreeConfig = treeConfig ?? SequentialTreeConfig;

            SecureArray<ulong> rawConfig;
            try
            {
                 rawConfig = new SecureArray<ulong>(8, SecureArrayType.ZeroedPinnedAndNoSwap, secureArrayCall);
            }
            catch (LockFailException)
            {
                rawConfig = new SecureArray<ulong>(8, SecureArrayType.ZeroedAndPinned, secureArrayCall);
            }

            // digest length
            if (config.OutputSizeInBytes is <= 0 or > 64)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(config),
                    $"Expected 0 < config.OutputSizeInBytes <= 64, got {config.OutputSizeInBytes}");
            }

            rawConfig[0] |= (uint)config.OutputSizeInBytes;

            // Key length
            if (config.Key != null)
            {
                if (config.Key.Length > 64)
                {
                    throw new ArgumentException($"Expected key length <= 64, got {config.Key.Length}", nameof(config));
                }

                rawConfig[0] |= (uint)config.Key.Length << 8;
            }

            // FanOut
            rawConfig[0] |= (uint)myTreeConfig.FanOut << 16;

            // Depth
            rawConfig[0] |= (uint)myTreeConfig.MaxHeight << 24;

            // Leaf length
            rawConfig[0] |= ((ulong)(uint)myTreeConfig.LeafSize) << 32;

            // Inner length
            if (!isSequential && myTreeConfig.IntermediateHashSize is <= 0 or > 64)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(treeConfig),
                    $"Expected 0 < treeConfig.IntermediateHashSize <= 64, got {myTreeConfig.IntermediateHashSize}");
            }

            rawConfig[2] |= (uint)myTreeConfig.IntermediateHashSize << 8;

            // Salt
            if (config.Salt != null)
            {
                if (config.Salt.Length != 16)
                {
                    throw new ArgumentException("config.Salt has invalid length");
                }

                rawConfig[4] = Blake2BCore.BytesToUInt64(config.Salt, 0);
                rawConfig[5] = Blake2BCore.BytesToUInt64(config.Salt, 8);
            }

            // Personalization
            if (config.Personalization != null)
            {
                if (config.Personalization.Length != 16)
                {
                    throw new ArgumentException(
                        $"Expected config.Personalization == 16, got {config.Personalization.Length}",
                        nameof(config));
                }

                rawConfig[6] = Blake2BCore.BytesToUInt64(config.Personalization, 0);
                rawConfig[7] = Blake2BCore.BytesToUInt64(config.Personalization, 8);
            }

            return rawConfig;
        }

        /// <summary>
        /// Update the Blake2 raw configuration for the given depth and node offset.
        /// </summary>
        /// <param name="rawConfig">The configuration to update.</param>
        /// <param name="depth">The new depth value.</param>
        /// <param name="nodeOffset">The new node offset value.</param>
        public static void ConfigBSetNode(ulong[] rawConfig, byte depth, ulong nodeOffset)
        {
            rawConfig[1] = nodeOffset;
            rawConfig[2] = (rawConfig[2] & ~0xFFul) | depth;
        }
    }
}
