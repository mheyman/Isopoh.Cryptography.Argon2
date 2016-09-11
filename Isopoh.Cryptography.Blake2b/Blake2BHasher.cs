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
    using SecureArray;

    internal class Blake2BHasher : Hasher
    {
        private readonly Blake2BCore core = new Blake2BCore();
        private readonly SecureArray<ulong> rawConfig;
        private readonly SecureArray<byte> key;

        private readonly byte[] defaultOutputBuffer;
        private readonly int outputSizeInBytes;
        private static readonly Blake2BConfig DefaultConfig = new Blake2BConfig();

        public Blake2BHasher(Blake2BConfig config)
        {
            if (config == null)
                config = DefaultConfig;
            this.rawConfig = Blake2IvBuilder.ConfigB(config, null);
            if (config.Key != null && config.Key.Length != 0)
            {
                this.key = new SecureArray<byte>(128);
                Array.Copy(config.Key, this.key.Buffer, config.Key.Length);
            }

            this.outputSizeInBytes = config.OutputSizeInBytes;
            this.defaultOutputBuffer = config.Result64ByteBuffer;
            this.Init();
        }

        public override sealed void Init()
        {
            this.core.Initialize(this.rawConfig.Buffer);
            if (this.key != null)
            {
                this.core.HashCore(this.key.Buffer, 0, this.key.Buffer.Length);
            }
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
        public override byte[] Finish()
        {
            if (this.defaultOutputBuffer != null)
            {
                return this.core.HashFinal(this.defaultOutputBuffer);
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

        public override void Update(byte[] data, int start, int count)
        {
            this.core.HashCore(data, start, count);
        }

        /// <summary>
        /// Disposes resources if <paramref name="disposing"/> is true.
        /// </summary>
        /// <param name="disposing">
        /// Set to true if disposing.
        /// </param>
        protected override void Dispose(bool disposing)
        {
            this.key?.Dispose();
            this.rawConfig?.Dispose();
        }
    }
}
