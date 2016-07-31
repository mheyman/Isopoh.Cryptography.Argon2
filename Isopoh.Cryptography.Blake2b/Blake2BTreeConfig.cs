// BLAKE2 reference source code package - C# implementation

// Written in 2012 by Christian Winnerlein  <codesinchaos@gmail.com>

// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.

// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

namespace Isopoh.Cryptography.Blake2b
{
    public sealed class Blake2BTreeConfig
    {
        public int IntermediateHashSize { get; set; }
        public int MaxHeight { get; set; }
        public long LeafSize { get; set; }
        public int FanOut { get; set; }

        public Blake2BTreeConfig()
        {
            this.IntermediateHashSize = 64;
        }

        public static Blake2BTreeConfig CreateInterleaved(int parallelism)
        {
            var result = new Blake2BTreeConfig
            {
                FanOut = parallelism,
                MaxHeight = 2,
                IntermediateHashSize = 64
            };
            return result;
        }
    }
}
