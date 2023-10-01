// <copyright file="Argon2TestVector.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

using Xunit.Abstractions;

namespace TestLib;
using Isopoh.Cryptography.Argon2;
using Isopoh.Cryptography.SecureArray;

/// <summary>
/// Holds Argon2 test vector information.
/// </summary>
public sealed class Argon2TestVector
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Argon2TestVector"/> class.
    /// </summary>
    /// <param name="name">
    /// name of the vector.
    /// </param>
    /// <param name="type">
    /// Data-driven or independent.
    /// </param>
    /// <param name="version">
    /// The Argon2 version.
    /// </param>
    /// <param name="iterations">
    /// The number of iterations.
    /// </param>
    /// <param name="memoryKBytes">
    /// The memory to use.
    /// </param>
    /// <param name="parallelism">
    /// The number of threads to use.
    /// </param>
    /// <param name="tagLength">
    /// How many bytes to output.
    /// </param>
    /// <param name="password">
    /// The password to hash.
    /// </param>
    /// <param name="salt">
    /// The salt to use in the hash. Minimum of 8 bytes. 16 recommended.
    /// </param>
    /// <param name="secret">
    /// The secret to use in the hash.
    /// </param>
    /// <param name="associatedData">
    /// The associated data to use in the hash (like a salt but can be shorter).
    /// </param>
    /// <param name="tag">
    /// The expected hash created from the above parameters.
    /// </param>
    public Argon2TestVector(
        string name,
        Argon2Type type,
        Argon2Version version,
        int iterations,
        int memoryKBytes,
        int parallelism,
        int tagLength,
        string password,
        string salt,
        string secret,
        string associatedData,
        string tag)
    {
        this.Name = name;
        this.Type = type;
        this.Version = version;
        this.Iterations = iterations;
        this.MemoryKBytes = memoryKBytes;
        this.Parallelism = parallelism;
        this.TagLength = tagLength;
        this.Password = ToBytes(password);
        this.Salt = ToBytes(salt);
        this.Secret = ToBytes(secret);
        this.AssociatedData = ToBytes(associatedData);
        this.Tag = ToBytes(tag);
        this.Config = new Argon2Config
        {
            Type = type,
            Version = version,
            TimeCost = iterations,
            MemoryCost = memoryKBytes,
            Lanes = parallelism,
            Threads = parallelism,
            Password = this.Password,
            Salt = this.Salt,
            Secret = this.Secret,
            AssociatedData = this.AssociatedData,
            HashLength = this.TagLength,
        };
        this.TagText = this.Config.EncodeString(this.Tag);
    }

    /// <summary>
    /// Gets the name of the test vector.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Gets the Argon2 type - data dependent or independent.
    /// </summary>
    public Argon2Type Type { get; }

    /// <summary>
    /// Gets the version of the Argon2 algorithm to use.
    /// </summary>
    public Argon2Version Version { get; }

    /// <summary>
    /// Gets the number of iterations to use in the Argon2 hash.
    /// </summary>
    public int Iterations { get; }

    /// <summary>
    /// Gets the amount of memory to use in the Argon2 hash.
    /// </summary>
    public int MemoryKBytes { get; }

    /// <summary>
    /// Gets the number of threads to use in the Argon2 hash.
    /// </summary>
    public int Parallelism { get; }

    /// <summary>
    /// Gets the size in bytes of the output hash value to create.
    /// </summary>
    public int TagLength { get; }

    /// <summary>
    /// Gets the password to hash.
    /// </summary>
    public byte[] Password { get; }

    /// <summary>
    /// Gets the salt to hash.
    /// </summary>
    public byte[] Salt { get; }

    /// <summary>
    /// Gets the secret to hash.
    /// </summary>
    public byte[] Secret { get; }

    /// <summary>
    /// Gets the associated data to hash.
    /// </summary>
    public byte[] AssociatedData { get; }

    /// <summary>
    /// Gets the expected result of the hash.
    /// </summary>
    public byte[] Tag { get; }

    /// <summary>
    /// Gets the config based on the fields.
    /// </summary>
    public Argon2Config Config { get; }

    /// <summary>
    /// Gets the encoded tag.
    /// </summary>
    public string TagText { get; }

    /// <summary>
    /// Validates the configuration parameters, when hashed, produce the expected hash value given by the test vector.
    /// </summary>
    /// <param name="output">Used to write output.</param>
    /// <returns>True on success; false otherwise.</returns>
    public bool Validate(ITestOutputHelper output)
    {
        var nl = Environment.NewLine;
        try
        {
            var argon2 = new Argon2(this.Config);
            SecureArray<byte> hash = argon2.Hash();
            if (!hash.Buffer.Where((b, i) => b != this.Tag[i]).Any())
            {
                var text = Argon2.Hash(this.Config);
                if (string.CompareOrdinal(text, this.TagText) == 0)
                {
                    output.WriteLine(
                        $"Test {this.Name} passed:{nl}"
                        + $"             Version 0x{(int)this.Version:X} ({(int)this.Version}){nl}"
                        + $"                Type {this.Type}{nl}"
                        + $"          Iterations {this.Iterations}{nl}"
                        + $"       Memory KBytes {this.MemoryKBytes}{nl}"
                        + $"         Parallelism {this.Parallelism}{nl}"
                        + $"            Password {BitConverter.ToString(this.Password)}{nl}"
                        + $"                Salt {BitConverter.ToString(this.Salt)}{nl}"
                        + $"              Secret {BitConverter.ToString(this.Secret)}{nl}"
                        + $"      AssociatedData {BitConverter.ToString(this.AssociatedData)}{nl}"
                        + $"  Gave expected hash {BitConverter.ToString(hash.Buffer)}{nl}"
                        + $"             encoded {text}");
                }
                else
                {
                    output.WriteLine(
                        $"  Test {this.Name}: Got{nl}" +
                        $"    {text}{nl}" +
                        $"  expected{nl}" +
                        $"    {this.TagText}");
                    return false;
                }
            }
            else
            {
                output.WriteLine(
                    $"  Test {this.Name}: Got{nl}" +
                    $"    {BitConverter.ToString(hash.Buffer)}{nl}" +
                    $"  expected{nl}" +
                    $"    {BitConverter.ToString(this.Tag)}");
                return false;
            }
        }

        // ReSharper disable once CatchAllClause
        catch (Exception e)
        {
            output.WriteLine($"Test {this.Name}: {e.Message} ({e.GetType()})");
        }

        return true;
    }

    /// <summary>
    /// Convert a hex string to bytes.
    /// </summary>
    /// <param name="s">
    /// The hex string.
    /// </param>
    /// <returns>
    /// The byte array.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// Invalid hex string.
    /// </exception>
    private static byte[] ToBytes(string s)
    {
        var ret = new List<byte>();
        for (int i = 1; i < s.Length; i += 2)
        {
            var ch = s[i - 1];
            var cl = s[i];
            while (char.IsWhiteSpace(ch))
            {
                ch = cl;
                ++i;
                if (i == s.Length)
                {
                    break;
                }

                cl = s[i];
            }

            byte val;
#pragma warning disable SA1131 // Use readable conditions

            // ReSharper disable StyleCop.SA1131
            if (ch is >= '0' and <= '9')
            {
                val = (byte)((uint)(ch - '0') << 4);
            }
            else if (ch is >= 'a' and <= 'f')
            {
                val = (byte)((uint)(ch - 'a' + 10) << 4);
            }
            else if (ch is >= 'A' and <= 'F')
            {
                val = (byte)((uint)(ch - 'A' + 10) << 4);
            }
            else
            {
                throw new ArgumentException($"Invalid character '{ch}' found in hex string");
            }

            if (cl is >= '0' and <= '9')
            {
                val += (byte)(uint)(cl - '0');
            }
            else if (cl is >= 'a' and <= 'f')
            {
                val += (byte)(uint)(cl - 'a' + 10);
            }
            else if (cl is >= 'A' and <= 'F')
            {
                val = (byte)(uint)(cl - 'A' + 10);
            }
            else
            {
                throw new ArgumentException($"Invalid character '{cl}' found in hex string");
            }

            // ReSharper restore StyleCop.SA1131
#pragma warning restore SA1131 // Use readable conditions

            ret.Add(val);
        }

        return ret.ToArray();
    }
}