// <copyright file="UnitTests.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>
// <summary>
// Tests because unit tests seem to be hard to get running.
// </summary>

namespace Isopoh.Cryptography.Test;
using TestLib;

using Argon2;
using SecureArray;
using Xunit;
using Xunit.Abstractions;

/// <summary>
/// Unit tests for Isopoh.Cryptography.Argon2.
/// </summary>
public class UnitTests
{
    private readonly ITestOutputHelper output;

    /// <summary>
    /// Initializes a new instance of the <see cref="UnitTests"/> class.
    /// </summary>
    /// <param name="output">
    /// Where to send the output to (doesn't seem to work...)
    /// </param>
    public UnitTests(ITestOutputHelper output)
    {
        this.output = output;
    }

    /// <summary>
    /// Test <see cref="Argon2"/>.
    /// </summary>
    [Fact]
    public void TestArgon2RoundTrip()
    {
        var (passed, text) = RoundTrip.Test(this.output);
        Assert.True(passed, text);
    }

    /// <summary>
    /// Test <see cref="Argon2"/>.
    /// </summary>
    [Fact]
    public void TestArgon2RoundTripSimpleCall()
    {
        var (passed, text) = RoundTripSimpleCall.Test(this.output);
        Assert.True(passed, text);
    }

    /// <summary>
    /// Test <see cref="Argon2"/>.
    /// </summary>
    [Fact]
    public void TestArgon2ThreadsDontMatter()
    {
        var (passed, text) = ThreadsDontMatter.Test(this.output);
        Assert.True(passed, text);
    }

    /// <summary>
    /// Test <see cref="Argon2"/>.
    /// </summary>
    [Fact]
    public void TestArgon2()
    {
        var (passed, text) = PublishedVector.Test(this.output);
        Assert.True(passed, text);
    }

    /// <summary>
    /// Test <see cref="Argon2"/>.
    /// </summary>
    [Fact]
    public void TestParallelismTiming()
    {
        var (passed, text) = TimeToHash.Test(this.output);
        Assert.True(passed, text);
    }

    /// <summary>
    /// Test <see cref="Argon2"/>.
    /// </summary>
    [Fact]
    public void TestLeaking()
    {
        var (passed, text) = LeakInVerify.Test(this.output);
        Assert.True(passed, text);
    }

    ////[Fact]
    ////public void TestStore64()
    ////{
    ////    var v1 = new byte[8];
    ////    var v2 = new byte[8];

    ////    rng.GetBytes(salt);
    ////    ulong tmp = Hasher.Load64(v1, 0);
    ////    Hasher.Store64(v2, 0, tmp);
    ////    this.output.WriteLine($"{BitConverter.ToString(v1)}");
    ////    this.output.WriteLine($"{tmp:X}");
    ////    this.output.WriteLine($"{BitConverter.ToString(v2)}");
    ////    Assert.True(false, $"{BitConverter.ToString(v1)}\r\n{tmp:X}\r\n{BitConverter.ToString(v2)}");

    ////    Assert.Equal(v1, v2);
    ////}

    /// <summary>
    /// Test the size of buffer <see cref="SecureArray"/> allows.
    /// </summary>
    /// <remarks>
    /// <see cref="SecureArray"/> already tends to try to figure this out under the hood.
    /// </remarks>
    [Fact]
    public void TestSecureArray()
    {
        var (passed, text) = SecureArraySizing.Test(this.output);
        Assert.True(passed, text);
    }

    [Fact]
    public void HashSize()
    {
        string password = "password";
        string hash = Argon2.Hash(password, hashLength: 16);
        Assert.True(Argon2.Verify(hash, password));
    }

    [Fact]
    public void TestHighMemoryCost()
    {
        var (passed, text) = HighMemoryCost.Test(this.output);
        Assert.True(passed, text);
    }
}