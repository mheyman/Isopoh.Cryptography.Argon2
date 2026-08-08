namespace Isopoh.Cryptography.UnitySmokeTests
{
    using Isopoh.Cryptography.Argon2;
    using Isopoh.Cryptography.SecureArray;
    using NUnit.Framework;

    public class UnitySmokeTests
    {
        [Test]
        public void HashAndVerifyUsesLockedDesktopMemory()
        {
            const string Password = "unity-smoke-test";
            string hash = Argon2.Hash(Password, timeCost: 1, memoryCost: 1024, parallelism: 1);

            Assert.That(Argon2.Verify(hash, Password), Is.True);
            Assert.That(SecureArray.DefaultCall.Os, Is.EqualTo("Linux"));
            Assert.That(SecureArray.DefaultCall.IsMemoryLockSupported, Is.True);

            using (SecureArray<byte> buffer = SecureArray<byte>.Create(
                4096,
                SecureArray.DefaultCall,
                LockMemoryPolicy.Enforce))
            {
                Assert.That(buffer.ProtectionType, Is.EqualTo(SecureArrayType.ZeroedPinnedAndNoSwap));
            }
        }
    }
}
