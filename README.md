# Fully Managed .Net Core Argon2 implementation

Uses the C# implementation of Blake2 modified from https://github.com/BLAKE2.
The Blake2 here uses SecureArray to protect potentially sensitive data.

Uses a highly modified port of Argon2 from https://github.com/P-H-C/phc-winner-argon2.

## Example Usage

Using the defaults:

```csharp
var password = "password1";
var passwordHash = Argon2.Hash(password);
if (Argon2.Verify(passwordHash, password))
{
    // do stuff
}
```

Setting everything:

```csharp
var password = "password1";
byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
byte[] salt = new byte[16];

// somewhere in the class definition:
//   private static readonly RandomNumberGenerator Rng = 
//       System.Security.Cryptography.RandomNumberGenerator.Create();
Rng.GetBytes(salt); 

var config = new Argon2Config
{
    Type = Argon2Type.DataIndependentAddressing,
    Version = Argon2Version.Nineteen,
    TimeCost = 10,
    MemoryCost = 32768,
    Lanes = 5,
    Threads = Environment.ProcessorCount,
    Password = passwordBytes,
    Salt = salt, // >= 8 bytes if not null
    Secret = secret, // from somewhere
    AssociatedData = associatedData, // from somewhere
    HashLength = 20 // >= 4
};
var argon2A = new Argon2(config);
string hashString;
using(SecureArray<byte> hashA = argon2.Hash())
{
    hashString = config.EncodeString(hashA.Buffer);
}

//
// Now pretend "passwordBytes" is what just came in and that it must be
// verified against the known "hashString".
//
// Note setting "Threads" to different values doesn't effect the result,
// just the time it takes to get the result.
//
var configOfPasswordToVerify = new Argon2Config { Password = passwordBytes, Threads = 1 };
SecureArray<byte> hashB = null;
try
{
    if (configOfPasswordToVerify.DecodeString(hashString, out hashB) && hashB != null)
    {
        var argon2ToVerify = new Argon2(configOfPasswordToVerify);
        using(var hashToVerify = argon2Verify.Hash())
        {
            if (!hashB.Buffer.Where((b, i) => b != hashToVerify[i]).Any())
            {
                // verified
            }
        }
    }
}
finally
{
    hashB?.Dispose();
}

//
// Or, more simply (but this doesn't allow setting "Threads")
//
if (Argon2.Verify(hashString, passwordBytes))
{
    // verified
}

```

## What is SecureArray?

You can think of the `SecureArray` sort of like you would think of
`SecureString` except that `SecureString` does crypto to protect 
its sensitive data and has windows of vulnerability. `SecureArray`
protects its data by locking it into RAM to protect it from swapping
to disk until disposed and also zeroing the buffer when disposed.

Because it locks the memory into RAM (and at a
non-movable-by-the-garbage-collector location), you need to use it
as infrequently as possible and for as short a time as possible.
Always dispose of your `SecureArray`s.
