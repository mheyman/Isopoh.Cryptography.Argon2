# Isopoh.Cryptography.Argon2 API

There are three assemblies and their respective namespaces:

1. [Isopoh.Cryptography.SecureArray](Isopoh.Cryptography.SecureArray.html)
1. [Isopoh.Cryptography.Blake2b](Isopoh.Cryptography.Blake2b.html)
1. [Isopoh.Cryptography.Argon2](Isopoh.Cryptography.Argon2.html)

To do Argon2 hashing, typically, the only calls needed are the static
[Argon2.Hash()](Isopoh.Cryptography.Argon2.Argon2.html#Isopoh_Cryptography_Argon2_Argon2_Hash_System_Byte___System_Byte___System_Int32_System_Int32_System_Int32_Isopoh_Cryptography_Argon2_Argon2Type_System_Int32_Isopoh_Cryptography_SecureArray_SecureArrayCall_)
calls to create the hash and one of the static [Argon2.Verify()](Isopoh.Cryptography.Argon2.Argon2.html#Isopoh_Cryptography_Argon2_Argon2_Verify_System_String_Isopoh_Cryptography_Argon2_Argon2Config_)
calls to verify the hash.