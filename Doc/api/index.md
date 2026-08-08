# Isopoh.Cryptography API

The library is divided into three assemblies and namespaces:

1. <xref:Isopoh.Cryptography.Argon2>
2. <xref:Isopoh.Cryptography.Blake2b>
3. <xref:Isopoh.Cryptography.SecureArray>

Most applications only need the static `Hash` and `Verify` methods on
<xref:Isopoh.Cryptography.Argon2.Argon2>. Server applications that perform repeated
operations can reuse buffers with <xref:Isopoh.Cryptography.Argon2.Argon2Memory>.

For operational guidance, see [Reusing Argon2 memory](../articles/reusable-memory.md)
and [Secure memory by platform](../articles/secure-memory.md).
