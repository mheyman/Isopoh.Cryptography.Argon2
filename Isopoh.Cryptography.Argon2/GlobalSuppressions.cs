// <copyright file="GlobalSuppressions.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("StyleCop.CSharp.SpacingRules", "SA1011:Closing square brackets should be spaced correctly", Justification = "nullable array ok", Scope = "type", Target = "~T:Isopoh.Cryptography.Argon2.Argon2Config")]
[assembly: SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "configuration array", Scope = "member", Target = "~P:Isopoh.Cryptography.Argon2.Argon2Config.AssociatedData")]
[assembly: SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "configuration array", Scope = "member", Target = "~P:Isopoh.Cryptography.Argon2.Argon2Config.Password")]
[assembly: SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "configuration array", Scope = "member", Target = "~P:Isopoh.Cryptography.Argon2.Argon2Config.Salt")]
[assembly: SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "configuration array", Scope = "member", Target = "~P:Isopoh.Cryptography.Argon2.Argon2Config.Secret")]
[assembly: SuppressMessage("StyleCop.CSharp.SpacingRules", "SA1011:Closing square brackets should be spaced correctly", Justification = "nullable array ok", Scope = "member", Target = "~M:Isopoh.Cryptography.Argon2.Argon2.Hash(System.Byte[],System.Byte[],System.Int32,System.Int32,System.Int32,Isopoh.Cryptography.Argon2.Argon2Type,System.Int32,Isopoh.Cryptography.SecureArray.SecureArrayCall)~System.String")]
[assembly: SuppressMessage("StyleCop.CSharp.SpacingRules", "SA1011:Closing square brackets should be spaced correctly", Justification = "nullable array ok", Scope = "member", Target = "~M:Isopoh.Cryptography.Argon2.Argon2.Verify(System.String,System.Byte[],System.Byte[],Isopoh.Cryptography.SecureArray.SecureArrayCall)~System.Boolean")]
[assembly: SuppressMessage("StyleCop.CSharp.SpacingRules", "SA1011:Closing square brackets should be spaced correctly", Justification = "nullable array ok", Scope = "member", Target = "~M:Isopoh.Cryptography.Argon2.DecodeExtension.DecodeBase64(System.Byte[]@,System.String,System.String,System.Int32)~System.Int32")]
[assembly: SuppressMessage("StyleCop.CSharp.SpacingRules", "SA1011:Closing square brackets should be spaced correctly", Justification = "nullable array ok", Scope = "member", Target = "~M:Isopoh.Cryptography.Argon2.DecodeExtension.FromBase64(System.Byte[]@,System.String,System.Int32)~System.Int32")]
[assembly: SuppressMessage("StyleCop.CSharp.SpacingRules", "SA1011:Closing square brackets should be spaced correctly", Justification = "nullable array ok", Scope = "member", Target = "~M:Isopoh.Cryptography.Argon2.DecodeExtension.DecodeString(Isopoh.Cryptography.Argon2.Argon2Config,System.String,Isopoh.Cryptography.SecureArray.SecureArray{System.Byte}@)~System.Boolean")]
[assembly: SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "ignoring so ok", Scope = "member", Target = "~M:Isopoh.Cryptography.Argon2.DecodeExtension.DecodeString(Isopoh.Cryptography.Argon2.Argon2Config,System.String,Isopoh.Cryptography.SecureArray.SecureArray{System.Byte}@)~System.Boolean")]
[assembly: SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "for display", Scope = "member", Target = "~M:Isopoh.Cryptography.Argon2.Argon2.InitialKat(System.Byte[],Isopoh.Cryptography.Argon2.Argon2)")]
[assembly: SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "for display", Scope = "member", Target = "~M:Isopoh.Cryptography.Argon2.Argon2.PrintTag(System.Byte[])")]
[assembly: SuppressMessage("Naming", "CA1724:Type names should not match namespaces", Justification = "breaking", Scope = "type", Target = "~T:Isopoh.Cryptography.Argon2.Argon2")]
