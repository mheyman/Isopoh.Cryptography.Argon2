// <copyright file="GlobalSuppressions.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "configuration item", Scope = "member", Target = "~P:Isopoh.Cryptography.Blake2b.Blake2BConfig.Key")]
[assembly: SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "configuration item", Scope = "member", Target = "~P:Isopoh.Cryptography.Blake2b.Blake2BConfig.Personalization")]
[assembly: SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "configuration item", Scope = "member", Target = "~P:Isopoh.Cryptography.Blake2b.Blake2BConfig.Result64ByteBuffer")]
[assembly: SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "configuration item", Scope = "member", Target = "~P:Isopoh.Cryptography.Blake2b.Blake2BConfig.Salt")]
[assembly: SuppressMessage("Naming", "CA1724:Type names should not match namespaces", Justification = "breaking", Scope = "type", Target = "~T:Isopoh.Cryptography.Blake2b.Blake2B")]
[assembly: SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1633:File should have header", Justification = "Alternate copyright", Scope = "namespace", Target = "~N:Isopoh.Cryptography.Blake2b")]
[assembly: SuppressMessage("Minor Code Smell", "S3261:Namespaces should not be empty", Justification = "reviewed", Scope = "namespace", Target = "~N:Isopoh.Cryptography.Blake2b")]
