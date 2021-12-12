// <copyright file="GlobalSuppressions.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.
using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Design", "CA1051:Do not declare visible instance fields", Justification = "C++ interop", Scope = "member", Target = "~F:Isopoh.Cryptography.SecureArray.DefaultWindowsSecureArrayCall.ProcessMemoryCounters.Cb")]
[assembly: SuppressMessage("Design", "CA1051:Do not declare visible instance fields", Justification = "C++ interop", Scope = "member", Target = "~F:Isopoh.Cryptography.SecureArray.DefaultWindowsSecureArrayCall.ProcessMemoryCounters.PageFaultCount")]
[assembly: SuppressMessage("Design", "CA1051:Do not declare visible instance fields", Justification = "C++ interop", Scope = "member", Target = "~F:Isopoh.Cryptography.SecureArray.DefaultWindowsSecureArrayCall.ProcessMemoryCounters.PagefileUsage")]
[assembly: SuppressMessage("Design", "CA1051:Do not declare visible instance fields", Justification = "C++ interop", Scope = "member", Target = "~F:Isopoh.Cryptography.SecureArray.DefaultWindowsSecureArrayCall.ProcessMemoryCounters.PeakPagefileUsage")]
[assembly: SuppressMessage("Design", "CA1051:Do not declare visible instance fields", Justification = "C++ interop", Scope = "member", Target = "~F:Isopoh.Cryptography.SecureArray.DefaultWindowsSecureArrayCall.ProcessMemoryCounters.PeakWorkingSetSize")]
[assembly: SuppressMessage("Design", "CA1051:Do not declare visible instance fields", Justification = "C++ interop", Scope = "member", Target = "~F:Isopoh.Cryptography.SecureArray.DefaultWindowsSecureArrayCall.ProcessMemoryCounters.QuotaNonPagedPoolUsage")]
[assembly: SuppressMessage("Design", "CA1051:Do not declare visible instance fields", Justification = "C++ interop", Scope = "member", Target = "~F:Isopoh.Cryptography.SecureArray.DefaultWindowsSecureArrayCall.ProcessMemoryCounters.QuotaPagedPoolUsage")]
[assembly: SuppressMessage("Design", "CA1051:Do not declare visible instance fields", Justification = "C++ interop", Scope = "member", Target = "~F:Isopoh.Cryptography.SecureArray.DefaultWindowsSecureArrayCall.ProcessMemoryCounters.QuotaPeakNonPagedPoolUsage")]
[assembly: SuppressMessage("Design", "CA1051:Do not declare visible instance fields", Justification = "C++ interop", Scope = "member", Target = "~F:Isopoh.Cryptography.SecureArray.DefaultWindowsSecureArrayCall.ProcessMemoryCounters.QuotaPeakPagedPoolUsage")]
[assembly: SuppressMessage("Design", "CA1051:Do not declare visible instance fields", Justification = "C++ interop", Scope = "member", Target = "~F:Isopoh.Cryptography.SecureArray.DefaultWindowsSecureArrayCall.ProcessMemoryCounters.WorkingSetSize")]
[assembly: SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "C++ interop", Scope = "type", Target = "~T:Isopoh.Cryptography.SecureArray.DefaultWindowsSecureArrayCall.ProcessMemoryCounters")]
[assembly: SuppressMessage("Performance", "CA1815:Override equals and operator equals on value types", Justification = "C++ interop", Scope = "type", Target = "~T:Isopoh.Cryptography.SecureArray.DefaultWindowsSecureArrayCall.ProcessMemoryCounters")]
[assembly: SuppressMessage("Style", "IDE0060:Remove unused parameter", Justification = "clearer and simpler with parameter", Scope = "member", Target = "~M:Isopoh.Cryptography.SecureArray.SecureArray.BuiltInTypeElementSize``1(``0[])~System.Int32")]
[assembly: SuppressMessage("Usage", "CA1801:Review unused parameters", Justification = "clearer and simpler with parameter", Scope = "member", Target = "~M:Isopoh.Cryptography.SecureArray.SecureArray.BuiltInTypeElementSize``1(``0[])~System.Int32")]
[assembly: SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "it is supposed to be an array", Scope = "member", Target = "~P:Isopoh.Cryptography.SecureArray.SecureArray`1.Buffer")]
[assembly: SuppressMessage("Design", "CA1000:Do not declare static members on generic types", Justification = "this is required here", Scope = "member", Target = "~M:Isopoh.Cryptography.SecureArray.SecureArray`1.Best(System.Int32,Isopoh.Cryptography.SecureArray.SecureArrayCall)~Isopoh.Cryptography.SecureArray.SecureArray{`0}")]
[assembly: SuppressMessage("Microsoft.Naming", "CA1724:TypeNamesShouldNotMatchNamespaces", Justification = "Old code")]
[assembly: SuppressMessage("Major Code Smell", "S1854:Unused assignments should be removed", Justification = "Things are strange in p/invoke code - this is probably correct...", Scope = "member", Target = "~M:Isopoh.Cryptography.SecureArray.DefaultWindowsSecureArrayCall.GetWorkingSetSize(System.IntPtr)~System.UInt64")]
[assembly: SuppressMessage("Major Code Smell", "S3358:Ternary operators should not be nested", Justification = "Reviewed", Scope = "member", Target = "~P:Isopoh.Cryptography.SecureArray.SecureArray.ProtectionType")]
