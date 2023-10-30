// <copyright file="IsExternalInit.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

#pragma warning disable S3261 // namespaces not empty
// ReSharper disable once CheckNamespace
// ReSharper disable once EmptyNamespace
namespace System.Runtime.CompilerServices;

#if !NET5_0_OR_GREATER
#pragma warning disable SA1600 // Elements should be documented
#pragma warning disable SA1502 // Element should not be on a single line
// ReSharper disable once UnusedMember.Global
internal static class IsExternalInit { }
#pragma warning restore SA1502 // Element should not be on a single line
#pragma warning restore SA1600 // Elements should be documented
#endif
#pragma warning restore S3261 // namespaces not empty