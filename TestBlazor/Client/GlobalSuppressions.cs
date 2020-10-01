// <copyright file="GlobalSuppressions.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Reliability", "CA2008:Do not create tasks without passing a TaskScheduler", Justification = "Run documented to use default scheduler", Scope = "member", Target = "~M:TestBlazor.Client.Argoner.Recalculate(System.Action)")]
