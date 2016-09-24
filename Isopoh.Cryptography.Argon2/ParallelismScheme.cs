// <copyright file="ParallelismScheme.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace Isopoh.Cryptography.Argon2
{
    /// <summary>
    /// How to do parallelism in the Argon2 block fill.
    /// </summary>
    public enum ParallelismScheme
    {
        /// <summary>
        /// Spawn a new thread for every block fill.
        /// </summary>
        NaiveThreads,

        /// <summary>
        /// Spawn only the threads needed and reuse them as required.
        /// </summary>
        Threads,

        /// <summary>
        /// Spawn a new task for every block fill
        /// </summary>
        NaiveTasks,

        /// <summary>
        /// Spawn only the tasks needed and reuse them as required.
        /// </summary>
        Tasks
    }
}