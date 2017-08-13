namespace Isopoh.Cryptography.Blake2b
{
    using Isopoh.Cryptography.SecureArray;

    /// <summary>
    /// 
    /// </summary>
    public enum LockMemoryPolicy
    {
        /// <summary>
        /// Do not attempt to lock Blake2B buffers into RAM
        /// </summary>
        None,

        /// <summary>
        /// Attempt to lock Blake2B buffers into RAM, but allow non locked memory
        /// if the operating system doesn't allow the memory to be locked.
        /// </summary>
        BestEffort,

        /// <summary>
        /// Throw <see cref="LockFailException"/> exception on failure to lock Blake2B buffers into RAM.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Different operating systems handle locking memory in different ways and have different
        /// default limits for the user. On Windows and MacOS, the defaults are that the user
        /// can lock as much memory as is available into RAM. On Linux, this is rarely the case.
        /// </para>
        /// <para>
        /// Typically, in Linux, to increase the limit, you must edit the /etc/security/limits.conf file.
        /// </para>
        /// </remarks>
        Enforce
    }
}