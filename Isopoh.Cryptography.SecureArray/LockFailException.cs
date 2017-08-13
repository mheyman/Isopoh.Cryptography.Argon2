namespace Isopoh.Cryptography.SecureArray
{
    /// <summary>
    /// Represents errors that occur trying to lock a buffer into memory
    /// </summary>
    public class LockFailException : System.Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="LockFailException"/> class.
        /// </summary>
        /// <param name="message"></param>
        /// <param name="currentMax"></param>
        /// <returns></returns>
        public LockFailException(string message, int currentMax) : base(message) 
        {
            this.CurrentMax = currentMax;
        }

        /// <summary>
        /// Gets the current maximum number of bytes that can be locked.
        /// </summary>
        /// <returns></returns>
        public int CurrentMax { get; }
    }
}