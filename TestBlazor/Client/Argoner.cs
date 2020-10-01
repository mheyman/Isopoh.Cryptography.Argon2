// <copyright file="Argoner.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

namespace TestBlazor.Client
{
    using System;
    using System.Threading.Tasks;
    using Isopoh.Cryptography.Argon2;

    /// <summary>
    /// Uses Argon2 to hash a secret.
    /// </summary>
    public class Argoner
    {
        /// <summary>
        /// Gets a value indicating whether the hash is being calculated.
        /// </summary>
        public bool Calculating { get; private set; }

        /// <summary>
        /// Gets how many seconds it took to create the hash to millisecond accuracy.
        /// </summary>
        public double CalculationSeconds { get; private set; }

        /// <summary>
        /// Gets the hash of the secret.
        /// </summary>
        public string Hash { get; private set; } = string.Empty;

        /// <summary>
        /// Gets the secret.
        /// </summary>
        public string Secret { get; private set; } = string.Empty;

        /// <summary>
        /// Gets or sets the time cost. Defaults to 3.
        /// </summary>
        public int TimeCost { get; set; } = 3;

        /// <summary>
        /// Gets or sets the memory cost. Defaults to 65536 (65536 * 1024 = 64MB).
        /// </summary>
        public int MemoryCost { get; set; } = 65536;

        /// <summary>
        /// Gets or sets the parallelism. Defaults to 1 (single threaded).
        /// </summary>
        public int Parallelism { get; set; } = 1;

        /// <summary>
        /// Gets or sets the type. Data-dependent (faster but susceptible to
        /// side-channel attacks), data-independent (slower and suitable
        /// for password hashing and password-based key derivation) or hybrid (a
        /// mixture of the two). The recommended type is hybrid.
        /// </summary>
        public Argon2Type Type { get; set; } = Argon2Type.HybridAddressing;

        /// <summary>
        /// Gets or sets the hash length.
        /// </summary>
        /// <remarks>
        /// The string returned base-64 encodes this with other parameters so
        /// the resulting string is significantly longer.
        /// </remarks>
        public int HashLength { get; set; } = 32;

        /// <summary>
        /// Sets the secret, notifying when the <see cref="Argoner"/> state changes (calculating hash takes a while).
        /// </summary>
        /// <param name="newSecret">The new secret.</param>
        /// <param name="stateHasChanged">Called when the state changes.</param>
        public void SetSecret(string newSecret, Action stateHasChanged)
        {
            if (newSecret != this.Secret)
            {
                this.Secret = newSecret;
                this.Recalculate(stateHasChanged ?? (() => { }));
            }
        }

        private void Recalculate(Action stateHasChanged)
        {
            var tick = DateTimeOffset.Now;
            this.Calculating = true;
            stateHasChanged();
            Task.Run(() => Argon2.Hash(
                    this.Secret, this.TimeCost, this.MemoryCost, this.Parallelism, this.Type, this.HashLength))
                .ContinueWith(
                    t =>
                    {
                        this.Hash = t.Result;
                        this.Calculating = false;
                        this.CalculationSeconds = ((int)(DateTimeOffset.Now - tick).TotalMilliseconds) / 1000.0;
                        stateHasChanged();
                    })
                .ConfigureAwait(false);
        }
    }
}
