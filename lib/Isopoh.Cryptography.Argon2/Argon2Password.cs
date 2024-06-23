namespace Isopoh.Cryptography.Argon2;

using System;

/// <summary>
/// Whether to keep of clear an existing password in an <see cref="Argon2Memory"/>.
/// </summary>
public enum Argon2ExistingPasswordResetPolicy
{
    /// <summary>
    /// Keep the existing password.
    /// </summary>
    Keep,

    /// <summary>
    /// Clear any existing password.
    /// </summary>
    Clear,
}

/// <summary>
/// This holds a password or an <see cref="Argon2ExistingPasswordResetPolicy"/>. I wish I had F# discriminated unions.
/// </summary>
public ref struct Argon2Password
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Argon2Password"/> struct.
    /// </summary>
    /// <param name="policy">The policy to initialize the struct with.</param>
    public Argon2Password(Argon2ExistingPasswordResetPolicy policy)
    {
        this.Policy = policy;
        this.Password = Span<byte>.Empty;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Argon2Password"/> struct.
    /// </summary>
    /// <param name="password">The password to initialize the struct with.</param>
    public Argon2Password(Span<byte> password)
    {
        this.Policy = Argon2ExistingPasswordResetPolicy.Clear;
        this.Password = password;
    }

    /// <summary>
    /// Cast an <see cref="Argon2Password"/> to an <see cref="Argon2ExistingPasswordResetPolicy"/>.
    /// </summary>
    /// <param name="password">The password to get the policy for. Note only relevant if the <see cref="Password"/> is empty.</param>
    public static implicit operator Argon2ExistingPasswordResetPolicy(Argon2Password password) => password.Policy;

    /// <summary>
    /// Cast an <see cref="Argon2ExistingPasswordResetPolicy"/> to an <see cref="Argon2Password"/>.
    /// </summary>
    /// <param name="policy">The policy to cast.</param>
    public static explicit operator Argon2Password(Argon2ExistingPasswordResetPolicy policy) => new Argon2Password(policy);

    /// <summary>
    /// Cast an <see cref="Argon2Password"/> to a password.
    /// </summary>
    /// <param name="password">The password to cast.</param>
    public static implicit operator Span<byte>(Argon2Password password) => password.Password;

    /// <summary>
    /// Cast a password to an <see cref="Argon2Password"/>.
    /// </summary>
    /// <param name="password">The password to cast.</param>
    public static explicit operator Argon2Password(Span<byte> password) => new Argon2Password(password);

    /// <summary>
    /// Gets the password policy. Only relevant if <see cref="Password"/> is empty.
    /// </summary>
    public Argon2ExistingPasswordResetPolicy Policy { get; private set; }

    /// <summary>
    /// Gets the password.
    /// </summary>
    public Span<byte> Password { get; private set; }
}