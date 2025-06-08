namespace Snowflake;

public class FingerprintMismatchException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="FingerprintMismatchException"/> class.
    /// </summary>
    public FingerprintMismatchException()
        : base("Public key fingerprint configured does not match the generated value using the Private key. KeyPair configuration invalid.")
    {
    }
}