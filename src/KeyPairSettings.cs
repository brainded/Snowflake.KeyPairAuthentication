namespace Snowflake;

public class KeyPairSettings
{
    /// <summary>
    /// The section name for the key pair settings in the configuration file.
    /// </summary>
    public const string Section = "SnowflakeKeyPair";

    /// <summary>
    /// The private key in PEM format. This should be the private key used for signing JWTs.
    /// </summary>
    public required string PrivateKey { get; set; }

    /// <summary>
    /// The passphrase for the private key. This is used to decrypt the private key.
    /// </summary>
    public required string PrivateKeyPassphrase { get; set; }

    /// <summary>
    /// The public key fingerprint in SHA256 format. This is used to verify the public key associated with the private key.
    /// </summary>
    public required string PublicKeyFingerprint { get; set; }

    /// <summary>
    /// The account identifier for the Snowflake account. This is typically the account name or ID.
    /// </summary>
    public required string AccountIdentifier { get; set; }

    /// <summary>
    /// The user name for the Snowflake account. This is the user that will be authenticated using the key pair.
    /// </summary>
    public required string User { get; set; }
}