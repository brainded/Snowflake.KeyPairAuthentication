namespace Snowflake;

public class KeyPairSettings
{
    public const string Section = "SnowflakeKeyPair";

    public required string PrivateKey { get; set; }
    public required string PrivateKeyPassphrase { get; set; }
    public required string PublicKeyFingerprint { get; set; }
    public required string AccountIdentifier { get; set; }
    public required string User { get; set; }
}