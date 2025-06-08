using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Snowflake;

public class KeyPairAuthentication
{
    private readonly KeyPairSettings _settings;
    private string PrivateKey => _settings.PrivateKey;
    private string PrivateKeyPassphrase => _settings.PrivateKeyPassphrase;
    private string PublicKeyFingerprint => _settings.PublicKeyFingerprint;
    private string AccountIdentifier => _settings.AccountIdentifier;
    private string User => _settings.User;

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyPairAuthentication"/> class.
    /// </summary>
    /// <param name="settings">The injected configuration settings.</param>
    public KeyPairAuthentication(IOptions<KeyPairSettings> settings)
    {
        _settings = settings.Value;
    }

    /// <summary>
    /// Builds a JWT token using the KeyPairSettings configuration.
    /// </summary>
    /// <returns>The Jwt Token for Authentication.</returns>
    /// <param name="tokenLifetime">Optional lifetime for the token. If not provided, defaults to 15 minutes.</param>
    /// <exception cref="FingerprintMismatchException"></exception>
    public string BuildJwtToken(TimeSpan? tokenLifetime = null)
    {
        // Load the private key
        var privateKey = DecryptPrivateKey(PrivateKey, PrivateKeyPassphrase);
        var publicKeyFingerprint = GeneratePublicKeyFingerprint(privateKey);

        if (PublicKeyFingerprint != publicKeyFingerprint) throw new FingerprintMismatchException();

        var utcNow = DateTimeOffset.UtcNow;
        var expires = utcNow.DateTime.Add(tokenLifetime ?? TimeSpan.FromMinutes(15));

        var subject = $"{AccountIdentifier}.{User}".ToUpper();
        var claims = new Claim[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, subject),
            new Claim(JwtRegisteredClaimNames.Iat, utcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

        var issuer = $"{subject}.SHA256:{publicKeyFingerprint}";

        // Create signing credentials
        var signingCredentials = new SigningCredentials(
            new RsaSecurityKey(privateKey),
            SecurityAlgorithms.RsaSha256
        );

        var token = new JwtSecurityToken(
            issuer: issuer,
            claims: claims,
            expires: expires,
            signingCredentials: signingCredentials);

        var tokenHandler = new JwtSecurityTokenHandler();
        return tokenHandler.WriteToken(token);
    }

    /// <summary>
    /// Decrypts the private key from PEM format using the provided passphrase.
    /// The PEM format should start with "-----BEGIN ENCRYPTED PRIVATE KEY-----"
    /// and end with "-----END ENCRYPTED PRIVATE KEY-----".
    /// </summary>
    /// <param name="pem">The pem.</param>
    /// <param name="passphrase">The passphrase.</param>
    /// <returns>The private key decrypted.</returns>
    private RSA DecryptPrivateKey(string pem, string passphrase)
    {
        // Remove the PEM header and footer
        var header = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        var footer = "-----END ENCRYPTED PRIVATE KEY-----";
        var start = pem.IndexOf(header, StringComparison.Ordinal) + header.Length;
        var end = pem.IndexOf(footer, start, StringComparison.Ordinal);
        var base64 = pem[start..end].Trim();

        // Decode the Base64 content
        var encryptedPrivateKey = Convert.FromBase64String(base64);

        // Decrypt the private key using the passphrase
        var rsa = RSA.Create();
        rsa.ImportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(passphrase), encryptedPrivateKey, out _);

        return rsa;
    }

    /// <summary>
    /// Generates the public key fingerprint from the RSA private key.
    /// </summary>
    /// <param name="rsa">The private key.</param>
    /// <returns>The public key as a Base64 string corresponding to the RSA private key.</returns>
    private string GeneratePublicKeyFingerprint(RSA rsa)
    {
        // Export the public key in DER format
        var publicKey = rsa.ExportSubjectPublicKeyInfo();

        // Compute the SHA-256 hash of the public key
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(publicKey);

        return Convert.ToBase64String(hash);
    }
}
