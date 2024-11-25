using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Snowflake;

public class KeyPairAuthentication
{
    private readonly string PrivateKey;
    private readonly string PrivateKeyPassphrase;
    private readonly string PublicKeyFingerprint;
    private readonly string AccountIdentifier;
    private readonly string User;

    public KeyPairAuthentication(string privateKey, string privateKeyPassphrase, string publicKey, string accountIdentifier, string user)
    {
        PrivateKey = privateKey;
        PrivateKeyPassphrase = privateKeyPassphrase;
        PublicKeyFingerprint = publicKey;
        AccountIdentifier = accountIdentifier;
        User = user;
    }

    private string BuildJwtToken()
    {
        // Load the private key
        var privateKey = DecryptPrivateKey(PrivateKey, PrivateKeyPassphrase);
        var publicKeyFingerprint = GeneratePublicKeyFingerprint(privateKey);

        if (PublicKeyFingerprint != publicKeyFingerprint)
        {
            throw new Exception("Public key fingerprint configured does not match the generated value using the Private key. KeyPair configuration invalid.");
        }

        var utcNow = DateTimeOffset.UtcNow;
        var expires = utcNow.DateTime.AddMinutes(15);

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

    public static RSA DecryptPrivateKey(string pem, string passphrase)
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

    public static string GeneratePublicKeyFingerprint(RSA rsa)
    {
        // Export the public key in DER format
        var publicKey = rsa.ExportSubjectPublicKeyInfo();

        // Compute the SHA-256 hash of the public key
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(publicKey);

        return Convert.ToBase64String(hash);
    }
}
