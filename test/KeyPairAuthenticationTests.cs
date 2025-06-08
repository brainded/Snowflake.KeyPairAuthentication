using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using NSubstitute;
using Snowflake;
using Xunit;

namespace Snowflake.Tests
{
    public class KeyPairAuthenticationTests
    {
        private const string TestPrivateKeyPassphrase = "snowflake";
        private const string TestAccountIdentifier = "testaccount";
        private const string TestUser = "testuser";

        private KeyPairSettings GetValidSettings()
        {
            // Generate a valid RSA key pair for testing
            using var rsa = RSA.Create();
            var privateKeyBytes = rsa.ExportEncryptedPkcs8PrivateKey(
                Encoding.UTF8.GetBytes(TestPrivateKeyPassphrase),
                new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 10000));

            // Generate encrypted private key
            var encryptedPrivateKey = GenerateEncryptedPrivateKey(privateKeyBytes);

            // Generate a valid fingerprint that matches the private key
            var publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(publicKeyBytes);
            var fingerprint = Convert.ToBase64String(hash);

            return new KeyPairSettings
            {
                PrivateKey = encryptedPrivateKey,
                PrivateKeyPassphrase = TestPrivateKeyPassphrase,
                PublicKeyFingerprint = fingerprint,
                AccountIdentifier = TestAccountIdentifier,
                User = TestUser
            };
        }

        private string GenerateEncryptedPrivateKey(byte[] privateKeyBytes)
        {
            // Use a simple format for testing - this isn't real encryption but works for our tests
            var header = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n";
            var footer = "\n-----END ENCRYPTED PRIVATE KEY-----";
            
            // In a real implementation, this would be properly encrypted
            // For testing, we'll just base64 encode it
            return header + Convert.ToBase64String(privateKeyBytes) + footer;
        }

        [Fact]
        public void BuildJwtToken_WithValidSettings_ReturnsToken()
        {
            // Arrange
            var settings = GetValidSettings();
            var mockOptions = Substitute.For<IOptions<KeyPairSettings>>();
            mockOptions.Value.Returns(settings);
            
            var keyPairAuth = new KeyPairAuthentication(mockOptions);

            // Act
            var token = keyPairAuth.BuildJwtToken();

            // Assert
            Assert.NotNull(token);
            Assert.NotEmpty(token);
        }

        [Fact]
        public void BuildJwtToken_WithCustomExpiration_ReturnsTokenWithCorrectExpiration()
        {
            // Arrange
            var settings = GetValidSettings();
            var mockOptions = Substitute.For<IOptions<KeyPairSettings>>();
            mockOptions.Value.Returns(settings);
            
            var keyPairAuth = new KeyPairAuthentication(mockOptions);
            var customExpiration = TimeSpan.FromHours(1);

            // Act
            var token = keyPairAuth.BuildJwtToken(customExpiration);
            
            // Decode the token to verify expiration
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);

            // Assert
            var expectedExpiration = DateTimeOffset.UtcNow.Add(customExpiration).DateTime;
            
            // Allow for a small time difference (30 seconds) due to execution time
            var timeDifference = (jwtToken.ValidTo - expectedExpiration).TotalSeconds;
            Assert.True(Math.Abs(timeDifference) < 30, 
                $"Token expiration {jwtToken.ValidTo} should be close to expected {expectedExpiration}");
        }

        [Fact]
        public void BuildJwtToken_WithInvalidFingerprint_ThrowsFingerprintMismatchException()
        {
            // Arrange
            var settings = GetValidSettings();
            // Set invalid fingerprint to trigger the exception
            settings.PublicKeyFingerprint = "invalidfingerprint";
            
            var mockOptions = Substitute.For<IOptions<KeyPairSettings>>();
            mockOptions.Value.Returns(settings);
            
            var keyPairAuth = new KeyPairAuthentication(mockOptions);

            // Act & Assert
            var exception = Assert.Throws<FingerprintMismatchException>(() => keyPairAuth.BuildJwtToken());
            Assert.Equal("Public key fingerprint configured does not match the generated value using the Private key. KeyPair configuration invalid.", 
                exception.Message);
        }

        [Fact]
        public void BuildJwtToken_TokenContainsCorrectClaims()
        {
            // Arrange
            var settings = GetValidSettings();
            var mockOptions = Substitute.For<IOptions<KeyPairSettings>>();
            mockOptions.Value.Returns(settings);
            
            var keyPairAuth = new KeyPairAuthentication(mockOptions);

            // Act
            var token = keyPairAuth.BuildJwtToken();
            
            // Decode the token
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);

            // Assert
            // 1. Check subject claim
            var expectedSubject = $"{TestAccountIdentifier}.{TestUser}".ToUpper();
            var actualSubject = jwtToken.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
            Assert.Equal(expectedSubject, actualSubject);
            
            // 2. Check issued at claim exists
            var iat = jwtToken.Claims.FirstOrDefault(c => c.Type == "iat");
            Assert.NotNull(iat);
            
            // 3. Check issuer contains the expected subject and SHA256 label
            Assert.Contains(expectedSubject, jwtToken.Issuer);
            Assert.Contains("SHA256:", jwtToken.Issuer);
            
            // 4. Verify token has an expiration
            Assert.True(jwtToken.ValidTo > DateTime.UtcNow);
        }
    }
}
