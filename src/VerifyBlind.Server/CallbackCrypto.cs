using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VerifyBlind.Server.Internal;

namespace VerifyBlind.Server;

/// <summary>An enclave-signed <c>{ payload, signature }</c> pair whose signature has NOT been checked yet.</summary>
public sealed class SignedPayload
{
    /// <summary>Creates a pair, e.g. from your own decryption.</summary>
    public SignedPayload(string payload, string signature)
    {
        Payload = payload;
        Signature = signature;
    }

    /// <summary>The signed JSON string. Contains identity codes: never log it.</summary>
    public string Payload { get; }

    /// <summary>Base64 RSA-PSS signature over <see cref="Payload"/>.</summary>
    public string Signature { get; }

    /// <inheritdoc />
    public override string ToString() => "SignedPayload([redacted])";
}

/// <summary>
/// Your fixed callback key pair for pattern B. Load the private key from an environment variable (never git).
/// <see cref="PublicKeyBase64"/> is what you send as <c>public_key</c> to <c>POST /api/pop/generate</c>.
/// </summary>
public sealed class VerifyBlindCallbackKey : IDisposable
{
    private VerifyBlindCallbackKey(RSA rsa)
    {
        Rsa = rsa;
        PublicKeyBase64 = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
        PkHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(PublicKeyBase64))).ToLowerInvariant();
    }

    /// <summary>The private key.</summary>
    public RSA Rsa { get; }

    /// <summary>Base64 SPKI of the public key (no PEM header): the <c>public_key</c> field of generate.</summary>
    public string PublicKeyBase64 { get; }

    /// <summary>Lowercase hex SHA-256 of the UTF-8 <see cref="PublicKeyBase64"/>: the <c>pk_hash</c> of the app link.</summary>
    public string PkHash { get; }

    /// <summary>
    /// Loads the private key from a PEM (<c>-----BEGIN PRIVATE KEY-----</c> or <c>RSA PRIVATE KEY</c>) or from
    /// base64 PKCS#8 DER (the format of <c>CALLBACK_PRIVATE_KEY</c> in the .NET example).
    /// </summary>
    /// <exception cref="ArgumentException">The text is not an RSA private key.</exception>
    public static VerifyBlindCallbackKey Load(string pemOrBase64Pkcs8)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pemOrBase64Pkcs8);
        var rsa = RSA.Create();
        try
        {
            if (pemOrBase64Pkcs8.Contains("-----BEGIN", StringComparison.Ordinal))
            {
                rsa.ImportFromPem(pemOrBase64Pkcs8);
            }
            else
            {
                var der = Base64.Decode(pemOrBase64Pkcs8) ?? throw new FormatException();
                rsa.ImportPkcs8PrivateKey(der, out _);
            }
            // A public-only PEM imports fine; signing-capable parameters prove it is a private key.
            rsa.ExportParameters(includePrivateParameters: true);
            return new VerifyBlindCallbackKey(rsa);
        }
        catch (Exception e) when (e is CryptographicException or FormatException or ArgumentException)
        {
            rsa.Dispose();
            throw new ArgumentException("The callback key is not an RSA private key (PEM or base64 PKCS#8).", nameof(pemOrBase64Pkcs8));
        }
    }

    /// <summary>Creates a new RSA-2048 key pair (e.g. a one-off setup script). Store <see cref="ExportPkcs8Base64"/> as a secret.</summary>
    public static VerifyBlindCallbackKey Generate() => new(RSA.Create(2048));

    /// <summary>The private key as base64 PKCS#8 DER, for your secret store. Never log it.</summary>
    public string ExportPkcs8Base64() => Convert.ToBase64String(Rsa.ExportPkcs8PrivateKey());

    /// <inheritdoc />
    public void Dispose() => Rsa.Dispose();

    /// <inheritdoc />
    public override string ToString() => $"VerifyBlindCallbackKey(pk_hash={PkHash})";
}

/// <summary>Pattern B decryption, exposed for custom flows. <c>VerifyCallbackAsync</c> uses it for you.</summary>
public static class CallbackCrypto
{
    /// <summary>
    /// Decrypts a pattern B <c>encrypted_response</c> with your callback private key.
    /// <list type="bullet">
    /// <item><c>enc_key</c>: RSA-OAEP-SHA256. The decrypted bytes are a base64 STRING; base64-decode it again to get the 32-byte AES key.</item>
    /// <item><c>blob</c>: IV (12 bytes) + ciphertext + tag (16 bytes), AES-256-GCM.</item>
    /// </list>
    /// The returned signature is NOT checked here: pass it to <c>VerifySignedAsync</c>.
    /// </summary>
    /// <exception cref="VerifyBlindException"><c>DECRYPT_FAILED</c>.</exception>
    public static SignedPayload DecryptCallbackResponse(string encKey, string blob, RSA privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        var wrapped = Base64.Decode(encKey) ?? throw DecryptFailed("enc_key is not base64");
        var data = Base64.Decode(blob) ?? throw DecryptFailed("blob is not base64");
        if (data.Length < 12 + 16) throw DecryptFailed("blob too short");

        byte[] plain;
        try
        {
            var aesKeyB64 = Encoding.UTF8.GetString(privateKey.Decrypt(wrapped, RSAEncryptionPadding.OaepSHA256));
            var aesKey = Base64.Decode(aesKeyB64) ?? throw DecryptFailed("unwrapped AES key is not base64");
            if (aesKey.Length != 32) throw DecryptFailed("unwrapped AES key is not 32 bytes");

            var iv = data.AsSpan(0, 12);
            var tag = data.AsSpan(data.Length - 16, 16);
            var cipher = data.AsSpan(12, data.Length - 12 - 16);
            plain = new byte[cipher.Length];
            using var gcm = new AesGcm(aesKey, 16);
            gcm.Decrypt(iv, cipher, tag, plain);
        }
        catch (CryptographicException)
        {
            throw DecryptFailed("wrong private key or tampered data");
        }

        return ParseSigned(plain) ?? throw DecryptFailed("decrypted body is not { payload, signature }");
    }

    // Only fixed texts reach the message, never decrypted content.
    private static VerifyBlindException DecryptFailed(string reason) =>
        new(VerifyBlindErrorCode.DecryptFailed, "could not decrypt encrypted_response: " + reason);

    /// <summary>Parses <c>{ "payload": string, "signature": string }</c>; <c>null</c> when it is not that shape. Never throws.</summary>
    internal static SignedPayload? ParseSigned(ReadOnlySpan<byte> json)
    {
        try
        {
            var reader = new Utf8JsonReader(json);
            using var doc = JsonDocument.ParseValue(ref reader);
            var root = doc.RootElement;
            if (root.ValueKind == JsonValueKind.Object
                && root.TryGetProperty("payload", out var p) && p.ValueKind == JsonValueKind.String
                && root.TryGetProperty("signature", out var s) && s.ValueKind == JsonValueKind.String)
                return new SignedPayload(p.GetString()!, s.GetString()!);
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
