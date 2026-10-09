using System.Security.Cryptography;
using System.Text.Json;

namespace VerifyBlind.Server.Internal;

internal static class Crypto
{
    /// <summary>
    /// Enclave result and webhook signatures: RSA-PSS, SHA-256, MGF1-SHA-256, salt length 32.
    /// .NET's <see cref="RSASignaturePadding.Pss"/> uses MGF1 with the signing hash and a salt as long as
    /// the hash (32 bytes for SHA-256), and verification requires exactly that salt length.
    /// </summary>
    public static bool VerifyPss(ReadOnlySpan<byte> data, byte[] signature, byte[] spki) =>
        Verify(data, signature, spki, RSASignaturePadding.Pss);

    /// <summary>PCR0 authorization signature: RSA PKCS#1 v1.5 (NOT PSS), SHA-256.</summary>
    public static bool VerifyPkcs1(ReadOnlySpan<byte> data, byte[] signature, byte[] spki) =>
        Verify(data, signature, spki, RSASignaturePadding.Pkcs1);

    private static bool Verify(ReadOnlySpan<byte> data, byte[] signature, byte[] spki, RSASignaturePadding padding)
    {
        if (signature.Length == 0) return false;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(spki, out _);
            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, padding);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary><c>GET /api/public/enclave-key</c> returns base64 SPKI as plain text.</summary>
    public static byte[] ParseSpkiBase64(string text)
    {
        var der = Base64.Decode(text) ?? throw new FormatException("enclave key is not base64");
        return NormalizeRsaSpki(der);
    }

    /// <summary><c>GET /api/public/webhook-signing-key</c> and <c>/developer-key</c> return JSON <c>{ "public_key": "&lt;PEM&gt;" }</c>.</summary>
    public static byte[] ParsePemFromJson(string text)
    {
        using var doc = JsonDocument.Parse(text);
        if (doc.RootElement.ValueKind != JsonValueKind.Object
            || !doc.RootElement.TryGetProperty("public_key", out var pk)
            || pk.ValueKind != JsonValueKind.String)
            throw new FormatException("public_key missing");
        var pem = pk.GetString()!;
        if (!pem.Contains("BEGIN PUBLIC KEY", StringComparison.Ordinal)) throw new FormatException("public_key is not a PEM public key");
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa.ExportSubjectPublicKeyInfo();
    }

    /// <summary>Checks that the bytes are an RSA SPKI and returns them re-exported.</summary>
    private static byte[] NormalizeRsaSpki(byte[] der)
    {
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(der, out _);
        return rsa.ExportSubjectPublicKeyInfo();
    }
}

internal static class Base64
{
    /// <summary>Strict base64 that also accepts the URL-safe alphabet, whitespace and missing padding. <c>null</c> when invalid.</summary>
    public static byte[]? Decode(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var chars = new char[value.Length + 3];
        var n = 0;
        foreach (var c in value)
        {
            if (char.IsWhiteSpace(c)) continue;
            chars[n++] = c switch { '-' => '+', '_' => '/', _ => c };
        }
        while (n % 4 != 0) chars[n++] = '=';
        try
        {
            return Convert.FromBase64CharArray(chars, 0, n);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
