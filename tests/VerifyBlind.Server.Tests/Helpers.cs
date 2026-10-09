using System.Collections.Concurrent;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace VerifyBlind.Server.Tests;

/// <summary>RSA-2048 key pairs generated once per test run (generation is slow).</summary>
internal static class Keys
{
    public static readonly RSA EnclaveA = Make();
    public static readonly RSA EnclaveB = Make();
    public static readonly RSA Webhook = Make();
    public static readonly RSA Partner = Make();
    public static readonly RSA OtherPartner = Make();

    /// <summary>RSA.Create(2048) generates the key lazily on first use; parallel tests could race to generate two.</summary>
    private static RSA Make()
    {
        var rsa = RSA.Create(2048);
        rsa.ExportParameters(includePrivateParameters: false);
        return rsa;
    }

    /// <summary>Base64 SPKI text, as <c>GET /api/public/enclave-key</c> returns it.</summary>
    public static string SpkiBase64(RSA key) => Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

    /// <summary>JSON with a PEM, as <c>/api/public/webhook-signing-key</c> and <c>/developer-key</c> return it.</summary>
    public static string PemJson(RSA key) =>
        JsonSerializer.Serialize(new { algorithm = "RSA-PSS-SHA256", public_key = key.ExportSubjectPublicKeyInfoPem() });
}

internal static class Sign
{
    /// <summary>Like the enclave: "18+" stays "18+" (the default encoder would write "+" as a \u escape).</summary>
    public static readonly JsonSerializerOptions Json = new() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>RSA-PSS SHA-256 with salt 32 through the platform (what the enclave does).</summary>
    public static string Pss(RSA key, byte[] data) =>
        Convert.ToBase64String(key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

    public static string Pss(RSA key, string data) => Pss(key, Encoding.UTF8.GetBytes(data));

    /// <summary>
    /// RSA-PSS SHA-256 / MGF1-SHA-256 with ANY salt length (RFC 8017 EMSA-PSS + raw RSA). .NET can only sign
    /// with salt = hash length, so a wrong-salt signature has to be built by hand.
    /// </summary>
    public static string PssWithSalt(RSA key, string data, int saltLength)
    {
        var p = key.ExportParameters(includePrivateParameters: true);
        var modBits = (int)new BigInteger(p.Modulus, isUnsigned: true, isBigEndian: true).GetBitLength();
        var emBits = modBits - 1;
        var emLen = (emBits + 7) / 8;
        const int hLen = 32;

        var mHash = SHA256.HashData(Encoding.UTF8.GetBytes(data));
        var salt = RandomNumberGenerator.GetBytes(saltLength);
        var mPrime = new byte[8 + hLen + saltLength];
        mHash.CopyTo(mPrime, 8);
        salt.CopyTo(mPrime, 8 + hLen);
        var h = SHA256.HashData(mPrime);

        var db = new byte[emLen - hLen - 1];
        db[emLen - saltLength - hLen - 2] = 0x01;
        salt.CopyTo(db, emLen - saltLength - hLen - 1);
        var mask = Mgf1(h, db.Length);
        for (var i = 0; i < db.Length; i++) db[i] ^= mask[i];
        db[0] &= (byte)(0xFF >> (8 * emLen - emBits));

        var em = new byte[emLen];
        db.CopyTo(em, 0);
        h.CopyTo(em, db.Length);
        em[^1] = 0xBC;

        var n = new BigInteger(p.Modulus, isUnsigned: true, isBigEndian: true);
        var d = new BigInteger(p.D, isUnsigned: true, isBigEndian: true);
        var s = BigInteger.ModPow(new BigInteger(em, isUnsigned: true, isBigEndian: true), d, n)
            .ToByteArray(isUnsigned: true, isBigEndian: true);
        var k = p.Modulus!.Length;
        var sig = new byte[k];
        s.CopyTo(sig, k - s.Length);
        return Convert.ToBase64String(sig);
    }

    private static byte[] Mgf1(byte[] seed, int length)
    {
        var output = new byte[length];
        var counter = new byte[4];
        for (int offset = 0, c = 0; offset < length; c++)
        {
            counter[0] = (byte)(c >> 24); counter[1] = (byte)(c >> 16); counter[2] = (byte)(c >> 8); counter[3] = (byte)c;
            var block = SHA256.HashData([.. seed, .. counter]);
            var take = Math.Min(block.Length, length - offset);
            Array.Copy(block, 0, output, offset, take);
            offset += take;
        }
        return output;
    }

    /// <summary>Builds a token exactly like the widget / SDK: base64(JSON { payload, signature }).</summary>
    public static string Token(RSA key, object payload, int? saltLength = null)
    {
        var json = payload as string ?? JsonSerializer.Serialize(payload, Json);
        var signature = saltLength is null ? Pss(key, json) : PssWithSalt(key, json, saltLength.Value);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { payload = json, signature })));
    }

    /// <summary>Encrypts like the enclave for pattern B: OAEP-SHA256-wrapped base64 AES key + AES-256-GCM blob.</summary>
    public static (string EncKey, string Blob) EncryptForCallback(RSA partnerPublic, string innerJson)
    {
        var aesKey = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(12);
        var plain = Encoding.UTF8.GetBytes(innerJson);
        var cipher = new byte[plain.Length];
        var tag = new byte[16];
        using (var gcm = new AesGcm(aesKey, 16)) gcm.Encrypt(iv, plain, cipher, tag);
        var encKey = partnerPublic.Encrypt(Encoding.UTF8.GetBytes(Convert.ToBase64String(aesKey)), RSAEncryptionPadding.OaepSHA256);
        return (Convert.ToBase64String(encKey), Convert.ToBase64String([.. iv, .. cipher, .. tag]));
    }
}

/// <summary>Fake API: <c>Routes[path]</c> returns (status, body) and may change between calls.</summary>
internal sealed class FakeApi : HttpMessageHandler
{
    public readonly ConcurrentDictionary<string, Func<(HttpStatusCode Status, string Body)>> Routes = new();
    public readonly ConcurrentQueue<Uri> Calls = new();
    public TimeSpan Delay { get; set; }

    public int Count(string path) => Calls.Count(u => u.AbsolutePath == path);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Calls.Enqueue(request.RequestUri!);
        if (Delay > TimeSpan.Zero) await Task.Delay(Delay, cancellationToken);
        if (!Routes.TryGetValue(request.RequestUri!.AbsolutePath, out var route))
            return new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("not found") };
        var (status, body) = route();
        return new HttpResponseMessage(status) { Content = new StringContent(body) };
    }
}

internal sealed class FakeTime : TimeProvider
{
    public DateTimeOffset Now { get; set; } = new(2026, 10, 10, 12, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => Now;

    public void Advance(TimeSpan by) => Now += by;
}

/// <summary>A dictionary-backed get-and-delete nonce store.</summary>
internal sealed class MemoryStore
{
    private readonly ConcurrentDictionary<string, string> _items = new();
    public readonly List<string> Calls = [];

    public MemoryStore Add(string nonce, string askedJson)
    {
        _items[nonce] = askedJson;
        return this;
    }

    public Task<string?> Consume(string nonce)
    {
        lock (Calls) Calls.Add(nonce);
        return Task.FromResult(_items.TryRemove(nonce, out var v) ? v : null);
    }
}

/// <summary>A verifier wired to a fake API and a fake clock.</summary>
internal sealed class Setup
{
    public const string Base = "https://api.test";
    public const string EnclavePath = "/api/public/enclave-key";
    public const string WebhookPath = "/api/public/webhook-signing-key";
    public const string DeveloperPath = "/api/public/developer-key";

    public readonly FakeApi Api = new();
    public readonly FakeTime Time = new();
    public RSA EnclaveKey = Keys.EnclaveA;
    public RSA WebhookKey = Keys.Webhook;
    public readonly VerifyBlindVerifier Verifier;

    public Setup(Action<VerifyBlindOptions>? configure = null)
    {
        Api.Routes[EnclavePath] = () => (HttpStatusCode.OK, Keys.SpkiBase64(EnclaveKey));
        Api.Routes[WebhookPath] = () => (HttpStatusCode.OK, Keys.PemJson(WebhookKey));
        var options = new VerifyBlindOptions { ApiBaseUrl = Base, TimeProvider = Time };
        configure?.Invoke(options);
        Verifier = new VerifyBlindVerifier(options, new HttpClient(Api));
    }
}
