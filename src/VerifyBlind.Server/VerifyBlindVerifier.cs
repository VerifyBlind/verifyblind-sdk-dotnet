using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VerifyBlind.Server.Internal;

namespace VerifyBlind.Server;

/// <summary>
/// Verifies VerifyBlind result tokens, webhooks and callbacks. Keep one instance (or register it with
/// <c>services.AddVerifyBlind()</c>): it caches the public keys and is thread-safe.
/// </summary>
/// <remarks>
/// Contract: https://verifyblind.com/ai-integration.md. Signatures are RSA-PSS, SHA-256, MGF1-SHA-256, salt 32.
/// Nothing here logs, and no error message contains <c>user_id</c>, <c>nsbd_id</c> or <c>doc_id</c>.
/// </remarks>
public sealed class VerifyBlindVerifier : IVerifyBlindVerifier
{
    private const string EnclaveKeyPath = "/api/public/enclave-key";
    private const string WebhookKeyPath = "/api/public/webhook-signing-key";
    private const string DeveloperKeyPath = "/api/public/developer-key";

    // One shared client for verifiers that were not given one. PooledConnectionLifetime picks up DNS changes.
    private static readonly Lazy<HttpClient> SharedHttpClient = new(() => new HttpClient(
        new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5), AllowAutoRedirect = false })
    {
        Timeout = Timeout.InfiniteTimeSpan, // per-request timeout below (VerifyBlindOptions.HttpTimeout)
    });

    private readonly VerifyBlindOptions _options;
    private readonly HttpClient _http;
    private readonly KeyCache _enclaveKey;
    private readonly KeyCache _webhookKey;
    private readonly KeyCache _developerKey;

    /// <summary>Creates a verifier.</summary>
    /// <param name="options">Settings; <c>null</c> = production defaults.</param>
    /// <param name="httpClient">
    /// Your <see cref="HttpClient"/> (proxy, handler, tests). <c>null</c> = a shared client of this library.
    /// Its <c>BaseAddress</c> is not used: requests go to <see cref="VerifyBlindOptions.ApiBaseUrl"/>.
    /// </param>
    public VerifyBlindVerifier(VerifyBlindOptions? options = null, HttpClient? httpClient = null)
    {
        _options = (options ?? new VerifyBlindOptions()).Validated();
        _http = httpClient ?? SharedHttpClient.Value;
        var time = _options.TimeProvider;
        _enclaveKey = new KeyCache(ct => LoadKeyAsync(EnclaveKeyPath, Crypto.ParseSpkiBase64, ct),
            _options.KeyCacheDuration, _options.KeyRefreshMinInterval, time);
        _webhookKey = new KeyCache(ct => LoadKeyAsync(WebhookKeyPath, Crypto.ParsePemFromJson, ct),
            _options.WebhookKeyCacheDuration, _options.KeyRefreshMinInterval, time);
        _developerKey = new KeyCache(ct => LoadKeyAsync(DeveloperKeyPath, Crypto.ParsePemFromJson, ct),
            _options.WebhookKeyCacheDuration, _options.KeyRefreshMinInterval, time);
    }

    /// <summary>
    /// Reads the signed validations against what YOUR server asked for this nonce (never against what the browser
    /// or app says). Returns a rejection reason, or <c>null</c> when they match.
    /// <list type="bullet">
    /// <item>Age asked: <c>age</c> must be a boolean AND <c>age_condition</c> must equal the asked condition
    /// (a visitor who edits <c>"18+"</c> to <c>"1+"</c> gets a genuinely signed <c>age: true</c> — for <c>"1+"</c>).</item>
    /// <item>Age not asked: neither <c>age</c> nor <c>age_condition</c> may be present.</item>
    /// <item><c>user_id</c> asked: a non-empty <c>user_id</c> must be present.</item>
    /// </list>
    /// The reason never contains identity codes.
    /// </summary>
    public static string? CheckAsked(VerifyBlindAsked? asked, VerifyBlindValidations? validations)
    {
        var a = asked ?? new VerifyBlindAsked();
        var v = (validations ?? VerifyBlindValidations.Empty).Raw;

        if (a.Age is null)
        {
            if (v.TryGetProperty("age", out _)) return "age result present although age was not asked";
            if (v.TryGetProperty("age_condition", out _)) return "age_condition present although age was not asked";
        }
        else
        {
            if (a.Age.Length == 0) return "the stored age condition is empty";
            if (!v.TryGetProperty("age", out var age) || age.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                return "age result missing";
            if (!v.TryGetProperty("age_condition", out var cond) || cond.ValueKind != JsonValueKind.String)
                return $"age_condition missing (expected {a.Age})";
            var answered = cond.GetString();
            if (!string.Equals(answered, a.Age, StringComparison.Ordinal))
                return $"age_condition does not match the asked condition (expected {a.Age}, got {answered})";
        }

        if (a.UserId && (!v.TryGetProperty("user_id", out var uid) || uid.ValueKind != JsonValueKind.String || uid.GetString()!.Length == 0))
            return "user_id missing although it was asked";

        return null;
    }

    /// <inheritdoc />
    public Task<VerifyBlindOutcome> VerifyAndConsumeAsync(string? token, Func<string, Task<string?>> consumeNonce, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(consumeNonce);
        return VerifyAndConsumeCoreAsync(token, nonce => ReadStoredJsonAsync(consumeNonce, nonce), cancellationToken);
    }

    /// <inheritdoc />
    public Task<VerifyBlindOutcome> VerifyAndConsumeAsync(string? token, Func<string, Task<VerifyBlindAsked?>> consumeNonce, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(consumeNonce);
        return VerifyAndConsumeCoreAsync(token, nonce => ReadStoredAskedAsync(consumeNonce, nonce), cancellationToken);
    }

    /// <inheritdoc />
    public Task<VerifyBlindOutcome> ConsumeAndCheckAsync(VerifiedResult verified, Func<string, Task<string?>> consumeNonce)
    {
        ArgumentNullException.ThrowIfNull(consumeNonce);
        return ConsumeAndCheckCoreAsync(verified, nonce => ReadStoredJsonAsync(consumeNonce, nonce));
    }

    /// <inheritdoc />
    public Task<VerifyBlindOutcome> ConsumeAndCheckAsync(VerifiedResult verified, Func<string, Task<VerifyBlindAsked?>> consumeNonce)
    {
        ArgumentNullException.ThrowIfNull(consumeNonce);
        return ConsumeAndCheckCoreAsync(verified, nonce => ReadStoredAskedAsync(consumeNonce, nonce));
    }

    /// <inheritdoc />
    public async Task<VerifiedResult> VerifyTokenAsync(string? token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new VerifyBlindException(VerifyBlindErrorCode.BadToken, "token must be a non-empty string");
        var json = Base64.Decode(token);
        var signed = json is null ? null : CallbackCrypto.ParseSigned(json);
        if (signed is null)
            throw new VerifyBlindException(VerifyBlindErrorCode.BadToken, "token is not base64 of JSON { payload, signature }");
        return await VerifySignedAsync(signed, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<VerifiedResult> VerifySignedAsync(SignedPayload signed, CancellationToken cancellationToken = default)
    {
        if (signed is null || string.IsNullOrEmpty(signed.Payload) || string.IsNullOrEmpty(signed.Signature))
            throw new VerifyBlindException(VerifyBlindErrorCode.BadToken, "payload and signature must be non-empty strings");

        var data = Encoding.UTF8.GetBytes(signed.Payload);
        var signature = Base64.Decode(signed.Signature) ?? [];
        var ok = await VerifyWithRefreshAsync(_enclaveKey, key => Crypto.VerifyPss(data, signature, key), cancellationToken).ConfigureAwait(false);
        if (!ok) throw new VerifyBlindException(VerifyBlindErrorCode.BadSignature, "enclave signature is not valid");

        var payload = ParseObject(data) ?? throw new VerifyBlindException(VerifyBlindErrorCode.BadPayload, "signed payload is not a JSON object");
        if (!payload.TryGetProperty("nonce", out var n) || n.ValueKind != JsonValueKind.String || n.GetString()!.Length == 0)
            throw new VerifyBlindException(VerifyBlindErrorCode.BadPayload, "signed payload has no nonce");

        var validations = payload.TryGetProperty("validations", out var v) && v.ValueKind == JsonValueKind.Object
            ? new VerifyBlindValidations(v)
            : VerifyBlindValidations.Empty;
        return new VerifiedResult(n.GetString()!, validations, payload, signed.Payload);
    }

    /// <inheritdoc />
    public async Task<WebhookBody> VerifyWebhookAsync(ReadOnlyMemory<byte> rawBody, string? signature, string? timestamp, CancellationToken cancellationToken = default)
    {
        var ts = timestamp?.Trim() ?? "";
        if (ts.Length is 0 or > 15 || !ts.All(char.IsAsciiDigit))
            throw new VerifyBlindException(VerifyBlindErrorCode.BadWebhookTimestamp, "X-Webhook-Timestamp missing or not Unix seconds");
        var tolerance = (long)_options.WebhookTolerance.TotalSeconds;
        var now = _options.TimeProvider.GetUtcNow().ToUnixTimeSeconds();
        if (Math.Abs(now - long.Parse(ts, NumberStyles.None, CultureInfo.InvariantCulture)) > tolerance)
            throw new VerifyBlindException(VerifyBlindErrorCode.BadWebhookTimestamp, $"X-Webhook-Timestamp is outside ±{tolerance} s");
        if (string.IsNullOrWhiteSpace(signature))
            throw new VerifyBlindException(VerifyBlindErrorCode.BadWebhookSignature, "X-Webhook-Signature missing");

        var prefix = Encoding.ASCII.GetBytes(ts + ".");
        var signedBytes = new byte[prefix.Length + rawBody.Length];
        prefix.CopyTo(signedBytes, 0);
        rawBody.Span.CopyTo(signedBytes.AsSpan(prefix.Length));
        var sig = Base64.Decode(signature) ?? [];
        var ok = await VerifyWithRefreshAsync(_webhookKey, key => Crypto.VerifyPss(signedBytes, sig, key), cancellationToken).ConfigureAwait(false);
        if (!ok) throw new VerifyBlindException(VerifyBlindErrorCode.BadWebhookSignature, "webhook signature is not valid");

        var body = ParseObject(rawBody.Span) ?? throw new VerifyBlindException(VerifyBlindErrorCode.BadPayload, "webhook body is not a JSON object");
        if (!body.TryGetProperty("nonce", out var n) || n.ValueKind != JsonValueKind.String || n.GetString()!.Length == 0)
            throw new VerifyBlindException(VerifyBlindErrorCode.BadPayload, "webhook body has no nonce");
        return new WebhookBody(n.GetString()!, body);
    }

    /// <inheritdoc />
    public Task<WebhookBody> VerifyRevokeAsync(ReadOnlyMemory<byte> rawBody, string? signature, string? timestamp, CancellationToken cancellationToken = default) =>
        VerifyWebhookAsync(rawBody, signature, timestamp, cancellationToken);

    /// <inheritdoc />
    public async Task<CallbackResult> VerifyCallbackAsync(ReadOnlyMemory<byte> rawBody, string? signature, string? timestamp, RSA privateKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        var body = await VerifyWebhookAsync(rawBody, signature, timestamp, cancellationToken).ConfigureAwait(false);

        if (body.GetString("status") == "cancelled")
        {
            var reason = body.GetString("reason");
            return new CallbackResult(CallbackStatus.Cancelled, body.Nonce, string.IsNullOrEmpty(reason) ? "user_cancelled" : reason, null, body);
        }

        if (!body.Json.TryGetProperty("encrypted_response", out var enc) || enc.ValueKind != JsonValueKind.Object
            || !enc.TryGetProperty("enc_key", out var encKey) || encKey.ValueKind != JsonValueKind.String
            || !enc.TryGetProperty("blob", out var blob) || blob.ValueKind != JsonValueKind.String)
            throw new VerifyBlindException(VerifyBlindErrorCode.DecryptFailed, "could not decrypt encrypted_response: encrypted_response must have enc_key and blob strings");

        var inner = CallbackCrypto.DecryptCallbackResponse(encKey.GetString()!, blob.GetString()!, privateKey);
        var verified = await VerifySignedAsync(inner, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(verified.Nonce, body.Nonce, StringComparison.Ordinal))
            throw new VerifyBlindException(VerifyBlindErrorCode.BadPayload, "signed nonce does not match the webhook nonce");
        return new CallbackResult(CallbackStatus.Completed, body.Nonce, null, verified, body);
    }

    /// <inheritdoc />
    public async Task<bool> VerifyPcr0SignatureAsync(string pcr0Hex, string pcr0SignatureBase64, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(pcr0Hex) || string.IsNullOrEmpty(pcr0SignatureBase64)) return false;
        var data = Encoding.UTF8.GetBytes(pcr0Hex);
        var sig = Base64.Decode(pcr0SignatureBase64) ?? [];
        return await VerifyWithRefreshAsync(_developerKey, key => Crypto.VerifyPkcs1(data, sig, key), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public void ClearKeyCache()
    {
        _enclaveKey.Clear();
        _webhookKey.Clear();
        _developerKey.Clear();
    }

    private async Task<VerifyBlindOutcome> VerifyAndConsumeCoreAsync(string? token, Func<string, Task<StoredAsked>> consume, CancellationToken cancellationToken)
    {
        VerifiedResult verified;
        try
        {
            verified = await VerifyTokenAsync(token, cancellationToken).ConfigureAwait(false);
        }
        catch (VerifyBlindException e)
        {
            return VerifyBlindOutcome.Failure(e);
        }
        return await ConsumeAndCheckCoreAsync(verified, consume).ConfigureAwait(false);
    }

    private async Task<VerifyBlindOutcome> ConsumeAndCheckCoreAsync(VerifiedResult verified, Func<string, Task<StoredAsked>> consume)
    {
        ArgumentNullException.ThrowIfNull(verified);
        var stored = await consume(verified.Nonce).ConfigureAwait(false);
        if (!stored.Found)
            return VerifyBlindOutcome.Failure(new VerifyBlindException(VerifyBlindErrorCode.NonceNotFound, "nonce is unknown, expired or already used"));
        if (verified.IsTest && !_options.AllowTestCards)
            return VerifyBlindOutcome.Failure(new VerifyBlindException(VerifyBlindErrorCode.TestCard, "demo-card result; set AllowTestCards on test setups only"));
        if (stored.Asked is null)
        {
            // Fail closed: if we cannot read what we asked, we cannot read the answer.
            return VerifyBlindOutcome.Failure(new VerifyBlindException(VerifyBlindErrorCode.AskedMismatch, "stored asked validations are unreadable"));
        }
        var mismatch = CheckAsked(stored.Asked, verified.Validations);
        if (mismatch is not null)
            return VerifyBlindOutcome.Failure(new VerifyBlindException(VerifyBlindErrorCode.AskedMismatch, mismatch));
        return VerifyBlindOutcome.Success(verified, stored.Asked);
    }

    /// <summary>Found = the store returned something for the nonce; Asked = null when that something is unreadable.</summary>
    private readonly record struct StoredAsked(bool Found, VerifyBlindAsked? Asked);

    private static async Task<StoredAsked> ReadStoredJsonAsync(Func<string, Task<string?>> consumeNonce, string nonce)
    {
        var json = await consumeNonce(nonce).ConfigureAwait(false);
        if (string.IsNullOrEmpty(json)) return new StoredAsked(false, null);
        return new StoredAsked(true, VerifyBlindAsked.TryParse(json, out var asked) ? asked : null);
    }

    private static async Task<StoredAsked> ReadStoredAskedAsync(Func<string, Task<VerifyBlindAsked?>> consumeNonce, string nonce)
    {
        var asked = await consumeNonce(nonce).ConfigureAwait(false);
        return new StoredAsked(asked is not null, asked);
    }

    /// <summary>Verify with the cached key; on failure refresh once (the key rotates on enclave restart) and retry.</summary>
    private static async Task<bool> VerifyWithRefreshAsync(KeyCache cache, Func<byte[], bool> check, CancellationToken cancellationToken)
    {
        var (key, fresh) = await cache.GetAsync(cancellationToken).ConfigureAwait(false);
        if (check(key)) return true;
        if (fresh) return false;
        var refreshed = await cache.RefreshAsync(key, cancellationToken).ConfigureAwait(false);
        return refreshed is not null && check(refreshed);
    }

    private async Task<byte[]> LoadKeyAsync(string path, Func<string, byte[]> parse, CancellationToken cancellationToken)
    {
        string text;
        using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            cts.CancelAfter(_options.HttpTimeout);
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, _options.ApiBaseUrl + path);
                using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseContentRead, cts.Token).ConfigureAwait(false);
                if (response.StatusCode != HttpStatusCode.OK)
                    throw new VerifyBlindException(VerifyBlindErrorCode.KeyFetchFailed, $"GET {path} returned HTTP {(int)response.StatusCode}");
                text = await response.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            }
            catch (Exception e) when (e is HttpRequestException or OperationCanceledException or IOException)
            {
                throw new VerifyBlindException(VerifyBlindErrorCode.KeyFetchFailed, $"GET {path} failed", e);
            }
        }
        try
        {
            return parse(text);
        }
        catch (Exception e) when (e is FormatException or JsonException or CryptographicException or ArgumentException)
        {
            throw new VerifyBlindException(VerifyBlindErrorCode.KeyFetchFailed, $"GET {path} returned an unusable key", e);
        }
    }

    /// <summary>Parses a JSON object; <c>null</c> for anything else. Never throws: parser messages could quote identity codes.</summary>
    private static JsonElement? ParseObject(ReadOnlySpan<byte> utf8)
    {
        try
        {
            var reader = new Utf8JsonReader(utf8);
            using var doc = JsonDocument.ParseValue(ref reader);
            return doc.RootElement.ValueKind == JsonValueKind.Object ? doc.RootElement.Clone() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
