using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;

namespace VerifyBlind.Server.Tests;

public class WebhookTests
{
    private const string RevokeBody = """{"nonce":"n-9","partner_id":"p-1","event_type":"CONSENT_WITHDRAWN"}""";

    private static (string Signature, string Timestamp) SignWebhook(Setup s, string body, RSA? key = null, long? ts = null)
    {
        var t = (ts ?? s.Time.Now.ToUnixTimeSeconds()).ToString();
        return (Sign.Pss(key ?? Keys.Webhook, $"{t}.{body}"), t);
    }

    [Fact]
    public async Task Valid_revoke_webhook_returns_the_body()
    {
        var s = new Setup();
        var (sig, ts) = SignWebhook(s, RevokeBody);
        var body = await s.Verifier.VerifyRevokeAsync(RevokeBody, sig, ts);
        Assert.Equal("n-9", body.Nonce);
        Assert.Equal("CONSENT_WITHDRAWN", body.GetString("event_type"));
    }

    [Fact]
    public async Task Raw_body_as_bytes_or_stream_works_the_same()
    {
        var s = new Setup();
        var (sig, ts) = SignWebhook(s, RevokeBody);
        Assert.Equal("n-9", (await s.Verifier.VerifyWebhookAsync(Encoding.UTF8.GetBytes(RevokeBody), sig, ts)).Nonce);
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(RevokeBody));
        Assert.Equal("n-9", (await s.Verifier.VerifyWebhookAsync(stream, sig, ts)).Nonce);
    }

    [Fact]
    public async Task Non_ascii_body_is_verified_over_its_exact_bytes()
    {
        var s = new Setup();
        const string body = """{"nonce":"n-9","reason":"kullanıcı iptal etti"}""";
        var (sig, ts) = SignWebhook(s, body);
        Assert.Equal("n-9", (await s.Verifier.VerifyWebhookAsync(Encoding.UTF8.GetBytes(body), sig, ts)).Nonce);
    }

    [Fact]
    public async Task Tampered_body_is_BAD_WEBHOOK_SIGNATURE()
    {
        var s = new Setup();
        var (sig, ts) = SignWebhook(s, RevokeBody);
        var e = await Assert.ThrowsAsync<VerifyBlindException>(() => s.Verifier.VerifyRevokeAsync(RevokeBody.Replace("n-9", "n-8"), sig, ts));
        Assert.Equal(VerifyBlindErrorCode.BadWebhookSignature, e.Code);
    }

    [Fact]
    public async Task Signature_over_a_different_timestamp_is_rejected()
    {
        var s = new Setup();
        var (sig, ts) = SignWebhook(s, RevokeBody);
        var other = (long.Parse(ts) + 1).ToString();
        var e = await Assert.ThrowsAsync<VerifyBlindException>(() => s.Verifier.VerifyRevokeAsync(RevokeBody, sig, other));
        Assert.Equal(VerifyBlindErrorCode.BadWebhookSignature, e.Code);
    }

    [Fact]
    public async Task Signature_with_salt_20_is_rejected()
    {
        var s = new Setup();
        var ts = s.Time.Now.ToUnixTimeSeconds().ToString();
        var sig = Sign.PssWithSalt(Keys.Webhook, $"{ts}.{RevokeBody}", 20);
        var e = await Assert.ThrowsAsync<VerifyBlindException>(() => s.Verifier.VerifyRevokeAsync(RevokeBody, sig, ts));
        Assert.Equal(VerifyBlindErrorCode.BadWebhookSignature, e.Code);
    }

    [Theory]
    [InlineData(301, false)]
    [InlineData(-301, false)]
    [InlineData(300, true)]
    [InlineData(-300, true)]
    public async Task Timestamp_window_is_300_s(int offset, bool ok)
    {
        var s = new Setup();
        var (sig, ts) = SignWebhook(s, RevokeBody, ts: s.Time.Now.ToUnixTimeSeconds() + offset);
        if (ok)
        {
            await s.Verifier.VerifyRevokeAsync(RevokeBody, sig, ts);
        }
        else
        {
            var e = await Assert.ThrowsAsync<VerifyBlindException>(() => s.Verifier.VerifyRevokeAsync(RevokeBody, sig, ts));
            Assert.Equal(VerifyBlindErrorCode.BadWebhookTimestamp, e.Code);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("-5")]
    [InlineData("1.5")]
    [InlineData("1234567890123456")]
    public async Task Missing_or_non_numeric_timestamp_is_BAD_WEBHOOK_TIMESTAMP(string? ts)
    {
        var s = new Setup();
        var e = await Assert.ThrowsAsync<VerifyBlindException>(() => s.Verifier.VerifyRevokeAsync(RevokeBody, "c2ln", ts));
        Assert.Equal(VerifyBlindErrorCode.BadWebhookTimestamp, e.Code);
        Assert.Empty(s.Api.Calls);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public async Task Missing_signature_is_BAD_WEBHOOK_SIGNATURE(string? sig)
    {
        var s = new Setup();
        var e = await Assert.ThrowsAsync<VerifyBlindException>(() => s.Verifier.VerifyRevokeAsync(RevokeBody, sig, s.Time.Now.ToUnixTimeSeconds().ToString()));
        Assert.Equal(VerifyBlindErrorCode.BadWebhookSignature, e.Code);
    }

    [Fact]
    public async Task Webhook_key_rotation_refreshes_once()
    {
        var s = new Setup();
        var (sig1, ts1) = SignWebhook(s, RevokeBody);
        await s.Verifier.VerifyRevokeAsync(RevokeBody, sig1, ts1);
        s.WebhookKey = Keys.EnclaveB;
        s.Time.Advance(TimeSpan.FromSeconds(30));
        var (sig2, ts2) = SignWebhook(s, RevokeBody, Keys.EnclaveB);
        await s.Verifier.VerifyRevokeAsync(RevokeBody, sig2, ts2);
        Assert.Equal(2, s.Api.Count(Setup.WebhookPath));
    }

    [Fact]
    public async Task Webhook_key_is_cached_for_an_hour()
    {
        var s = new Setup();
        for (var i = 0; i < 3; i++)
        {
            var (sig, ts) = SignWebhook(s, RevokeBody);
            await s.Verifier.VerifyRevokeAsync(RevokeBody, sig, ts);
            s.Time.Advance(TimeSpan.FromMinutes(20));
        }
        Assert.Equal(1, s.Api.Count(Setup.WebhookPath));
    }

    [Theory]
    [InlineData("""{"partner_id":"p"}""")]
    [InlineData("""{"nonce":""}""")]
    [InlineData("[1]")]
    [InlineData("not json")]
    public async Task Body_without_nonce_is_BAD_PAYLOAD(string body)
    {
        var s = new Setup();
        var (sig, ts) = SignWebhook(s, body);
        var e = await Assert.ThrowsAsync<VerifyBlindException>(() => s.Verifier.VerifyRevokeAsync(body, sig, ts));
        Assert.Equal(VerifyBlindErrorCode.BadPayload, e.Code);
    }

    [Fact]
    public async Task Webhook_key_endpoint_without_public_key_is_KEY_FETCH_FAILED()
    {
        var s = new Setup();
        s.Api.Routes[Setup.WebhookPath] = () => (HttpStatusCode.OK, """{"algorithm":"x"}""");
        var (sig, ts) = SignWebhook(s, RevokeBody);
        var e = await Assert.ThrowsAsync<VerifyBlindException>(() => s.Verifier.VerifyRevokeAsync(RevokeBody, sig, ts));
        Assert.Equal(VerifyBlindErrorCode.KeyFetchFailed, e.Code);
    }
}

public class CallbackTests
{
    private const string SecretUid = "UID_SECRET_7f3a";

    private static string SignedInner(string nonce)
    {
        var payload = JsonSerializer.Serialize(new { nonce, validations = new { age = true, age_condition = "18+", user_id = SecretUid } });
        return JsonSerializer.Serialize(new { payload, signature = Sign.Pss(Keys.EnclaveA, payload) });
    }

    private static string CompletedBody(string webhookNonce = "n-5", string? inner = null, RSA? partner = null)
    {
        var (encKey, blob) = Sign.EncryptForCallback(partner ?? Keys.Partner, inner ?? SignedInner(webhookNonce));
        return JsonSerializer.Serialize(new { nonce = webhookNonce, status = "completed", encrypted_response = new { enc_key = encKey, blob } });
    }

    private static (string Sig, string Ts) SignWebhook(Setup s, string body)
    {
        var ts = s.Time.Now.ToUnixTimeSeconds().ToString();
        return (Sign.Pss(Keys.Webhook, $"{ts}.{body}"), ts);
    }

    [Fact]
    public async Task Completed_callback_decrypts_and_verifies_the_enclave_signature()
    {
        var s = new Setup();
        var body = CompletedBody();
        var (sig, ts) = SignWebhook(s, body);
        var r = await s.Verifier.VerifyCallbackAsync(Encoding.UTF8.GetBytes(body), sig, ts, Keys.Partner);
        Assert.Equal(CallbackStatus.Completed, r.Status);
        Assert.Equal("n-5", r.Nonce);
        Assert.Equal(SecretUid, r.Verified!.Validations.UserId);

        var checkedOutcome = await s.Verifier.ConsumeAndCheckAsync(r.Verified, new MemoryStore().Add("n-5", """{"age":"18+","user_id":true}""").Consume);
        Assert.True(checkedOutcome.Ok, checkedOutcome.Error?.Message);
    }

    [Fact]
    public async Task Callback_key_from_pem_and_from_base64_pkcs8_both_work()
    {
        var s = new Setup();
        var body = CompletedBody();
        var (sig, ts) = SignWebhook(s, body);
        using var fromPem = VerifyBlindCallbackKey.Load(Keys.Partner.ExportPkcs8PrivateKeyPem());
        using var fromB64 = VerifyBlindCallbackKey.Load(Convert.ToBase64String(Keys.Partner.ExportPkcs8PrivateKey()));
        Assert.Equal(CallbackStatus.Completed, (await s.Verifier.VerifyCallbackAsync(body, sig, ts, fromPem)).Status);
        Assert.Equal(CallbackStatus.Completed, (await s.Verifier.VerifyCallbackAsync(body, sig, ts, fromB64)).Status);
        Assert.Equal(Keys.SpkiBase64(Keys.Partner), fromPem.PublicKeyBase64);
        Assert.Equal(64, fromPem.PkHash.Length);
        Assert.Equal(fromPem.PkHash, fromB64.PkHash);
        Assert.DoesNotContain(fromPem.ExportPkcs8Base64(), fromPem.ToString());
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a key")]
    [InlineData("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----")]
    public void Callback_key_rejects_non_private_keys(string text)
    {
        Assert.Throws<ArgumentException>(() => VerifyBlindCallbackKey.Load(text));
        Assert.Throws<ArgumentException>(() => VerifyBlindCallbackKey.Load(Keys.Partner.ExportSubjectPublicKeyInfoPem()));
    }

    [Fact]
    public async Task Cancelled_callback_returns_the_reason()
    {
        var s = new Setup();
        const string body = """{"nonce":"n-5","status":"cancelled","reason":"no_card_registered"}""";
        var (sig, ts) = SignWebhook(s, body);
        var r = await s.Verifier.VerifyCallbackAsync(body, sig, ts, VerifyBlindCallbackKey.Load(Keys.Partner.ExportPkcs8PrivateKeyPem()));
        Assert.Equal(CallbackStatus.Cancelled, r.Status);
        Assert.Equal("no_card_registered", r.Reason);
        Assert.Null(r.Verified);
        Assert.Equal(0, s.Api.Count(Setup.EnclavePath));
    }

    [Fact]
    public async Task Cancelled_callback_without_reason_defaults_to_user_cancelled()
    {
        var s = new Setup();
        const string body = """{"nonce":"n-5","status":"cancelled"}""";
        var (sig, ts) = SignWebhook(s, body);
        var r = await s.Verifier.VerifyCallbackAsync(Encoding.UTF8.GetBytes(body), sig, ts, Keys.Partner);
        Assert.Equal("user_cancelled", r.Reason);
    }

    [Fact]
    public async Task Signed_nonce_different_from_webhook_nonce_is_BAD_PAYLOAD()
    {
        var s = new Setup();
        var body = CompletedBody("n-5", SignedInner("n-other"));
        var (sig, ts) = SignWebhook(s, body);
        var e = await Assert.ThrowsAsync<VerifyBlindException>(() => s.Verifier.VerifyCallbackAsync(Encoding.UTF8.GetBytes(body), sig, ts, Keys.Partner));
        Assert.Equal(VerifyBlindErrorCode.BadPayload, e.Code);
    }

    [Fact]
    public async Task Inner_signature_from_another_key_is_BAD_SIGNATURE()
    {
        var s = new Setup();
        var payload = JsonSerializer.Serialize(new { nonce = "n-5", validations = new { age = true, age_condition = "18+" } });
        var inner = JsonSerializer.Serialize(new { payload, signature = Sign.Pss(Keys.EnclaveB, payload) });
        var body = CompletedBody("n-5", inner);
        var (sig, ts) = SignWebhook(s, body);
        var e = await Assert.ThrowsAsync<VerifyBlindException>(() => s.Verifier.VerifyCallbackAsync(Encoding.UTF8.GetBytes(body), sig, ts, Keys.Partner));
        Assert.Equal(VerifyBlindErrorCode.BadSignature, e.Code);
    }

    [Fact]
    public async Task Wrong_private_key_is_DECRYPT_FAILED()
    {
        var s = new Setup();
        var body = CompletedBody();
        var (sig, ts) = SignWebhook(s, body);
        var e = await Assert.ThrowsAsync<VerifyBlindException>(() => s.Verifier.VerifyCallbackAsync(Encoding.UTF8.GetBytes(body), sig, ts, Keys.OtherPartner));
        Assert.Equal(VerifyBlindErrorCode.DecryptFailed, e.Code);
    }

    [Fact]
    public async Task Missing_encrypted_response_is_DECRYPT_FAILED()
    {
        var s = new Setup();
        const string body = """{"nonce":"n-5","status":"completed"}""";
        var (sig, ts) = SignWebhook(s, body);
        var e = await Assert.ThrowsAsync<VerifyBlindException>(() => s.Verifier.VerifyCallbackAsync(Encoding.UTF8.GetBytes(body), sig, ts, Keys.Partner));
        Assert.Equal(VerifyBlindErrorCode.DecryptFailed, e.Code);
    }

    [Fact]
    public async Task Callback_webhook_signature_is_checked_before_decrypting()
    {
        var s = new Setup();
        var body = CompletedBody();
        var (sig, ts) = SignWebhook(s, body);
        var e = await Assert.ThrowsAsync<VerifyBlindException>(() => s.Verifier.VerifyCallbackAsync(Encoding.UTF8.GetBytes(body + " "), sig, ts, Keys.Partner));
        Assert.Equal(VerifyBlindErrorCode.BadWebhookSignature, e.Code);
        Assert.Equal(0, s.Api.Count(Setup.EnclavePath));
    }

    [Fact]
    public void DecryptCallbackResponse_rejects_a_tampered_blob()
    {
        var (encKey, blob) = Sign.EncryptForCallback(Keys.Partner, SignedInner("n-5"));
        var ok = CallbackCrypto.DecryptCallbackResponse(encKey, blob, Keys.Partner);
        Assert.Contains("n-5", ok.Payload);
        Assert.DoesNotContain(SecretUid, ok.ToString());

        var bytes = Convert.FromBase64String(blob);
        bytes[20] ^= 1;
        var e = Assert.Throws<VerifyBlindException>(() => CallbackCrypto.DecryptCallbackResponse(encKey, Convert.ToBase64String(bytes), Keys.Partner));
        Assert.Equal(VerifyBlindErrorCode.DecryptFailed, e.Code);
        Assert.Throws<VerifyBlindException>(() => CallbackCrypto.DecryptCallbackResponse(encKey, "AAAA", Keys.Partner));
        Assert.Throws<VerifyBlindException>(() => CallbackCrypto.DecryptCallbackResponse("!!", blob, Keys.Partner));
    }

    [Fact]
    public void Decrypted_body_that_is_not_payload_and_signature_is_DECRYPT_FAILED_without_content_in_the_message()
    {
        var (encKey, blob) = Sign.EncryptForCallback(Keys.Partner, $$"""{"user_id":"{{SecretUid}}"}""");
        var e = Assert.Throws<VerifyBlindException>(() => CallbackCrypto.DecryptCallbackResponse(encKey, blob, Keys.Partner));
        Assert.Equal(VerifyBlindErrorCode.DecryptFailed, e.Code);
        Assert.DoesNotContain(SecretUid, e.ToString());
    }
}

public class Pcr0Tests
{
    [Fact]
    public async Task PKCS1_signature_verifies_and_PSS_signature_does_not()
    {
        var s = new Setup();
        s.Api.Routes[Setup.DeveloperPath] = () => (HttpStatusCode.OK, Keys.PemJson(Keys.EnclaveB));
        const string pcr0 = "a1b2c3";
        var pkcs1 = Convert.ToBase64String(Keys.EnclaveB.SignData(Encoding.UTF8.GetBytes(pcr0), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.True(await s.Verifier.VerifyPcr0SignatureAsync(pcr0, pkcs1));
        Assert.False(await s.Verifier.VerifyPcr0SignatureAsync(pcr0, Sign.Pss(Keys.EnclaveB, pcr0)));
        Assert.False(await s.Verifier.VerifyPcr0SignatureAsync("a1b2c4", pkcs1));
        Assert.False(await s.Verifier.VerifyPcr0SignatureAsync("", pkcs1));
    }

    [Fact]
    public async Task Developer_key_fetch_failure_is_KEY_FETCH_FAILED()
    {
        var s = new Setup();
        var e = await Assert.ThrowsAsync<VerifyBlindException>(() => s.Verifier.VerifyPcr0SignatureAsync("a1", "AAAA"));
        Assert.Equal(VerifyBlindErrorCode.KeyFetchFailed, e.Code);
    }
}

public class DependencyInjectionTests
{
    [Fact]
    public void AddVerifyBlind_registers_one_singleton_for_both_types()
    {
        var services = new ServiceCollection();
        services.AddVerifyBlind(o => o.AllowTestCards = true);
        services.AddVerifyBlind(); // a second call does not add another registration
        using var sp = services.BuildServiceProvider();
        var a = sp.GetRequiredService<IVerifyBlindVerifier>();
        var b = sp.GetRequiredService<VerifyBlindVerifier>();
        Assert.Same(a, b);
        Assert.Single(services, d => d.ServiceType == typeof(VerifyBlindVerifier));
    }

    [Fact]
    public async Task AddVerifyBlind_uses_the_given_HttpClient()
    {
        var api = new FakeApi();
        api.Routes[Setup.EnclavePath] = () => (HttpStatusCode.OK, Keys.SpkiBase64(Keys.EnclaveA));
        var services = new ServiceCollection();
        services.AddVerifyBlind(o => o.ApiBaseUrl = Setup.Base, _ => new HttpClient(api));
        using var sp = services.BuildServiceProvider();
        var verifier = sp.GetRequiredService<IVerifyBlindVerifier>();
        var r = await verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveA, new { nonce = "n" }));
        Assert.Equal("n", r.Nonce);
        Assert.Equal(1, api.Count(Setup.EnclavePath));
    }

    [Theory]
    [InlineData("not a url")]
    [InlineData("ftp://api.verifyblind.com")]
    public void Invalid_options_fail_at_registration(string url) =>
        Assert.Throws<ArgumentException>(() => new ServiceCollection().AddVerifyBlind(o => o.ApiBaseUrl = url));

    [Fact]
    public void Error_codes_have_suggested_http_statuses()
    {
        Assert.Equal(400, VerifyBlindErrorCode.SuggestedHttpStatus(VerifyBlindErrorCode.BadToken));
        Assert.Equal(401, VerifyBlindErrorCode.SuggestedHttpStatus(VerifyBlindErrorCode.BadSignature));
        Assert.Equal(503, VerifyBlindErrorCode.SuggestedHttpStatus(VerifyBlindErrorCode.KeyFetchFailed));
        Assert.Equal(400, VerifyBlindErrorCode.SuggestedHttpStatus(VerifyBlindErrorCode.BadPayload));
        Assert.Equal(401, VerifyBlindErrorCode.SuggestedHttpStatus(VerifyBlindErrorCode.NonceNotFound));
        Assert.Equal(401, VerifyBlindErrorCode.SuggestedHttpStatus(VerifyBlindErrorCode.AskedMismatch));
        Assert.Equal(401, VerifyBlindErrorCode.SuggestedHttpStatus(VerifyBlindErrorCode.BadWebhookTimestamp));
        Assert.Equal(401, VerifyBlindErrorCode.SuggestedHttpStatus(VerifyBlindErrorCode.BadWebhookSignature));
        Assert.Equal(400, VerifyBlindErrorCode.SuggestedHttpStatus(VerifyBlindErrorCode.DecryptFailed));
        Assert.Equal(403, VerifyBlindErrorCode.SuggestedHttpStatus(VerifyBlindErrorCode.TestCard));
    }
}
