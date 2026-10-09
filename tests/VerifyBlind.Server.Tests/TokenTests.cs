using System.Net;
using System.Text;
using System.Text.Json;

namespace VerifyBlind.Server.Tests;

public class TokenTests
{
    private const string SecretUid = "UID_SECRET_7f3a";
    private static readonly object GoodPayload = new
    {
        nonce = "n-1",
        validations = new { age = true, age_condition = "18+", user_id = SecretUid, nsbd_id = "NSBD_SECRET", doc_id = "DOC_SECRET" },
        additional_data = new { order = 42 },
    };

    private static async Task<VerifyBlindException> Fails(Func<Task> act)
    {
        var e = await Assert.ThrowsAsync<VerifyBlindException>(act);
        return e;
    }

    [Fact]
    public async Task Valid_token_verifies_and_returns_the_parsed_payload()
    {
        var s = new Setup();
        var r = await s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveA, GoodPayload));
        Assert.Equal("n-1", r.Nonce);
        Assert.True(r.Validations.Age);
        Assert.Equal("18+", r.Validations.AgeCondition);
        Assert.Equal(SecretUid, r.Validations.UserId);
        Assert.Equal("NSBD_SECRET", r.Validations.NsbdId);
        Assert.Equal("DOC_SECRET", r.Validations.DocId);
        Assert.False(r.IsTest);
        Assert.Equal(42, r.AdditionalData!.Value.GetProperty("order").GetInt32());
        Assert.Contains("\"nonce\":\"n-1\"", r.RawPayload);
    }

    [Fact]
    public async Task Uses_the_production_api_by_default_and_honours_ApiBaseUrl()
    {
        Assert.Equal("https://api.verifyblind.com", new VerifyBlindOptions().ApiBaseUrl);
        var s = new Setup(o => o.ApiBaseUrl = Setup.Base + "/");
        await s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveA, GoodPayload));
        Assert.Equal("https://api.test/api/public/enclave-key", Assert.Single(s.Api.Calls).ToString());
    }

    [Fact]
    public async Task Url_safe_base64_without_padding_is_accepted()
    {
        var s = new Setup();
        var token = Sign.Token(Keys.EnclaveA, GoodPayload).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        Assert.Equal("n-1", (await s.Verifier.VerifyTokenAsync(token)).Nonce);
    }

    [Fact]
    public async Task Tampered_payload_is_BAD_SIGNATURE()
    {
        var s = new Setup();
        var token = Sign.Token(Keys.EnclaveA, GoodPayload);
        var signed = JsonDocument.Parse(Convert.FromBase64String(token)).RootElement;
        var tampered = signed.GetProperty("payload").GetString()!.Replace("18+", "1+");
        var forged = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { payload = tampered, signature = signed.GetProperty("signature").GetString() })));
        Assert.Equal(VerifyBlindErrorCode.BadSignature, (await Fails(() => s.Verifier.VerifyTokenAsync(forged))).Code);
    }

    [Fact]
    public async Task Hand_built_PSS_with_salt_32_verifies()
    {
        // Proves the hand-built signer below is correct, so the wrong-salt tests test the salt and nothing else.
        var s = new Setup();
        Assert.Equal("n-1", (await s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveA, GoodPayload, saltLength: 32))).Nonce);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(20)]
    [InlineData(64)]
    public async Task Signature_with_another_salt_length_is_BAD_SIGNATURE(int salt)
    {
        var s = new Setup();
        var e = await Fails(() => s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveA, GoodPayload, saltLength: salt)));
        Assert.Equal(VerifyBlindErrorCode.BadSignature, e.Code);
    }

    [Fact]
    public async Task Signature_from_another_key_is_BAD_SIGNATURE()
    {
        var s = new Setup();
        var e = await Fails(() => s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveB, GoodPayload)));
        Assert.Equal(VerifyBlindErrorCode.BadSignature, e.Code);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not base64 !!")]
    [InlineData("bm90IGpzb24=")] // "not json"
    [InlineData("WzEsMl0=")] // [1,2]
    [InlineData("eyJwYXlsb2FkIjoxLCJzaWduYXR1cmUiOiJ4In0=")] // {"payload":1,"signature":"x"}
    [InlineData("eyJwYXlsb2FkIjoiIiwic2lnbmF0dXJlIjoiIn0=")] // {"payload":"","signature":""}
    public async Task Malformed_tokens_are_BAD_TOKEN(string? token)
    {
        var s = new Setup();
        Assert.Equal(VerifyBlindErrorCode.BadToken, (await Fails(() => s.Verifier.VerifyTokenAsync(token))).Code);
        Assert.Empty(s.Api.Calls);
    }

    [Theory]
    [InlineData("{\"validations\":{}}")]
    [InlineData("{\"nonce\":\"\"}")]
    [InlineData("{\"nonce\":5}")]
    [InlineData("[1]")]
    [InlineData("not json")]
    public async Task Valid_signature_over_a_payload_without_nonce_is_BAD_PAYLOAD(string payload)
    {
        var s = new Setup();
        var e = await Fails(() => s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveA, payload)));
        Assert.Equal(VerifyBlindErrorCode.BadPayload, e.Code);
    }

    [Fact]
    public async Task Key_rotation_cached_key_fails_refreshes_once_and_succeeds()
    {
        var s = new Setup();
        await s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveA, GoodPayload));
        s.EnclaveKey = Keys.EnclaveB; // enclave restarted
        s.Time.Advance(TimeSpan.FromSeconds(20));
        Assert.Equal("n-1", (await s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveB, GoodPayload))).Nonce);
        Assert.Equal(2, s.Api.Count(Setup.EnclavePath));
    }

    [Fact]
    public async Task Refresh_happens_only_once_per_bad_token()
    {
        var s = new Setup();
        await s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveA, GoodPayload));
        s.Time.Advance(TimeSpan.FromSeconds(20));
        await Fails(() => s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveB, GoodPayload)));
        Assert.Equal(2, s.Api.Count(Setup.EnclavePath));
    }

    [Fact]
    public async Task A_key_fetched_for_this_call_is_not_fetched_again_on_failure()
    {
        var s = new Setup();
        await Fails(() => s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveB, GoodPayload)));
        Assert.Equal(1, s.Api.Count(Setup.EnclavePath));
    }

    [Fact]
    public async Task A_key_younger_than_KeyRefreshMinInterval_is_not_refreshed()
    {
        var s = new Setup();
        await s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveA, GoodPayload));
        s.Time.Advance(TimeSpan.FromSeconds(5));
        for (var i = 0; i < 5; i++)
            await Fails(() => s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveB, GoodPayload)));
        Assert.Equal(1, s.Api.Count(Setup.EnclavePath));
    }

    [Fact]
    public async Task Refreshed_key_equal_to_the_cached_one_is_not_tried_twice()
    {
        var s = new Setup();
        await s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveA, GoodPayload));
        s.Time.Advance(TimeSpan.FromSeconds(30));
        await Fails(() => s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveB, GoodPayload)));
        // A second bad token right after: the key was just refreshed, so no third request.
        await Fails(() => s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveB, GoodPayload)));
        Assert.Equal(2, s.Api.Count(Setup.EnclavePath));
    }

    [Fact]
    public async Task Key_is_cached_for_60_s_by_default()
    {
        var s = new Setup();
        var token = Sign.Token(Keys.EnclaveA, GoodPayload);
        await s.Verifier.VerifyTokenAsync(token);
        s.Time.Advance(TimeSpan.FromSeconds(59));
        await s.Verifier.VerifyTokenAsync(token);
        Assert.Equal(1, s.Api.Count(Setup.EnclavePath));
        s.Time.Advance(TimeSpan.FromSeconds(2));
        await s.Verifier.VerifyTokenAsync(token);
        Assert.Equal(2, s.Api.Count(Setup.EnclavePath));
    }

    [Fact]
    public async Task ClearKeyCache_forces_a_new_request()
    {
        var s = new Setup();
        var token = Sign.Token(Keys.EnclaveA, GoodPayload);
        await s.Verifier.VerifyTokenAsync(token);
        s.Verifier.ClearKeyCache();
        await s.Verifier.VerifyTokenAsync(token);
        Assert.Equal(2, s.Api.Count(Setup.EnclavePath));
    }

    [Fact]
    public async Task Concurrent_first_calls_share_one_key_request()
    {
        var s = new Setup();
        s.Api.Delay = TimeSpan.FromMilliseconds(100);
        var token = Sign.Token(Keys.EnclaveA, GoodPayload);
        await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => s.Verifier.VerifyTokenAsync(token)));
        Assert.Equal(1, s.Api.Count(Setup.EnclavePath));
    }

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError, "x")]
    [InlineData(HttpStatusCode.OK, "")]
    [InlineData(HttpStatusCode.OK, "not a key !!")]
    [InlineData(HttpStatusCode.OK, "aGVsbG8=")] // base64, but not an SPKI
    public async Task HTTP_error_or_unusable_key_is_KEY_FETCH_FAILED(HttpStatusCode status, string body)
    {
        var s = new Setup();
        s.Api.Routes[Setup.EnclavePath] = () => (status, body);
        var e = await Fails(() => s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveA, GoodPayload)));
        Assert.Equal(VerifyBlindErrorCode.KeyFetchFailed, e.Code);
        Assert.Equal(503, e.HttpStatus);
    }

    [Fact]
    public async Task Timeout_is_KEY_FETCH_FAILED()
    {
        var s = new Setup(o => o.HttpTimeout = TimeSpan.FromMilliseconds(50));
        s.Api.Delay = TimeSpan.FromSeconds(5);
        var e = await Fails(() => s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveA, GoodPayload)));
        Assert.Equal(VerifyBlindErrorCode.KeyFetchFailed, e.Code);
    }

    [Fact]
    public async Task A_failed_key_fetch_is_retried_on_the_next_call()
    {
        var s = new Setup();
        var fail = true;
        s.Api.Routes[Setup.EnclavePath] = () => fail ? (HttpStatusCode.BadGateway, "") : (HttpStatusCode.OK, Keys.SpkiBase64(Keys.EnclaveA));
        var token = Sign.Token(Keys.EnclaveA, GoodPayload);
        await Fails(() => s.Verifier.VerifyTokenAsync(token));
        fail = false;
        Assert.Equal("n-1", (await s.Verifier.VerifyTokenAsync(token)).Nonce);
    }

    [Fact]
    public async Task Result_ToString_hides_identity_codes()
    {
        var s = new Setup();
        var r = await s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveA, GoodPayload));
        foreach (var text in new[] { r.ToString(), r.Validations.ToString() })
        {
            Assert.DoesNotContain(SecretUid, text);
            Assert.DoesNotContain("NSBD_SECRET", text);
            Assert.DoesNotContain("DOC_SECRET", text);
            Assert.Contains("[redacted]", text);
        }
        var outcome = await s.Verifier.VerifyAndConsumeAsync(Sign.Token(Keys.EnclaveA, GoodPayload),
            new MemoryStore().Add("n-1", "{\"age\":\"18+\",\"user_id\":true}").Consume);
        Assert.True(outcome.Ok);
        Assert.DoesNotContain(SecretUid, outcome.ToString());
    }
}
