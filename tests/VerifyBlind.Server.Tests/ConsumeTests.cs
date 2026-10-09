using System.Text;
using System.Text.Json;

namespace VerifyBlind.Server.Tests;

public class CheckAskedTests
{
    public static TheoryData<string, string?, string?, bool> Cases => new()
    {
        // name, asked JSON (null = none), validations JSON (null = none), should pass
        { "age asked, matching condition", """{"age":"18+"}""", """{"age":true,"age_condition":"18+"}""", true },
        { "age asked, answer false is still a valid answer", """{"age":"18+"}""", """{"age":false,"age_condition":"18+"}""", true },
        { "age asked, age_condition missing", """{"age":"18+"}""", """{"age":true}""", false },
        { "age asked, age_condition mismatched (1+ attack)", """{"age":"18+"}""", """{"age":true,"age_condition":"1+"}""", false },
        { "age asked, age_condition not a string", """{"age":"18+"}""", """{"age":true,"age_condition":18}""", false },
        { "age asked, age missing", """{"age":"18+"}""", """{"age_condition":"18+"}""", false },
        { "age asked, age not boolean", """{"age":"18+"}""", """{"age":"true","age_condition":"18+"}""", false },
        { "age not asked but age present", """{"user_id":true}""", """{"age":true,"age_condition":"1+","user_id":"u"}""", false },
        { "age not asked but age null", """{"user_id":true}""", """{"age":null,"user_id":"u"}""", false },
        { "age not asked, age absent", """{"user_id":true}""", """{"user_id":"u"}""", true },
        { "age not asked but age_condition present", """{"user_id":true}""", """{"age_condition":"18+","user_id":"u"}""", false },
        { "user_id asked but missing", """{"user_id":true}""", "{}", false },
        { "user_id asked but empty", """{"user_id":true}""", """{"user_id":""}""", false },
        { "user_id asked but not a string", """{"user_id":true}""", """{"user_id":5}""", false },
        { "both asked, both present", """{"age":"18+","user_id":true}""", """{"age":true,"age_condition":"18+","user_id":"u"}""", true },
        { "nothing asked, nothing answered", "{}", "{}", true },
        { "nothing asked, validations absent", null, null, true },
        { "age asked, validations absent", """{"age":"18+"}""", null, false },
        { "user_id other than true is not asked", """{"user_id":"yes"}""", "{}", true },
        { "empty stored age condition is rejected", """{"age":""}""", """{"age":true,"age_condition":""}""", false },
    };

    [Theory]
    [MemberData(nameof(Cases))]
    public void CheckAsked_rules(string name, string? askedJson, string? validationsJson, bool pass)
    {
        VerifyBlindAsked? asked = null;
        if (askedJson is not null) Assert.True(VerifyBlindAsked.TryParse(askedJson, out asked), name);
        VerifyBlindValidations? validations = validationsJson is null
            ? null
            : new VerifyBlindValidations(JsonDocument.Parse(validationsJson).RootElement.Clone());
        var reason = VerifyBlindVerifier.CheckAsked(asked, validations);
        if (pass) Assert.True(reason is null, $"{name}: {reason}");
        else Assert.False(string.IsNullOrEmpty(reason), name);
    }

    [Fact]
    public void Asked_round_trips_through_ToJson()
    {
        var json = new VerifyBlindAsked { Age = "18+", UserId = true }.ToJson();
        Assert.Equal("""{"age":"18+","user_id":true}""", json);
        Assert.True(VerifyBlindAsked.TryParse(json, out var back));
        Assert.Equal("18+", back!.Age);
        Assert.True(back.UserId);
        Assert.Equal("{}", new VerifyBlindAsked().ToJson());
    }

    [Theory]
    [InlineData("")]
    [InlineData("{oops")]
    [InlineData("[1]")]
    [InlineData("\"18+\"")]
    [InlineData("""{"age":18}""")]
    public void Unreadable_asked_json_does_not_parse(string json) =>
        Assert.False(VerifyBlindAsked.TryParse(json, out _));
}

public class ConsumeTests
{
    private const string SecretUid = "UID_SECRET_7f3a";
    private const string Asked = """{"age":"18+","user_id":true}""";
    private static readonly object GoodPayload = new
    {
        nonce = "n-1",
        validations = new { age = true, age_condition = "18+", user_id = SecretUid, nsbd_id = "NSBD_SECRET", doc_id = "DOC_SECRET" },
    };
    private static readonly object DemoPayload = new
    {
        nonce = "n-1",
        validations = new { age = true, age_condition = "18+", user_id = "TEST_abc", is_test = true },
    };
    private static readonly object PrefixOnlyPayload = new
    {
        nonce = "n-1",
        validations = new { age = true, age_condition = "18+", nsbd_id = "TEST_def" },
    };

    [Fact]
    public async Task Happy_path_returns_ok_with_validations_and_asked()
    {
        var s = new Setup();
        var store = new MemoryStore().Add("n-1", Asked);
        var r = await s.Verifier.VerifyAndConsumeAsync(Sign.Token(Keys.EnclaveA, GoodPayload), store.Consume);
        Assert.True(r.Ok, r.Error?.Message);
        Assert.Equal("n-1", r.Result.Nonce);
        Assert.True(r.Validations.Age);
        Assert.Equal(SecretUid, r.Validations.UserId);
        Assert.Equal("18+", r.Asked.Age);
        Assert.True(r.Asked.UserId);
        Assert.Equal(["n-1"], store.Calls);
    }

    [Fact]
    public async Task Typed_store_overload_works_the_same()
    {
        var s = new Setup();
        var r = await s.Verifier.VerifyAndConsumeAsync(Sign.Token(Keys.EnclaveA, GoodPayload),
            nonce => Task.FromResult<VerifyBlindAsked?>(nonce == "n-1" ? new VerifyBlindAsked { Age = "18+", UserId = true } : null));
        Assert.True(r.Ok, r.Error?.Message);
        var missing = await s.Verifier.VerifyAndConsumeAsync(Sign.Token(Keys.EnclaveA, GoodPayload),
            _ => Task.FromResult<VerifyBlindAsked?>(null));
        Assert.Equal(VerifyBlindErrorCode.NonceNotFound, missing.Error!.Code);
    }

    [Fact]
    public async Task Replay_second_use_of_the_same_token_is_NONCE_NOT_FOUND()
    {
        var s = new Setup();
        var store = new MemoryStore().Add("n-1", Asked);
        var token = Sign.Token(Keys.EnclaveA, GoodPayload);
        Assert.True((await s.Verifier.VerifyAndConsumeAsync(token, store.Consume)).Ok);
        var again = await s.Verifier.VerifyAndConsumeAsync(token, store.Consume);
        Assert.False(again.Ok);
        Assert.Equal(VerifyBlindErrorCode.NonceNotFound, again.Error.Code);
        Assert.Equal(401, again.Error.HttpStatus);
    }

    [Fact]
    public async Task Result_not_matching_what_was_asked_is_ASKED_MISMATCH()
    {
        var s = new Setup();
        var store = new MemoryStore().Add("n-1", """{"age":"21+","user_id":true}""");
        var r = await s.Verifier.VerifyAndConsumeAsync(Sign.Token(Keys.EnclaveA, GoodPayload), store.Consume);
        Assert.Equal(VerifyBlindErrorCode.AskedMismatch, r.Error!.Code);
        Assert.Contains("21+", r.Error.Message);
    }

    [Fact]
    public async Task The_1_plus_attack_is_caught()
    {
        var s = new Setup();
        var store = new MemoryStore().Add("n-1", """{"age":"18+"}""");
        var token = Sign.Token(Keys.EnclaveA, new { nonce = "n-1", validations = new { age = true, age_condition = "1+" } });
        var r = await s.Verifier.VerifyAndConsumeAsync(token, store.Consume);
        Assert.Equal(VerifyBlindErrorCode.AskedMismatch, r.Error!.Code);
    }

    [Theory]
    [InlineData("{oops")]
    [InlineData("[1]")]
    [InlineData("""{"age":18}""")]
    public async Task Unreadable_stored_value_fails_closed(string stored)
    {
        var s = new Setup();
        var r = await s.Verifier.VerifyAndConsumeAsync(Sign.Token(Keys.EnclaveA, GoodPayload), new MemoryStore().Add("n-1", stored).Consume);
        Assert.Equal(VerifyBlindErrorCode.AskedMismatch, r.Error!.Code);
    }

    [Fact]
    public async Task Bad_signature_never_touches_the_nonce_store()
    {
        var s = new Setup();
        var store = new MemoryStore().Add("n-1", Asked);
        var r = await s.Verifier.VerifyAndConsumeAsync(Sign.Token(Keys.EnclaveB, GoodPayload), store.Consume);
        Assert.Equal(VerifyBlindErrorCode.BadSignature, r.Error!.Code);
        Assert.Empty(store.Calls);
        // The nonce is still there for the genuine token.
        Assert.True((await s.Verifier.VerifyAndConsumeAsync(Sign.Token(Keys.EnclaveA, GoodPayload), store.Consume)).Ok);
    }

    [Fact]
    public async Task Bad_token_and_key_failures_are_returned_not_thrown()
    {
        var s = new Setup();
        Assert.Equal(VerifyBlindErrorCode.BadToken, (await s.Verifier.VerifyAndConsumeAsync("nope", new MemoryStore().Consume)).Error!.Code);
        s.Api.Routes[Setup.EnclavePath] = () => (System.Net.HttpStatusCode.ServiceUnavailable, "");
        var r = await s.Verifier.VerifyAndConsumeAsync(Sign.Token(Keys.EnclaveA, GoodPayload), new MemoryStore().Consume);
        Assert.Equal(VerifyBlindErrorCode.KeyFetchFailed, r.Error!.Code);
        Assert.Equal(503, r.Error.HttpStatus);
    }

    [Fact]
    public async Task Errors_from_your_store_propagate()
    {
        var s = new Setup();
        var e = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            s.Verifier.VerifyAndConsumeAsync(Sign.Token(Keys.EnclaveA, GoodPayload), (Func<string, Task<string?>>)(_ => throw new InvalidOperationException("redis down"))));
        Assert.Equal("redis down", e.Message);
    }

    [Fact]
    public async Task Demo_card_is_rejected_by_default_with_TEST_CARD()
    {
        var s = new Setup();
        var store = new MemoryStore().Add("n-1", Asked);
        var r = await s.Verifier.VerifyAndConsumeAsync(Sign.Token(Keys.EnclaveA, DemoPayload), store.Consume);
        Assert.Equal(VerifyBlindErrorCode.TestCard, r.Error!.Code);
        Assert.Equal(403, r.Error.HttpStatus);
        Assert.Equal(["n-1"], store.Calls); // the nonce is consumed first: a demo token cannot be replayed either
    }

    [Fact]
    public async Task Demo_card_with_TEST_prefix_only_is_rejected_too()
    {
        var s = new Setup();
        var r = await s.Verifier.VerifyAndConsumeAsync(Sign.Token(Keys.EnclaveA, PrefixOnlyPayload), new MemoryStore().Add("n-1", """{"age":"18+"}""").Consume);
        Assert.Equal(VerifyBlindErrorCode.TestCard, r.Error!.Code);
    }

    [Fact]
    public async Task Demo_card_is_accepted_with_AllowTestCards()
    {
        var s = new Setup(o => o.AllowTestCards = true);
        var r = await s.Verifier.VerifyAndConsumeAsync(Sign.Token(Keys.EnclaveA, DemoPayload), new MemoryStore().Add("n-1", Asked).Consume);
        Assert.True(r.Ok, r.Error?.Message);
        Assert.True(r.Result.IsTest);
    }

    [Fact]
    public async Task Demo_card_is_checked_after_the_nonce()
    {
        var s = new Setup();
        var r = await s.Verifier.VerifyAndConsumeAsync(Sign.Token(Keys.EnclaveA, DemoPayload), new MemoryStore().Consume);
        Assert.Equal(VerifyBlindErrorCode.NonceNotFound, r.Error!.Code);
    }

    [Fact]
    public async Task No_error_message_contains_identity_codes()
    {
        var s = new Setup();
        var token = Sign.Token(Keys.EnclaveA, GoodPayload);
        var texts = new List<string>();
        foreach (var stored in new[] { "", """{"age":"21+"}""", """{"age":"18+","user_id":true,"extra":1}""", "{oops", "{}", """{"age":null}""" })
        {
            var r = await s.Verifier.VerifyAndConsumeAsync(token, new MemoryStore().Add("n-1", stored).Consume);
            texts.Add(r.ToString());
            if (!r.Ok) texts.Add(r.Error.ToString());
        }
        var bad = await s.Verifier.VerifyAndConsumeAsync(Sign.Token(Keys.EnclaveB, GoodPayload), new MemoryStore().Consume);
        texts.Add(bad.Error!.ToString());
        var truncated = Encoding.UTF8.GetString(Convert.FromBase64String(token))[..60];
        var badToken = await s.Verifier.VerifyAndConsumeAsync(Convert.ToBase64String(Encoding.UTF8.GetBytes(truncated)), new MemoryStore().Consume);
        texts.Add(badToken.Error!.ToString());
        Assert.True(texts.Count >= 8);
        foreach (var t in texts)
            foreach (var secret in new[] { SecretUid, "NSBD_SECRET", "DOC_SECRET" })
                Assert.DoesNotContain(secret, t);
    }

    [Fact]
    public async Task ConsumeAndCheck_works_for_an_already_verified_result()
    {
        var s = new Setup();
        var verified = await s.Verifier.VerifyTokenAsync(Sign.Token(Keys.EnclaveA, GoodPayload));
        var r = await s.Verifier.ConsumeAndCheckAsync(verified, new MemoryStore().Add("n-1", Asked).Consume);
        Assert.True(r.Ok, r.Error?.Message);
    }
}
