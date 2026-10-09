using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

namespace VerifyBlind.Server;

/// <summary>
/// The <c>validations</c> object inside the enclave-signed payload.
/// </summary>
/// <remarks>
/// <see cref="UserId"/>, <see cref="NsbdId"/> and <see cref="DocId"/> are pseudonymous personal data:
/// store them like other user data and NEVER write them to logs. <see cref="ToString"/> hides them.
/// </remarks>
public sealed class VerifyBlindValidations
{
    internal static readonly VerifyBlindValidations Empty = new(EmptyObject());

    internal VerifyBlindValidations(JsonElement raw)
    {
        Raw = raw;
        Age = raw.TryGetProperty("age", out var a) && a.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? a.GetBoolean()
            : null;
        AgeCondition = StringField(raw, "age_condition");
        UserId = StringField(raw, "user_id");
        NsbdId = StringField(raw, "nsbd_id");
        DocId = StringField(raw, "doc_id");
        IsTest = (raw.TryGetProperty("is_test", out var t) && t.ValueKind == JsonValueKind.True)
                 || IsTestCode(UserId) || IsTestCode(NsbdId) || IsTestCode(DocId);
    }

    /// <summary>Answer to the asked age condition (<c>true</c> = meets it). <c>null</c> when age was not answered.</summary>
    public bool? Age { get; }

    /// <summary>The condition the enclave answered, e.g. <c>"18+"</c>. Must equal what you asked (checked for you).</summary>
    public string? AgeCondition { get; }

    /// <summary>Stable pseudonymous code for this person, unique to your partner account. Use it for decisions. Never log it.</summary>
    public string? UserId { get; }

    /// <summary>Second pseudonymous code (for future passport / foreign-ID support). Store it; never log it.</summary>
    public string? NsbdId { get; }

    /// <summary>Third pseudonymous code (for future passport / foreign-ID support). Store it; never log it.</summary>
    public string? DocId { get; }

    /// <summary><c>true</c> for a demo-card result (test partners only): <c>is_test: true</c> or codes starting with <c>TEST_</c>.</summary>
    public bool IsTest { get; }

    /// <summary>The whole <c>validations</c> JSON object. Contains the identity codes: never log it.</summary>
    public JsonElement Raw { get; }

    /// <summary>A log-safe description: identity codes are replaced with <c>[redacted]</c>.</summary>
    public override string ToString()
    {
        static string Code(string? c) => c is null ? "null" : "[redacted]";
        var age = Age is null ? "null" : Age.Value ? "true" : "false";
        return $"age={age}, age_condition={AgeCondition ?? "null"}, user_id={Code(UserId)}, " +
               $"nsbd_id={Code(NsbdId)}, doc_id={Code(DocId)}, is_test={(IsTest ? "true" : "false")}";
    }

    private static string? StringField(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static bool IsTestCode(string? code) => code is not null && code.StartsWith("TEST_", StringComparison.Ordinal);

    private static JsonElement EmptyObject()
    {
        using var doc = JsonDocument.Parse("{}");
        return doc.RootElement.Clone();
    }
}

/// <summary>
/// A result whose enclave signature has been verified. On its own it only proves that the enclave signed it:
/// consume its nonce and check it against what you asked before acting on it
/// (<see cref="IVerifyBlindVerifier.VerifyAndConsumeAsync(string, Func{string, Task{string?}}, CancellationToken)"/> does all of it).
/// </summary>
public sealed class VerifiedResult
{
    internal VerifiedResult(string nonce, VerifyBlindValidations validations, JsonElement payload, string rawPayload)
    {
        Nonce = nonce;
        Validations = validations;
        Payload = payload;
        RawPayload = rawPayload;
    }

    /// <summary>The signed nonce.</summary>
    public string Nonce { get; }

    /// <summary>The signed <c>validations</c> (empty when absent).</summary>
    public VerifyBlindValidations Validations { get; }

    /// <summary>The whole parsed payload (<c>nonce</c>, <c>validations</c>, <c>additional_data</c>, ...). Never log it.</summary>
    public JsonElement Payload { get; }

    /// <summary>The exact signed payload string. Never log it.</summary>
    public string RawPayload { get; }

    /// <summary><c>true</c> for demo-card results. Keep them out of production decisions.</summary>
    public bool IsTest => Validations.IsTest;

    /// <summary>The <c>additional_data</c> you sent at generate, or <c>null</c>.</summary>
    public JsonElement? AdditionalData =>
        Payload.TryGetProperty("additional_data", out var d) && d.ValueKind != JsonValueKind.Null ? d : null;

    /// <summary>A log-safe description: identity codes are replaced with <c>[redacted]</c>.</summary>
    public override string ToString() => $"VerifiedResult(nonce={Nonce}, {Validations})";
}

/// <summary>
/// The result of <c>VerifyAndConsumeAsync</c> / <c>ConsumeAndCheckAsync</c>. Verification failures are
/// returned here (<see cref="Ok"/> = <c>false</c>, <see cref="Error"/>) instead of being thrown.
/// </summary>
public sealed class VerifyBlindOutcome
{
    private VerifyBlindOutcome(VerifiedResult? result, VerifyBlindAsked? asked, VerifyBlindException? error)
    {
        Result = result;
        Asked = asked;
        Error = error;
    }

    internal static VerifyBlindOutcome Success(VerifiedResult result, VerifyBlindAsked asked) => new(result, asked, null);

    internal static VerifyBlindOutcome Failure(VerifyBlindException error) => new(null, null, error);

    /// <summary><c>true</c> when the signature, the nonce and the asked check all passed.</summary>
    /// <remarks><c>Validations.Age == false</c> is still <c>Ok</c>: the person does not meet the condition; you decide.</remarks>
    [MemberNotNullWhen(true, nameof(Result), nameof(Asked), nameof(Validations))]
    [MemberNotNullWhen(false, nameof(Error))]
    public bool Ok => Error is null;

    /// <summary>The verified result when <see cref="Ok"/>.</summary>
    public VerifiedResult? Result { get; }

    /// <summary>What your server asked for this nonce, when <see cref="Ok"/>.</summary>
    public VerifyBlindAsked? Asked { get; }

    /// <summary>Shortcut for <c>Result.Validations</c>.</summary>
    public VerifyBlindValidations? Validations => Result?.Validations;

    /// <summary>The reason when not <see cref="Ok"/>. Return <c>Error.Code</c> with <c>Error.HttpStatus</c>.</summary>
    public VerifyBlindException? Error { get; }

    /// <summary>A log-safe description: identity codes are replaced with <c>[redacted]</c>.</summary>
    public override string ToString() => Ok ? $"Ok: {Result}" : $"Failed: {Error.Code}";
}
