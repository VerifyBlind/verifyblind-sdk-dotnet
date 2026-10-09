using System.Text.Json;

namespace VerifyBlind.Server;

/// <summary>A webhook body whose signature has been verified. Only <see cref="Nonce"/> is guaranteed; other fields vary by event.</summary>
public sealed class WebhookBody
{
    internal WebhookBody(string nonce, JsonElement json)
    {
        Nonce = nonce;
        Json = json;
    }

    /// <summary>The nonce this webhook is about. Key your action on it.</summary>
    public string Nonce { get; }

    /// <summary>The whole JSON body (e.g. <c>event_type</c>, <c>status</c>, <c>reason</c>).</summary>
    public JsonElement Json { get; }

    /// <summary>A string field of the body, or <c>null</c>.</summary>
    public string? GetString(string name) =>
        Json.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    /// <inheritdoc />
    public override string ToString() => $"WebhookBody(nonce={Nonce})";
}

/// <summary>Status of a pattern B callback.</summary>
public enum CallbackStatus
{
    /// <summary>The user finished; <see cref="CallbackResult.Verified"/> holds the signature-checked result.</summary>
    Completed,

    /// <summary>The user cancelled; <see cref="CallbackResult.Reason"/> says why.</summary>
    Cancelled,
}

/// <summary>The result of <see cref="IVerifyBlindVerifier.VerifyCallbackAsync(ReadOnlyMemory{byte}, string?, string?, System.Security.Cryptography.RSA, CancellationToken)"/>.</summary>
public sealed class CallbackResult
{
    internal CallbackResult(CallbackStatus status, string nonce, string? reason, VerifiedResult? verified, WebhookBody body)
    {
        Status = status;
        Nonce = nonce;
        Reason = reason;
        Verified = verified;
        Body = body;
    }

    /// <summary>Completed or cancelled.</summary>
    public CallbackStatus Status { get; }

    /// <summary>The nonce this callback is about.</summary>
    public string Nonce { get; }

    /// <summary>
    /// Cancel reason when <see cref="Status"/> is <see cref="CallbackStatus.Cancelled"/>: <c>user_cancelled</c>,
    /// <c>no_card_registered</c>, <c>user_declined</c>, <c>fingerprint_failed</c>, <c>session_expired</c>
    /// (treat unknown values as <c>user_cancelled</c>).
    /// </summary>
    public string? Reason { get; }

    /// <summary>
    /// The decrypted, enclave-signature-checked result when completed. You still must consume the nonce and
    /// check what you asked: pass it to <c>ConsumeAndCheckAsync</c>.
    /// </summary>
    public VerifiedResult? Verified { get; }

    /// <summary>The verified webhook body.</summary>
    public WebhookBody Body { get; }

    /// <inheritdoc />
    public override string ToString() => $"CallbackResult({Status}, nonce={Nonce})";
}
