using System.Security.Cryptography;

namespace VerifyBlind.Server;

/// <summary>
/// Verifies VerifyBlind results on your server. Register it once (<c>services.AddVerifyBlind()</c>) or keep one
/// <see cref="VerifyBlindVerifier"/> instance: it caches the public keys and is thread-safe.
/// </summary>
/// <remarks>Nothing here logs, and no error message contains <c>user_id</c>, <c>nsbd_id</c> or <c>doc_id</c>.</remarks>
public interface IVerifyBlindVerifier
{
    /// <summary>
    /// The whole pattern A check in one call: enclave signature → consume the nonce exactly once → demo-card check
    /// → the signed answer against what you asked. Verification failures are returned in the outcome, not thrown.
    /// </summary>
    /// <param name="token">The <c>token</c> the web widget (<c>onSuccess</c>) or the mobile SDK gave you.</param>
    /// <param name="consumeNonce">
    /// Your nonce store: atomically get-and-delete the nonce and return the JSON you stored with it at generate
    /// (e.g. <c>{"age":"18+","user_id":true}</c>), or <c>null</c> when it is unknown, expired or already used.
    /// It is not called when the signature is invalid. Its exceptions are not caught.
    /// </param>
    /// <param name="cancellationToken">Cancels the key request.</param>
    Task<VerifyBlindOutcome> VerifyAndConsumeAsync(string? token, Func<string, Task<string?>> consumeNonce, CancellationToken cancellationToken = default);

    /// <summary>Same as the other overload, for a store that returns <see cref="VerifyBlindAsked"/> objects.</summary>
    Task<VerifyBlindOutcome> VerifyAndConsumeAsync(string? token, Func<string, Task<VerifyBlindAsked?>> consumeNonce, CancellationToken cancellationToken = default);

    /// <summary>
    /// Nonce consume → demo-card check → asked check, for a result whose signature is already verified
    /// (e.g. <see cref="CallbackResult.Verified"/>).
    /// </summary>
    Task<VerifyBlindOutcome> ConsumeAndCheckAsync(VerifiedResult verified, Func<string, Task<string?>> consumeNonce);

    /// <summary>Same as the other overload, for a store that returns <see cref="VerifyBlindAsked"/> objects.</summary>
    Task<VerifyBlindOutcome> ConsumeAndCheckAsync(VerifiedResult verified, Func<string, Task<VerifyBlindAsked?>> consumeNonce);

    /// <summary>
    /// Signature only. You must still consume the nonce and check what you asked before acting on the result.
    /// </summary>
    /// <exception cref="VerifyBlindException"><c>BAD_TOKEN</c>, <c>BAD_SIGNATURE</c>, <c>BAD_PAYLOAD</c>, <c>KEY_FETCH_FAILED</c>.</exception>
    Task<VerifiedResult> VerifyTokenAsync(string? token, CancellationToken cancellationToken = default);

    /// <summary>Same as <see cref="VerifyTokenAsync"/> for an already-decoded <c>{ payload, signature }</c>.</summary>
    /// <exception cref="VerifyBlindException"><c>BAD_TOKEN</c>, <c>BAD_SIGNATURE</c>, <c>BAD_PAYLOAD</c>, <c>KEY_FETCH_FAILED</c>.</exception>
    Task<VerifiedResult> VerifySignedAsync(SignedPayload signed, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a webhook from VerifyBlind (revoke or pattern B callback): the timestamp is within the allowed
    /// window and <c>X-Webhook-Signature</c> is RSA-PSS over <c>"{X-Webhook-Timestamp}.{raw body}"</c> with the key
    /// from <c>/api/public/webhook-signing-key</c>. Returns the JSON body (which must have a <c>nonce</c>).
    /// </summary>
    /// <param name="rawBody">The request body EXACTLY as received, before any JSON parsing.</param>
    /// <param name="signature">The <c>X-Webhook-Signature</c> header.</param>
    /// <param name="timestamp">The <c>X-Webhook-Timestamp</c> header (Unix seconds).</param>
    /// <param name="cancellationToken">Cancels the key request.</param>
    /// <exception cref="VerifyBlindException"><c>BAD_WEBHOOK_TIMESTAMP</c>, <c>BAD_WEBHOOK_SIGNATURE</c>, <c>BAD_PAYLOAD</c>, <c>KEY_FETCH_FAILED</c>.</exception>
    Task<WebhookBody> VerifyWebhookAsync(ReadOnlyMemory<byte> rawBody, string? signature, string? timestamp, CancellationToken cancellationToken = default);

    /// <summary>Revoke webhook: the same signature as the callback. Act on <see cref="WebhookBody.Nonce"/> only.</summary>
    /// <exception cref="VerifyBlindException">See <see cref="VerifyWebhookAsync"/>.</exception>
    Task<WebhookBody> VerifyRevokeAsync(ReadOnlyMemory<byte> rawBody, string? signature, string? timestamp, CancellationToken cancellationToken = default);

    /// <summary>
    /// Pattern B callback: verifies the webhook, then (unless cancelled) decrypts <c>encrypted_response</c> with your
    /// callback private key, verifies the enclave signature and checks that the signed nonce is the webhook nonce.
    /// You still consume the nonce and check what you asked: <see cref="ConsumeAndCheckAsync(VerifiedResult, Func{string, Task{string?}})"/>.
    /// </summary>
    /// <exception cref="VerifyBlindException">Webhook errors, <c>DECRYPT_FAILED</c>, <c>BAD_SIGNATURE</c>, <c>BAD_PAYLOAD</c>.</exception>
    Task<CallbackResult> VerifyCallbackAsync(ReadOnlyMemory<byte> rawBody, string? signature, string? timestamp, RSA privateKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Optional enclave check: the PCR0 authorization signature (RSA PKCS#1 v1.5, SHA-256, over the PCR0 hex string)
    /// against <c>GET /api/public/developer-key</c>. Then compare the PCR0 with <c>expected_pcr.json</c> of
    /// https://github.com/VerifyBlind/VerifyBlind-Enclave/releases/latest yourself.
    /// </summary>
    /// <returns><c>false</c> for a bad signature.</returns>
    /// <exception cref="VerifyBlindException"><c>KEY_FETCH_FAILED</c> when the key cannot be fetched.</exception>
    Task<bool> VerifyPcr0SignatureAsync(string pcr0Hex, string pcr0SignatureBase64, CancellationToken cancellationToken = default);

    /// <summary>Drops all cached public keys.</summary>
    void ClearKeyCache();
}
