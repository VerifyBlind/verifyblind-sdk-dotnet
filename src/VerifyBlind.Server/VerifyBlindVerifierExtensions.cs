using System.Text;

namespace VerifyBlind.Server;

/// <summary>Convenience overloads: raw body as a string or a request stream, callback key object.</summary>
public static class VerifyBlindVerifierExtensions
{
    /// <summary>Largest webhook body read from a stream. VerifyBlind webhooks are a few kilobytes.</summary>
    public const int MaxWebhookBodyBytes = 1024 * 1024;

    /// <summary><see cref="IVerifyBlindVerifier.VerifyWebhookAsync"/> with the raw body as a string (UTF-8).</summary>
    public static Task<WebhookBody> VerifyWebhookAsync(this IVerifyBlindVerifier verifier, string rawBody, string? signature, string? timestamp, CancellationToken cancellationToken = default) =>
        verifier.VerifyWebhookAsync(Encoding.UTF8.GetBytes(rawBody ?? ""), signature, timestamp, cancellationToken);

    /// <summary><see cref="IVerifyBlindVerifier.VerifyWebhookAsync"/> reading the raw body from a stream (e.g. <c>HttpRequest.Body</c>).</summary>
    public static async Task<WebhookBody> VerifyWebhookAsync(this IVerifyBlindVerifier verifier, Stream body, string? signature, string? timestamp, CancellationToken cancellationToken = default) =>
        await verifier.VerifyWebhookAsync(await ReadBodyAsync(body, cancellationToken).ConfigureAwait(false), signature, timestamp, cancellationToken).ConfigureAwait(false);

    /// <summary><see cref="IVerifyBlindVerifier.VerifyRevokeAsync"/> with the raw body as a string (UTF-8).</summary>
    public static Task<WebhookBody> VerifyRevokeAsync(this IVerifyBlindVerifier verifier, string rawBody, string? signature, string? timestamp, CancellationToken cancellationToken = default) =>
        verifier.VerifyRevokeAsync(Encoding.UTF8.GetBytes(rawBody ?? ""), signature, timestamp, cancellationToken);

    /// <summary><see cref="IVerifyBlindVerifier.VerifyRevokeAsync"/> reading the raw body from a stream (e.g. <c>HttpRequest.Body</c>).</summary>
    public static async Task<WebhookBody> VerifyRevokeAsync(this IVerifyBlindVerifier verifier, Stream body, string? signature, string? timestamp, CancellationToken cancellationToken = default) =>
        await verifier.VerifyRevokeAsync(await ReadBodyAsync(body, cancellationToken).ConfigureAwait(false), signature, timestamp, cancellationToken).ConfigureAwait(false);

    /// <summary><see cref="IVerifyBlindVerifier.VerifyCallbackAsync"/> with a <see cref="VerifyBlindCallbackKey"/>.</summary>
    public static Task<CallbackResult> VerifyCallbackAsync(this IVerifyBlindVerifier verifier, ReadOnlyMemory<byte> rawBody, string? signature, string? timestamp, VerifyBlindCallbackKey key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        return verifier.VerifyCallbackAsync(rawBody, signature, timestamp, key.Rsa, cancellationToken);
    }

    /// <summary><see cref="IVerifyBlindVerifier.VerifyCallbackAsync"/> with the raw body as a string (UTF-8).</summary>
    public static Task<CallbackResult> VerifyCallbackAsync(this IVerifyBlindVerifier verifier, string rawBody, string? signature, string? timestamp, VerifyBlindCallbackKey key, CancellationToken cancellationToken = default) =>
        verifier.VerifyCallbackAsync(Encoding.UTF8.GetBytes(rawBody ?? ""), signature, timestamp, key, cancellationToken);

    /// <summary><see cref="IVerifyBlindVerifier.VerifyCallbackAsync"/> reading the raw body from a stream (e.g. <c>HttpRequest.Body</c>).</summary>
    public static async Task<CallbackResult> VerifyCallbackAsync(this IVerifyBlindVerifier verifier, Stream body, string? signature, string? timestamp, VerifyBlindCallbackKey key, CancellationToken cancellationToken = default) =>
        await verifier.VerifyCallbackAsync(await ReadBodyAsync(body, cancellationToken).ConfigureAwait(false), signature, timestamp, key, cancellationToken).ConfigureAwait(false);

    private static async Task<ReadOnlyMemory<byte>> ReadBodyAsync(Stream body, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(body);
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await body.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > MaxWebhookBodyBytes)
                throw new VerifyBlindException(VerifyBlindErrorCode.BadPayload, "webhook body is too large");
            buffer.Write(chunk, 0, read);
        }
        return buffer.ToArray();
    }
}
