namespace VerifyBlind.Server;

/// <summary>
/// The stable error codes of this library. They are the same strings the Node.js library
/// (<c>@verifyblind/server</c>) uses, so you can return them to your client unchanged.
/// Branch on the code, not on the message (messages may change).
/// </summary>
public static class VerifyBlindErrorCode
{
    /// <summary>The token is not base64 of JSON <c>{ payload, signature }</c>. HTTP 400.</summary>
    public const string BadToken = "BAD_TOKEN";

    /// <summary>The enclave signature does not verify (also after one key refresh). HTTP 401.</summary>
    public const string BadSignature = "BAD_SIGNATURE";

    /// <summary>A VerifyBlind public key could not be fetched or read. Usually temporary. HTTP 503.</summary>
    public const string KeyFetchFailed = "KEY_FETCH_FAILED";

    /// <summary>The signature is valid but the body is not in the expected shape (e.g. no nonce). HTTP 400.</summary>
    public const string BadPayload = "BAD_PAYLOAD";

    /// <summary>The nonce is unknown to your store: expired or already used (replay). HTTP 401.</summary>
    public const string NonceNotFound = "NONCE_NOT_FOUND";

    /// <summary>The signed result does not match what your server asked for this nonce. HTTP 401.</summary>
    public const string AskedMismatch = "ASKED_MISMATCH";

    /// <summary>Webhook timestamp header missing, not a number, or outside the allowed window. HTTP 401.</summary>
    public const string BadWebhookTimestamp = "BAD_WEBHOOK_TIMESTAMP";

    /// <summary>Webhook signature header missing or not valid (also after one key refresh). HTTP 401.</summary>
    public const string BadWebhookSignature = "BAD_WEBHOOK_SIGNATURE";

    /// <summary>The callback <c>encrypted_response</c> could not be decrypted with your private key. HTTP 400.</summary>
    public const string DecryptFailed = "DECRYPT_FAILED";

    /// <summary>A demo-card result while <see cref="VerifyBlindOptions.AllowTestCards"/> is off. HTTP 403.</summary>
    public const string TestCard = "TEST_CARD";

    /// <summary>The suggested HTTP status for your endpoint's response to a given code.</summary>
    public static int SuggestedHttpStatus(string code) => code switch
    {
        BadToken or BadPayload or DecryptFailed => 400,
        BadSignature or NonceNotFound or AskedMismatch or BadWebhookTimestamp or BadWebhookSignature => 401,
        TestCard => 403,
        KeyFetchFailed => 503,
        _ => 400,
    };
}

/// <summary>
/// Every failure this library reports. <see cref="Code"/> is one of <see cref="VerifyBlindErrorCode"/>.
/// Messages never contain <c>user_id</c>, <c>nsbd_id</c> or <c>doc_id</c>.
/// </summary>
public sealed class VerifyBlindException : Exception
{
    /// <summary>Creates an error with one of the <see cref="VerifyBlindErrorCode"/> values.</summary>
    public VerifyBlindException(string code, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        Code = code;
    }

    /// <summary>Stable machine-readable code, e.g. <c>"BAD_SIGNATURE"</c>.</summary>
    public string Code { get; }

    /// <summary>The suggested HTTP status for your endpoint's response (400, 401, 403 or 503).</summary>
    public int HttpStatus => VerifyBlindErrorCode.SuggestedHttpStatus(Code);
}
