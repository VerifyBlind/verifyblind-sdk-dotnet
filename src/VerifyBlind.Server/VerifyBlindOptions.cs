namespace VerifyBlind.Server;

/// <summary>Settings for <see cref="VerifyBlindVerifier"/>. The defaults suit production.</summary>
public sealed class VerifyBlindOptions
{
    /// <summary>The production API.</summary>
    public const string DefaultApiBaseUrl = "https://api.verifyblind.com";

    /// <summary>VerifyBlind API base URL. Default <c>https://api.verifyblind.com</c>.</summary>
    public string ApiBaseUrl { get; set; } = DefaultApiBaseUrl;

    /// <summary>How long the enclave public key is cached. Default 60 s (the key rotates when the enclave restarts).</summary>
    public TimeSpan KeyCacheDuration { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>How long the webhook-signing and developer public keys are cached. Default 1 hour.</summary>
    public TimeSpan WebhookKeyCacheDuration { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// A cached key younger than this is not fetched again when a signature fails: it is current, the signature
    /// is simply wrong. Keeps requests with bad signatures from making your server hammer the API. Default 10 s.
    /// </summary>
    public TimeSpan KeyRefreshMinInterval { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Allowed clock difference for webhook timestamps. Default 300 s (±5 minutes).</summary>
    public TimeSpan WebhookTolerance { get; set; } = TimeSpan.FromSeconds(300);

    /// <summary>Timeout of one public-key request. Default 10 s.</summary>
    public TimeSpan HttpTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Accept demo-card results (<c>validations.is_test: true</c> or <c>TEST_</c> codes). Demo cards work only for
    /// test partners. Default <c>false</c> (rejected with <c>TEST_CARD</c>): turn on for test setups only.
    /// </summary>
    public bool AllowTestCards { get; set; }

    /// <summary>Clock replacement for tests. Default <see cref="TimeProvider.System"/>.</summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    internal VerifyBlindOptions Validated()
    {
        if (!Uri.TryCreate(ApiBaseUrl, UriKind.Absolute, out var uri) || (uri.Scheme != "https" && uri.Scheme != "http"))
            throw new ArgumentException("ApiBaseUrl must be an absolute http(s) URL.", nameof(ApiBaseUrl));
        if (HttpTimeout <= TimeSpan.Zero)
            throw new ArgumentException("HttpTimeout must be positive.", nameof(HttpTimeout));
        ArgumentNullException.ThrowIfNull(TimeProvider);
        return new VerifyBlindOptions
        {
            ApiBaseUrl = ApiBaseUrl.TrimEnd('/'),
            KeyCacheDuration = KeyCacheDuration,
            WebhookKeyCacheDuration = WebhookKeyCacheDuration,
            KeyRefreshMinInterval = KeyRefreshMinInterval,
            WebhookTolerance = WebhookTolerance,
            HttpTimeout = HttpTimeout,
            AllowTestCards = AllowTestCards,
            TimeProvider = TimeProvider,
        };
    }
}
