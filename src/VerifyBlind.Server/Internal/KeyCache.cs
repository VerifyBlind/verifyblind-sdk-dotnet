namespace VerifyBlind.Server.Internal;

/// <summary>
/// Caches one public key (SPKI DER bytes) with a TTL and shares a single in-flight request between
/// concurrent callers. Bytes, not RSA objects: each verification imports its own RSA instance, so a key
/// replaced by a refresh is never disposed under another thread.
/// </summary>
internal sealed class KeyCache
{
    private readonly Func<CancellationToken, Task<byte[]>> _load;
    private readonly TimeSpan _ttl;
    private readonly TimeSpan _minRefreshInterval;
    private readonly TimeProvider _time;
    private readonly object _lock = new();

    private byte[]? _key;
    private DateTimeOffset _fetchedAt;
    private Task<byte[]>? _inflight;

    public KeyCache(Func<CancellationToken, Task<byte[]>> load, TimeSpan ttl, TimeSpan minRefreshInterval, TimeProvider time)
    {
        _load = load;
        _ttl = ttl;
        _minRefreshInterval = minRefreshInterval;
        _time = time;
    }

    /// <summary>
    /// The cached key, or a freshly fetched one. <c>Fresh</c> is true when it was fetched for this call
    /// (a retry with a refresh is then useless).
    /// </summary>
    public async Task<(byte[] Key, bool Fresh)> GetAsync(CancellationToken cancellationToken)
    {
        Task<byte[]> task;
        lock (_lock)
        {
            if (_key is not null && _time.GetUtcNow() - _fetchedAt < _ttl) return (_key, false);
            task = StartFetch();
        }
        return (await task.WaitAsync(cancellationToken).ConfigureAwait(false), true);
    }

    /// <summary>
    /// Called after <paramref name="stale"/> failed to verify a signature. Returns a different key to retry
    /// with, or <c>null</c> when a retry cannot help (the key is current or did not change).
    /// </summary>
    public async Task<byte[]?> RefreshAsync(byte[] stale, CancellationToken cancellationToken)
    {
        Task<byte[]> task;
        lock (_lock)
        {
            // Another caller already replaced the key: retry with it, no request needed.
            if (_key is not null && !ReferenceEquals(_key, stale)) return _key;
            // Fetched moments ago: it is current, the signature is simply wrong.
            if (_key is not null && _time.GetUtcNow() - _fetchedAt < _minRefreshInterval) return null;
            task = StartFetch();
        }
        var fresh = await task.WaitAsync(cancellationToken).ConfigureAwait(false);
        return fresh.AsSpan().SequenceEqual(stale) ? null : fresh;
    }

    public void Clear()
    {
        lock (_lock)
        {
            _key = null;
            _fetchedAt = default;
        }
    }

    // Caller holds _lock.
    private Task<byte[]> StartFetch()
    {
        if (_inflight is not null) return _inflight;
        // The shared fetch must not die with one caller's cancellation: callers cancel their wait instead.
        var task = FetchAndStoreAsync();
        // A fetch that finished synchronously has already run its finally block: do not keep it as in-flight.
        if (!task.IsCompleted) _inflight = task;
        return task;
    }

    private async Task<byte[]> FetchAndStoreAsync()
    {
        try
        {
            var key = await _load(CancellationToken.None).ConfigureAwait(false);
            lock (_lock)
            {
                _key = key;
                _fetchedAt = _time.GetUtcNow();
            }
            return key;
        }
        finally
        {
            lock (_lock) _inflight = null;
        }
    }
}
