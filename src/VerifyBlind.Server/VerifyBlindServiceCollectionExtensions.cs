using Microsoft.Extensions.DependencyInjection.Extensions;
using VerifyBlind.Server;

// The usual home of Add* extensions, so `services.AddVerifyBlind()` needs no extra using.
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Registers VerifyBlind in an ASP.NET Core (or any Microsoft.Extensions.DependencyInjection) container.</summary>
public static class VerifyBlindServiceCollectionExtensions
{
    /// <summary>
    /// Registers one <see cref="VerifyBlindVerifier"/> as a singleton, resolvable as <see cref="VerifyBlindVerifier"/>
    /// and <see cref="IVerifyBlindVerifier"/>. It uses this library's shared <see cref="HttpClient"/>.
    /// </summary>
    /// <example><code>builder.Services.AddVerifyBlind(o => o.AllowTestCards = builder.Environment.IsDevelopment());</code></example>
    public static IServiceCollection AddVerifyBlind(this IServiceCollection services, Action<VerifyBlindOptions>? configure = null) =>
        services.AddVerifyBlind(configure, httpClient: null);

    /// <summary>
    /// Same as <see cref="AddVerifyBlind(IServiceCollection, Action{VerifyBlindOptions}?)"/> with your own
    /// <see cref="HttpClient"/> (proxy, custom handler), e.g.
    /// <c>sp =&gt; sp.GetRequiredService&lt;IHttpClientFactory&gt;().CreateClient("verifyblind")</c>.
    /// The verifier is a singleton and keeps the client it is given.
    /// </summary>
    public static IServiceCollection AddVerifyBlind(this IServiceCollection services, Action<VerifyBlindOptions>? configure, Func<IServiceProvider, HttpClient>? httpClient)
    {
        ArgumentNullException.ThrowIfNull(services);
        var options = new VerifyBlindOptions();
        configure?.Invoke(options);
        options.Validated(); // fail at startup, not on the first request

        services.TryAddSingleton(sp => new VerifyBlindVerifier(options, httpClient?.Invoke(sp)));
        services.TryAddSingleton<IVerifyBlindVerifier>(sp => sp.GetRequiredService<VerifyBlindVerifier>());
        return services;
    }
}
