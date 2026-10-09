# VerifyBlind .NET Server Library

> **Kimliğinizi Kanıtlayın, Gizliliğinizi Koruyun** · _Prove Your Identity, Protect Your Privacy_

**[🇹🇷 Türkçe](#türkçe) · [🇬🇧 English](#english)**

---

## Türkçe

VerifyBlind doğrulama sonucunu **kendi sunucunuzda** birkaç satırla doğrulamak için resmi .NET kütüphanesi.
.NET 8+ (`net8.0`; .NET 9 ve 10'da da çalışır). Kripto için yalnız .NET'in kendi `System.Security.Cryptography`
sınıflarını kullanır; tek bağımlılığı `Microsoft.Extensions.DependencyInjection.Abstractions`'tır. ASP.NET Core
(Minimal API ya da controller), worker servisleri ve konsol uygulamalarında kullanılabilir.

## Ne yapar

```
[Web widget / mobil SDK]  ── onSuccess → token ──►  [Sizin sunucunuz]
                                                        │  verifier.VerifyAndConsumeAsync(token, nonceTüket)
                                                        │   1. Enclave imzası (RSA-PSS SHA-256, salt 32)
                                                        │   2. Nonce'u bir kez tüketir (tekrar oynatma koruması)
                                                        │   3. Demo kartı reddeder (varsayılan)
                                                        │   4. Sonucu SİZİN sorduğunuz koşula göre okur
                                                        ▼
                                                  r.Ok == true, r.Validations.Age, r.Validations.UserId, ...
```

- Enclave anahtarını `GET /api/public/enclave-key` adresinden alır, 60 sn önbellekte tutar; imza tutmazsa
  anahtarı **bir kez** tazeleyip yeniden dener (enclave yeniden başlayınca anahtar değişir). Anahtar o çağrıda
  zaten yeni alındıysa tekrar almaz.
- Webhook (callback ve revoke) imzasını doğrular, callback'te `encrypted_response`'u çözer (desen B).
- İsteğe bağlı: PCR0 yetkilendirme imzasını doğrular.
- Hiçbir şey loglamaz. Hata mesajlarında ve `ToString()` çıktılarında `user_id`, `nsbd_id`, `doc_id` geçmez.

## Kurulum

```bash
dotnet add package VerifyBlind.Server
```

## Hızlı Başlangıç: Minimal API

```csharp
using StackExchange.Redis;
using VerifyBlind.Server;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddVerifyBlind();
builder.Services.AddSingleton<IConnectionMultiplexer>(ConnectionMultiplexer.Connect(builder.Configuration["REDIS_URL"]!));
var app = builder.Build();

app.MapPost("/api/verifyblind/verify", async (VerifyRequest req, IVerifyBlindVerifier verifier, IConnectionMultiplexer redis) =>
{
    var db = redis.GetDatabase();
    var r = await verifier.VerifyAndConsumeAsync(req.Token,
        async nonce => (string?)await db.StringGetDeleteAsync($"vb:nonce:{nonce}"));
    if (!r.Ok) return Results.Json(new { error = r.Error.Code }, statusCode: r.Error.HttpStatus);

    // r.Validations.UserId / NsbdId / DocId → veritabanına, LOGA DEĞİL
    return Results.Ok(new { ok = true, age = r.Validations.Age });
});

app.Run();

record VerifyRequest(string? Token);
```

## Hızlı Başlangıç: Controller

```csharp
using Microsoft.AspNetCore.Mvc;
using VerifyBlind.Server;

[ApiController]
[Route("api/verifyblind")]
public class VerifyBlindController(IVerifyBlindVerifier verifier, INonceStore nonces) : ControllerBase
{
    [HttpPost("verify")]
    public async Task<IActionResult> Verify([FromBody] VerifyRequest req, CancellationToken ct)
    {
        var r = await verifier.VerifyAndConsumeAsync(req.Token, nonces.TakeAsync, ct);
        if (!r.Ok) return StatusCode(r.Error.HttpStatus, new { error = r.Error.Code });

        // r.Validations.Age == true → kişi SİZİN sorduğunuz koşulu sağlıyor
        return Ok(new { ok = true, age = r.Validations.Age });
    }
}

public interface INonceStore
{
    /// Al-ve-sil: generate'te sakladığınız JSON'u döndürür; bilinmeyen/süresi dolmuş/kullanılmış nonce için null.
    Task<string?> TakeAsync(string nonce);
}

public record VerifyRequest(string? Token);
```

`Program.cs`'te `builder.Services.AddVerifyBlind();` yeterlidir. Test ortamında demo kartı kabul etmek için:
`builder.Services.AddVerifyBlind(o => o.AllowTestCards = builder.Environment.IsDevelopment());`

## Nonce kuralı

Generate vekilinizde (`POST /api/pop/generate`) dönen `nonce`'u, **sorduğunuz validations ile birlikte**
saklayın (TTL **960 sn**):

```csharp
var asked = new VerifyBlindAsked { Age = "18+", UserId = true };   // tarayıcının gönderdiği DEĞİL, sunucunuzun ayarı
// generate gövdesinde: "validations": asked.ToJson()  →  {"age":"18+","user_id":true}
// ... VerifyBlind'dan { nonce } döndükten sonra:
await db.StringSetAsync($"vb:nonce:{nonce}", asked.ToJson(), TimeSpan.FromSeconds(960));
```

`VerifyAndConsumeAsync`'e verdiğiniz fonksiyon nonce'u **al-ve-sil** şeklinde tüketmelidir (Redis
`StringGetDeleteAsync`, SQL'de `DELETE ... RETURNING` / `DELETE ... OUTPUT`). Bilinmeyen, süresi dolmuş ya da
kullanılmış nonce için `null` döndürün; sonuç `NONCE_NOT_FOUND` olur. Aynı token ikinci kez gelirse reddedilir.
Saklanan değeri JSON metni (`Func<string, Task<string?>>`) ya da `VerifyBlindAsked` nesnesi
(`Func<string, Task<VerifyBlindAsked?>>`) olarak döndürebilirsiniz.

Kütüphane, imza geçersizse nonce deposuna hiç dokunmaz. Deponuzun fırlattığı hatalar yakalanmaz, size ulaşır.

## Sorulan doğrulamalar kuralı

Sonucu **tarayıcının söylediğine göre değil, sizin sakladığınıza göre** okuyun. `CheckAsked` (ve
`VerifyAndConsumeAsync`) şunları denetler:

| Siz sordunuz | İmzalı sonuçta olması gereken |
|---|---|
| `Age = "18+"` | `validations.age` boolean **ve** `validations.age_condition == "18+"` (yoksa ya da farklıysa red) |
| `Age` sormadınız | `validations.age` ve `validations.age_condition` **olmamalı** |
| `UserId = true` | `validations.user_id` dolu olmalı |

Neden: tarayıcı isteği DevTools'ta değiştirilebilir. Ziyaretçi `"18+"`'yı `"1+"` yapar ve gerçekten imzalı bir
`age: true` alır, ama `age_condition: "1+"` olarak imzalanır. Bu kural o sonucu yakalar.

`r.Validations.Age == false` geçerli bir cevaptır (kişi koşulu sağlamıyor); `r.Ok == true` döner, kararı siz verirsiniz.

## Kimlik kodlarını asla loglamayın

`user_id`, `nsbd_id`, `doc_id` takma adlı kişisel veridir. Veritabanına kullanıcı verisi gibi kaydedin;
`ILogger`, istek logları, hata izleme (Sentry vb.) ya da analitiğe **yazmayın**. Bu kütüphane hiçbir şey loglamaz;
hata mesajları ve `ToString()` çıktıları bu kodları `[redacted]` olarak gösterir. Yine de `r.Result.Payload`,
`r.Result.RawPayload` ya da `r.Validations.Raw`'ı loglamayın ve Serilog'da `{@r}` gibi nesne açma (destructuring)
kullanmayın.

Demo kartı sonuçları `validations.is_test: true` taşır (`r.Result.IsTest`) ve kodları `TEST_` ile başlar.
`VerifyAndConsumeAsync` bunları varsayılan olarak `TEST_CARD` hatasıyla reddeder; yalnız test ortamında
`AllowTestCards = true` verin.

## API

| Üye | Açıklama |
|---|---|
| `services.AddVerifyBlind(o => ...)` | Tek bir `VerifyBlindVerifier`'ı singleton kaydeder (`IVerifyBlindVerifier` olarak da). İkinci parametre `sp => HttpClient` ile kendi `HttpClient`'ınızı verebilirsiniz |
| `new VerifyBlindVerifier(options?, httpClient?)` | DI olmadan. Tek örnek tutun: anahtarları önbellekler, iş parçacığı güvenlidir |
| `VerifyAndConsumeAsync(token, consumeNonce, ct)` | İmza → nonce tüketme → demo kart → sorulan koşul. `VerifyBlindOutcome` (`Ok`, `Result`, `Validations`, `Asked`, `Error`). Doğrulama hatasında fırlatmaz |
| `VerifyTokenAsync(token, ct)` | Yalnız imza. `VerifiedResult` döner ya da `VerifyBlindException` fırlatır. Nonce'u siz tüketmelisiniz |
| `VerifySignedAsync(new SignedPayload(payload, signature), ct)` | `VerifyTokenAsync`'in çözülmüş hâli |
| `ConsumeAndCheckAsync(verified, consumeNonce)` | İmzası doğrulanmış sonuç için nonce + demo kart + koşul |
| `VerifyBlindVerifier.CheckAsked(asked, validations)` | Red nedeni (string) ya da `null` |
| `VerifyWebhookAsync(rawBody, signature, timestamp, ct)` | `X-Webhook-Signature` / `X-Webhook-Timestamp` doğrular (±300 sn), JSON gövdeyi (`WebhookBody`) döner. `rawBody`: `byte[]`, `string` ya da `Stream` (`Request.Body`) |
| `VerifyRevokeAsync(...)` | Revoke webhook'u (aynı imza). Yalnız `body.Nonce`'a göre işlem yapın |
| `VerifyCallbackAsync(rawBody, signature, timestamp, key, ct)` | Desen B: webhook + `encrypted_response` çözme + enclave imzası + nonce eşleşmesi. `Status`: `Completed` / `Cancelled` |
| `VerifyBlindCallbackKey.Load(pemOrBase64)` | Callback özel anahtarı (PEM ya da base64 PKCS#8). `PublicKeyBase64` generate'e giden `public_key`, `PkHash` uygulama bağlantısındaki `pk_hash` |
| `CallbackCrypto.DecryptCallbackResponse(encKey, blob, rsa)` | Yalnız çözme (RSA-OAEP-SHA256 + AES-256-GCM) |
| `VerifyPcr0SignatureAsync(pcr0Hex, sigB64, ct)` | İsteğe bağlı enclave kontrolü (PKCS#1 v1.5). Sonra PCR0'ı Enclave reposunun `expected_pcr.json` dosyasıyla kendiniz karşılaştırın |

`VerifyBlindOptions`: `ApiBaseUrl` (`https://api.verifyblind.com`), `KeyCacheDuration` (60 sn),
`WebhookKeyCacheDuration` (1 saat), `KeyRefreshMinInterval` (10 sn: bundan genç anahtar, imza tutmadı diye yeniden
alınmaz), `WebhookTolerance` (300 sn), `HttpTimeout` (10 sn), `AllowTestCards` (`false`), `TimeProvider`.

### Hata kodları (`VerifyBlindException.Code`)

`Code` dizeleri Node.js kütüphanesiyle aynıdır; `HttpStatus` önerilen yanıt kodunu verir.

| Kod | Anlamı | `HttpStatus` |
|---|---|---|
| `BAD_TOKEN` | Token, `{ payload, signature }` JSON'unun base64'ü değil | 400 |
| `BAD_SIGNATURE` | Enclave imzası tutmuyor (anahtar bir kez tazelendikten sonra da) | 401 |
| `KEY_FETCH_FAILED` | VerifyBlind açık anahtarı alınamadı (geçici) | 503 |
| `BAD_PAYLOAD` | İmza geçerli ama gövde beklenen biçimde değil | 400 |
| `NONCE_NOT_FOUND` | Nonce bilinmiyor, süresi dolmuş ya da kullanılmış | 401 |
| `ASKED_MISMATCH` | Sonuç sizin sorduğunuzla eşleşmiyor | 401 |
| `BAD_WEBHOOK_TIMESTAMP` / `BAD_WEBHOOK_SIGNATURE` | Webhook reddedildi | 401 |
| `DECRYPT_FAILED` | `encrypted_response` çözülemedi | 400 |
| `TEST_CARD` | Demo kart sonucu ve `AllowTestCards` kapalı | 403 |

## Revoke webhook'u

Ham gövdeye ihtiyaç var: gövdeyi model bağlamayla (`[FromBody]`) okumayın, `Request.Body`'yi verin.

```csharp
app.MapPost("/api/verifyblind/revoke", async (HttpRequest request, IVerifyBlindVerifier verifier) =>
{
    try
    {
        var body = await verifier.VerifyRevokeAsync(request.Body,
            request.Headers["X-Webhook-Signature"], request.Headers["X-Webhook-Timestamp"]);
        await DeleteVerificationByNonce(body.Nonce); // bu nonce'a bağlı veriyi silin ya da işaretleyin
        return Results.Ok();
    }
    catch (VerifyBlindException e)
    {
        return Results.StatusCode(e.HttpStatus);
    }
});
```

## Desen B (callback)

```csharp
// Sabit RSA-2048 anahtar çifti; özel anahtar ortam değişkeninde, git'e girmez.
var callbackKey = VerifyBlindCallbackKey.Load(builder.Configuration["CALLBACK_PRIVATE_KEY"]!);
// Generate'te: "public_key": callbackKey.PublicKeyBase64, "callback_url": "https://siteniz/api/callback"

app.MapPost("/api/callback", async (HttpRequest request, IVerifyBlindVerifier verifier, IConnectionMultiplexer redis) =>
{
    try
    {
        var r = await verifier.VerifyCallbackAsync(request.Body,
            request.Headers["X-Webhook-Signature"], request.Headers["X-Webhook-Timestamp"], callbackKey);
        if (r.Status == CallbackStatus.Cancelled)
        {
            await SaveStatus(r.Nonce, "cancelled", r.Reason);
        }
        else
        {
            var db = redis.GetDatabase();
            var checkedResult = await verifier.ConsumeAndCheckAsync(r.Verified!,
                async nonce => (string?)await db.StringGetDeleteAsync($"vb:nonce:{nonce}"));
            if (checkedResult.Ok) await SaveStatus(r.Nonce, "completed", null);
        }
    }
    catch (VerifyBlindException) { /* imza/çözme hatası: sonucu saklamayın */ }
    return Results.Ok();
});
```

## Güvenlik Notları

- API anahtarı (`VERIFYBLIND_API_KEY`) yalnız sunucuda durur. Bu kütüphane API anahtarı istemez; yalnız açık
  uç noktalardan açık anahtarları okur.
- Sorulacak `validations`'ı generate vekilinizde sunucu ayarından koyun; tarayıcının gönderdiğini yok sayın.
- Kurallar ve tüm akış: https://verifyblind.com/ai-integration.md · https://verifyblind.com/tr/developers

## Sürüm Geçmişi

| Sürüm | Açıklama |
|---------|-------------|
| 1.0.0 | İlk sürüm: token doğrulama, nonce + demo kart + sorulan koşul, webhook/revoke, callback çözme, PCR0, `AddVerifyBlind` |

---

## English

The official .NET library for verifying a VerifyBlind result **on your own server** in a few lines.
.NET 8+ (`net8.0`; runs on .NET 9 and 10 too). Cryptography uses only .NET's own `System.Security.Cryptography`;
the single dependency is `Microsoft.Extensions.DependencyInjection.Abstractions`. Works in ASP.NET Core (Minimal API
or controllers), worker services and console apps.

### What it does

```
[Web widget / mobile SDK]  ── onSuccess → token ──►  [Your server]
                                                        │  verifier.VerifyAndConsumeAsync(token, consumeNonce)
                                                        │   1. Enclave signature (RSA-PSS SHA-256, salt 32)
                                                        │   2. Consumes the nonce exactly once (replay protection)
                                                        │   3. Rejects demo cards (default)
                                                        │   4. Reads the result against what YOU asked
                                                        ▼
                                                  r.Ok == true, r.Validations.Age, r.Validations.UserId, ...
```

- Fetches the enclave key from `GET /api/public/enclave-key`, caches it for 60 s, and on a failed signature
  refreshes it **once** and retries (the key rotates when the enclave restarts). A key fetched for the same call
  is not fetched again.
- Verifies webhook signatures (callback and revoke) and decrypts the callback `encrypted_response` (pattern B).
- Optional: verifies the PCR0 authorization signature.
- Logs nothing. Error messages and `ToString()` output never contain `user_id`, `nsbd_id` or `doc_id`.

### Installation

```bash
dotnet add package VerifyBlind.Server
```

### Quick Start: Minimal API

```csharp
using StackExchange.Redis;
using VerifyBlind.Server;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddVerifyBlind();
builder.Services.AddSingleton<IConnectionMultiplexer>(ConnectionMultiplexer.Connect(builder.Configuration["REDIS_URL"]!));
var app = builder.Build();

app.MapPost("/api/verifyblind/verify", async (VerifyRequest req, IVerifyBlindVerifier verifier, IConnectionMultiplexer redis) =>
{
    var db = redis.GetDatabase();
    var r = await verifier.VerifyAndConsumeAsync(req.Token,
        async nonce => (string?)await db.StringGetDeleteAsync($"vb:nonce:{nonce}"));
    if (!r.Ok) return Results.Json(new { error = r.Error.Code }, statusCode: r.Error.HttpStatus);

    // r.Validations.UserId / NsbdId / DocId → database, NOT logs
    return Results.Ok(new { ok = true, age = r.Validations.Age });
});

app.Run();

record VerifyRequest(string? Token);
```

### Quick Start: Controller

```csharp
using Microsoft.AspNetCore.Mvc;
using VerifyBlind.Server;

[ApiController]
[Route("api/verifyblind")]
public class VerifyBlindController(IVerifyBlindVerifier verifier, INonceStore nonces) : ControllerBase
{
    [HttpPost("verify")]
    public async Task<IActionResult> Verify([FromBody] VerifyRequest req, CancellationToken ct)
    {
        var r = await verifier.VerifyAndConsumeAsync(req.Token, nonces.TakeAsync, ct);
        if (!r.Ok) return StatusCode(r.Error.HttpStatus, new { error = r.Error.Code });

        // r.Validations.Age == true → the person meets the condition YOU asked
        return Ok(new { ok = true, age = r.Validations.Age });
    }
}

public interface INonceStore
{
    /// Get-and-delete: returns the JSON stored at generate; null for an unknown, expired or used nonce.
    Task<string?> TakeAsync(string nonce);
}

public record VerifyRequest(string? Token);
```

In `Program.cs`, `builder.Services.AddVerifyBlind();` is enough. To accept the demo card on a test setup:
`builder.Services.AddVerifyBlind(o => o.AllowTestCards = builder.Environment.IsDevelopment());`

### The nonce rule

In your generate proxy (`POST /api/pop/generate`), store the returned `nonce` **together with the validations
you asked** (TTL **960 s**):

```csharp
var asked = new VerifyBlindAsked { Age = "18+", UserId = true };   // your server's setting, NOT what the browser sent
// in the generate body: "validations": asked.ToJson()  →  {"age":"18+","user_id":true}
// ... after VerifyBlind returns { nonce }:
await db.StringSetAsync($"vb:nonce:{nonce}", asked.ToJson(), TimeSpan.FromSeconds(960));
```

The function you pass to `VerifyAndConsumeAsync` must **get-and-delete** the nonce (Redis `StringGetDeleteAsync`,
SQL `DELETE ... RETURNING` / `DELETE ... OUTPUT`). Return `null` for an unknown, expired or used nonce; the result
is then `NONCE_NOT_FOUND`. The same token presented twice is rejected. Return the stored value as JSON text
(`Func<string, Task<string?>>`) or as a `VerifyBlindAsked` object (`Func<string, Task<VerifyBlindAsked?>>`).

The library does not touch your nonce store when the signature is invalid. Exceptions thrown by your store are
not caught; they reach you.

### The asked-validations rule

Read the result against **what you stored, not what the browser says**. `CheckAsked` (and `VerifyAndConsumeAsync`)
enforce:

| You asked | The signed result must have |
|---|---|
| `Age = "18+"` | `validations.age` boolean **and** `validations.age_condition == "18+"` (missing or different → reject) |
| no `Age` | **no** `validations.age` and no `validations.age_condition` |
| `UserId = true` | a non-empty `validations.user_id` |

Why: the browser request can be edited in DevTools. A visitor changes `"18+"` to `"1+"` and receives a genuinely
signed `age: true`, but it is signed with `age_condition: "1+"`. This rule catches it.

`r.Validations.Age == false` is a valid answer (the person does not meet the condition): you get `r.Ok == true` and
make the decision yourself.

### Never log identity codes

`user_id`, `nsbd_id` and `doc_id` are pseudonymous personal data. Store them like other user data; **never** write
them to `ILogger`, request logs, error tracking (Sentry etc.) or analytics. This library logs nothing; error
messages and `ToString()` output show these codes as `[redacted]`. Still, do not log `r.Result.Payload`,
`r.Result.RawPayload` or `r.Validations.Raw`, and do not destructure the result in Serilog (`{@r}`).

Demo-card results carry `validations.is_test: true` (`r.Result.IsTest`) and codes prefixed `TEST_`.
`VerifyAndConsumeAsync` rejects them by default with `TEST_CARD`; set `AllowTestCards = true` on test setups only.

### API

| Member | Description |
|---|---|
| `services.AddVerifyBlind(o => ...)` | Registers one `VerifyBlindVerifier` as a singleton (also as `IVerifyBlindVerifier`). Pass `sp => HttpClient` as the second argument to use your own `HttpClient` |
| `new VerifyBlindVerifier(options?, httpClient?)` | Without DI. Keep one instance: it caches the keys and is thread-safe |
| `VerifyAndConsumeAsync(token, consumeNonce, ct)` | Signature → nonce consume → demo card → asked check. `VerifyBlindOutcome` (`Ok`, `Result`, `Validations`, `Asked`, `Error`). Does not throw for verification failures |
| `VerifyTokenAsync(token, ct)` | Signature only. Returns `VerifiedResult` or throws `VerifyBlindException`. You must consume the nonce |
| `VerifySignedAsync(new SignedPayload(payload, signature), ct)` | `VerifyTokenAsync` for an already-decoded token |
| `ConsumeAndCheckAsync(verified, consumeNonce)` | Nonce + demo card + asked check for a result whose signature is already verified |
| `VerifyBlindVerifier.CheckAsked(asked, validations)` | A rejection reason (string) or `null` |
| `VerifyWebhookAsync(rawBody, signature, timestamp, ct)` | Verifies `X-Webhook-Signature` / `X-Webhook-Timestamp` (±300 s), returns the JSON body (`WebhookBody`). `rawBody`: `byte[]`, `string` or `Stream` (`Request.Body`) |
| `VerifyRevokeAsync(...)` | Revoke webhook (same signature). Act on `body.Nonce` only |
| `VerifyCallbackAsync(rawBody, signature, timestamp, key, ct)` | Pattern B: webhook + `encrypted_response` decrypt + enclave signature + nonce match. `Status`: `Completed` / `Cancelled` |
| `VerifyBlindCallbackKey.Load(pemOrBase64)` | Callback private key (PEM or base64 PKCS#8). `PublicKeyBase64` is the `public_key` for generate, `PkHash` the `pk_hash` of the app link |
| `CallbackCrypto.DecryptCallbackResponse(encKey, blob, rsa)` | Decrypt only (RSA-OAEP-SHA256 + AES-256-GCM) |
| `VerifyPcr0SignatureAsync(pcr0Hex, sigB64, ct)` | Optional enclave check (PKCS#1 v1.5). Then compare the PCR0 with `expected_pcr.json` from the Enclave repo yourself |

`VerifyBlindOptions`: `ApiBaseUrl` (`https://api.verifyblind.com`), `KeyCacheDuration` (60 s),
`WebhookKeyCacheDuration` (1 hour), `KeyRefreshMinInterval` (10 s: a younger key is not fetched again because a
signature failed), `WebhookTolerance` (300 s), `HttpTimeout` (10 s), `AllowTestCards` (`false`), `TimeProvider`.

#### Error codes (`VerifyBlindException.Code`)

The `Code` strings are the same as in the Node.js library; `HttpStatus` gives the suggested response status.

| Code | Meaning | `HttpStatus` |
|---|---|---|
| `BAD_TOKEN` | The token is not base64 of JSON `{ payload, signature }` | 400 |
| `BAD_SIGNATURE` | The enclave signature does not verify (also after one key refresh) | 401 |
| `KEY_FETCH_FAILED` | A VerifyBlind public key could not be fetched (temporary) | 503 |
| `BAD_PAYLOAD` | Valid signature, but the body is not in the expected shape | 400 |
| `NONCE_NOT_FOUND` | Nonce unknown, expired or already used | 401 |
| `ASKED_MISMATCH` | The result does not match what you asked | 401 |
| `BAD_WEBHOOK_TIMESTAMP` / `BAD_WEBHOOK_SIGNATURE` | Webhook rejected | 401 |
| `DECRYPT_FAILED` | `encrypted_response` could not be decrypted | 400 |
| `TEST_CARD` | Demo-card result while `AllowTestCards` is off | 403 |

### Revoke webhook

You need the raw body: do not bind it (`[FromBody]`), pass `Request.Body`.

```csharp
app.MapPost("/api/verifyblind/revoke", async (HttpRequest request, IVerifyBlindVerifier verifier) =>
{
    try
    {
        var body = await verifier.VerifyRevokeAsync(request.Body,
            request.Headers["X-Webhook-Signature"], request.Headers["X-Webhook-Timestamp"]);
        await DeleteVerificationByNonce(body.Nonce); // delete or mark the data tied to this nonce
        return Results.Ok();
    }
    catch (VerifyBlindException e)
    {
        return Results.StatusCode(e.HttpStatus);
    }
});
```

### Pattern B (callback)

```csharp
// A fixed RSA-2048 key pair; the private key lives in an environment variable, never in git.
var callbackKey = VerifyBlindCallbackKey.Load(builder.Configuration["CALLBACK_PRIVATE_KEY"]!);
// At generate: "public_key": callbackKey.PublicKeyBase64, "callback_url": "https://your-site/api/callback"

app.MapPost("/api/callback", async (HttpRequest request, IVerifyBlindVerifier verifier, IConnectionMultiplexer redis) =>
{
    try
    {
        var r = await verifier.VerifyCallbackAsync(request.Body,
            request.Headers["X-Webhook-Signature"], request.Headers["X-Webhook-Timestamp"], callbackKey);
        if (r.Status == CallbackStatus.Cancelled)
        {
            await SaveStatus(r.Nonce, "cancelled", r.Reason);
        }
        else
        {
            var db = redis.GetDatabase();
            var checkedResult = await verifier.ConsumeAndCheckAsync(r.Verified!,
                async nonce => (string?)await db.StringGetDeleteAsync($"vb:nonce:{nonce}"));
            if (checkedResult.Ok) await SaveStatus(r.Nonce, "completed", null);
        }
    }
    catch (VerifyBlindException) { /* signature/decrypt error: do not store a result */ }
    return Results.Ok();
});
```

### Security Notes

- The API key (`VERIFYBLIND_API_KEY`) stays on the server. This library does not need the API key; it only
  reads public keys from public endpoints.
- Set the `validations` to ask in your generate proxy from server configuration; ignore what the browser sent.
- Rules and the full flow: https://verifyblind.com/ai-integration.md · https://verifyblind.com/en/developers

### Version History

| Version | Description |
|---------|-------------|
| 1.0.0 | First release: token verify, nonce + demo card + asked check, webhook/revoke, callback decrypt, PCR0, `AddVerifyBlind` |

---

## Lisans · License

Apache License 2.0 — bkz. / see [LICENSE](LICENSE).
