using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace VerifyBlind.Server;

/// <summary>
/// What YOUR server asked VerifyBlind at generate time (the <c>validations</c> you sent to
/// <c>POST /api/pop/generate</c>). Store it together with the returned nonce, for example as
/// <see cref="ToJson"/>, and give it back when the nonce is consumed.
/// </summary>
/// <example><c>new VerifyBlindAsked { Age = "18+", UserId = true }</c></example>
public sealed class VerifyBlindAsked
{
    /// <summary>Age condition, e.g. <c>"18+"</c>, <c>"16-"</c>, <c>"18-65"</c>, <c>"24"</c>. <c>null</c> when age was not asked.</summary>
    public string? Age { get; init; }

    /// <summary><c>true</c> when you asked for the pseudonymous codes (<c>user_id</c>, <c>nsbd_id</c>, <c>doc_id</c>).</summary>
    public bool UserId { get; init; }

    /// <summary>
    /// The JSON you send as <c>validations</c> to <c>POST /api/pop/generate</c> and store with the nonce,
    /// e.g. <c>{"age":"18+","user_id":true}</c>.
    /// </summary>
    public string ToJson()
    {
        using var stream = new MemoryStream();
        // Relaxed escaping: the default encoder writes "+" as a \u escape (same JSON, harder to read in your store).
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            writer.WriteStartObject();
            if (Age is not null) writer.WriteString("age", Age);
            if (UserId) writer.WriteBoolean("user_id", true);
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    /// <summary>
    /// Reads the JSON you stored with the nonce. Returns <c>false</c> when it is not a JSON object or
    /// <c>age</c> is neither a string nor null. <c>user_id</c> counts as asked only when it is JSON <c>true</c>.
    /// </summary>
    public static bool TryParse(string? json, out VerifyBlindAsked? asked)
    {
        asked = null;
        if (string.IsNullOrWhiteSpace(json)) return false;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return false;

            string? age = null;
            if (root.TryGetProperty("age", out var a))
            {
                if (a.ValueKind == JsonValueKind.String) age = a.GetString();
                else if (a.ValueKind != JsonValueKind.Null) return false;
            }
            var userId = root.TryGetProperty("user_id", out var u) && u.ValueKind == JsonValueKind.True;
            asked = new VerifyBlindAsked { Age = age, UserId = userId };
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <inheritdoc />
    public override string ToString() => ToJson();
}
