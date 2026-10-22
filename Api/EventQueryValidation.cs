using iisidsd.Networking;

namespace iisidsd.Api;

internal static class EventQueryValidation
{
    public static bool TryValidate(
        int? limit,
        int defaultLimit,
        int maximumLimit,
        string? clientIp,
        string? domain,
        out int normalizedLimit,
        out string? normalizedClientIp,
        out string? normalizedDomain,
        out Dictionary<string, string[]> errors)
    {
        normalizedLimit = limit ?? defaultLimit;
        normalizedClientIp = null;
        normalizedDomain = null;
        errors = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

        if (normalizedLimit is < 1 || normalizedLimit > maximumLimit)
        {
            errors["limit"] = [$"Limit must be between 1 and {maximumLimit}."];
        }

        if (clientIp is not null)
        {
            if (!IpAddressNormalizer.TryNormalize(clientIp, out var parsedClientIp))
            {
                errors["clientIp"] = ["Client IP must be a valid IPv4 or IPv6 address."];
            }
            else
            {
                normalizedClientIp = parsedClientIp;
            }
        }

        if (domain is not null)
        {
            if (string.IsNullOrWhiteSpace(domain) || domain.Length > 253 || domain.Any(char.IsControl))
            {
                errors["domain"] = ["Domain must contain 1 to 253 non-control characters."];
            }
            else
            {
                normalizedDomain = domain.Trim();
            }
        }

        return errors.Count == 0;
    }

    public static IResult ValidationProblem(Dictionary<string, string[]> errors)
        => Results.ValidationProblem(errors);
}