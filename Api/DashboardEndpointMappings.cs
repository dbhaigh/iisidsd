using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using iisidsd.Configuration;
using iisidsd.Iis;
using iisidsd.Models;
using iisidsd.Networking;
using iisidsd.Observability;
using iisidsd.Services;
using iisidsd.Storage;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace iisidsd.Api;

public static class DashboardEndpointMappings
{
    public static void MapDashboardEndpoints(this WebApplication webApp, JsonSerializerOptions jsonOptions)
    {
        webApp.MapGet("/health", (SqliteHealthProbe sqliteHealthProbe) =>
        {
            var sqliteConnectionHealthy = sqliteHealthProbe.IsHealthy();
            return Results.Json(new { status = sqliteConnectionHealthy ? "ok" : "degraded" }, statusCode: sqliteConnectionHealthy
                ? StatusCodes.Status200OK
                : StatusCodes.Status503ServiceUnavailable);
        }).AllowAnonymous();

        webApp.MapGet("/metrics", (IisObservability observability) =>
            Results.Text(observability.RenderPrometheus(), contentType: "text/plain; version=0.0.4; charset=utf-8"))
            .RequireAuthorization("DashboardAdministrator");

        webApp.MapGet("/api/events", (IEventStore store, int? limit, string? clientIp, string? domain, bool? suspiciousOnly) =>
        {
            if (!EventQueryValidation.TryValidate(limit, 100, 1_000, clientIp, domain,
                    out var normalizedLimit, out var normalizedClientIp, out var normalizedDomain, out var errors))
            {
                return EventQueryValidation.ValidationProblem(errors);
            }

            return Results.Ok(store.GetRecent(normalizedLimit, normalizedClientIp, normalizedDomain, suspiciousOnly ?? false));
        });

        webApp.MapGet("/api/findings", (IIpAggregationService aggregationService, int? limit, string? domain) =>
        {
            if (!EventQueryValidation.TryValidate(limit, 100, 500, null, domain,
                    out var normalizedLimit, out _, out var normalizedDomain, out var errors))
            {
                return EventQueryValidation.ValidationProblem(errors);
            }

            return Results.Ok(aggregationService.GetFindings(normalizedLimit, normalizedDomain));
        });

        webApp.MapGet("/api/incidents", (IAnalystIncidentStore incidentStore, int? limit) =>
            Results.Ok(incidentStore.List(limit ?? 250)))
            .RequireAuthorization("DashboardAdministrator");

        webApp.MapPut("/api/incidents/{clientIp}", (
            IAnalystIncidentStore incidentStore,
            HttpContext context,
            string clientIp,
            AnalystIncidentUpdateRequest request) =>
        {
            if (!IpAddressNormalizer.TryNormalize(clientIp, out var normalizedIp))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    [nameof(clientIp)] = ["Client IP must be a valid IPv4 or IPv6 address."]
                });
            }

            if (request.Status is not ("open" or "acknowledged" or "suppressed" or "resolved"))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    [nameof(request.Status)] = ["Status must be open, acknowledged, suppressed, or resolved."]
                });
            }

            if (request.Note is null || request.Note.Length > 4000 || request.Note.Any(char.IsControl) && request.Note.Any(character => character is not '\r' and not '\n' and not '\t'))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    [nameof(request.Note)] = ["Note must be 4,000 characters or fewer and cannot contain control characters."]
                });
            }

            return Results.Ok(incidentStore.Save(
                normalizedIp,
                request.Status,
                request.Note,
                context.User.Identity?.Name ?? "unknown"));
        }).RequireAuthorization("DashboardAdministrator");

        webApp.MapGet("/api/findings/{clientIp}", (IIpAggregationService aggregationService, string clientIp, string? domain) =>
        {
            if (!EventQueryValidation.TryValidate(null, 1, 1, clientIp, domain,
                    out _, out var normalizedClientIp, out var normalizedDomain, out var errors))
            {
                return EventQueryValidation.ValidationProblem(errors);
            }

            var finding = aggregationService.GetFinding(normalizedClientIp!, normalizedDomain);
            return finding is null ? Results.NotFound() : Results.Ok(finding);
        });

        webApp.MapGet("/api/findings/{clientIp}/events", (IEventStore store, string clientIp, int? limit, string? domain, bool? suspiciousOnly) =>
        {
            if (!EventQueryValidation.TryValidate(limit, 250, 1_000, clientIp, domain,
                    out var normalizedLimit, out var normalizedClientIp, out var normalizedDomain, out var errors))
            {
                return EventQueryValidation.ValidationProblem(errors);
            }

            return Results.Ok(store.GetRecent(normalizedLimit, normalizedClientIp, normalizedDomain, suspiciousOnly ?? false));
        });

        webApp.MapGet("/api/export/findings", (
            IIpAggregationService aggregationService,
            int? limit,
            string? domain,
            string? format) =>
        {
            if (!EventQueryValidation.TryValidate(limit, 100, 500, null, domain,
                    out var normalizedLimit, out _, out var normalizedDomain, out var errors))
            {
                return EventQueryValidation.ValidationProblem(errors);
            }

            var findings = aggregationService.GetFindings(normalizedLimit, normalizedDomain);
            return CreateExportResult(
                findings,
                "findings",
                format,
                jsonOptions,
                ["clientIp", "requestCount", "suspiciousRequestCount", "highestRiskScore", "highestRiskSeverity", "firstSeen", "lastSeen", "domains", "detectionReasons", "riskIndicators", "isDenied", "banCount", "banStarted", "banEnds", "banDurationHours"],
                finding =>
                [
                    finding.ClientIp,
                    finding.RequestCount.ToString(CultureInfo.InvariantCulture),
                    finding.SuspiciousRequestCount.ToString(CultureInfo.InvariantCulture),
                    finding.HighestRiskScore.ToString(CultureInfo.InvariantCulture),
                    finding.HighestRiskSeverity,
                    finding.FirstSeen.ToString("O", CultureInfo.InvariantCulture),
                    finding.LastSeen.ToString("O", CultureInfo.InvariantCulture),
                    JsonSerializer.Serialize(finding.Domains, jsonOptions),
                    JsonSerializer.Serialize(finding.DetectionReasons, jsonOptions),
                    JsonSerializer.Serialize(finding.RiskIndicators, jsonOptions),
                    finding.IsDenied.ToString(),
                    finding.BanCount.ToString(CultureInfo.InvariantCulture),
                    finding.BanStarted?.ToString("O", CultureInfo.InvariantCulture),
                    finding.BanEnds?.ToString("O", CultureInfo.InvariantCulture),
                    finding.BanDurationHours.ToString(CultureInfo.InvariantCulture)
                ]);
        }).RequireAuthorization("DashboardAdministrator");

        webApp.MapGet("/api/export/events", (
            IEventStore store,
            int? limit,
            string? clientIp,
            string? domain,
            bool? suspiciousOnly,
            string? format) =>
        {
            if (!EventQueryValidation.TryValidate(limit, 100, 10_000, clientIp, domain,
                    out var normalizedLimit, out var normalizedClientIp, out var normalizedDomain, out var errors))
            {
                return EventQueryValidation.ValidationProblem(errors);
            }

            var events = store.GetRecent(normalizedLimit, normalizedClientIp, normalizedDomain, suspiciousOnly ?? false);
            return CreateExportResult(
                events,
                "events",
                format,
                jsonOptions,
                ["timestamp", "eventId", "server", "domain", "method", "path", "clientIp", "statusCode", "userAgent", "isSuspicious", "detectionReason", "riskScore", "riskSeverity", "riskIndicators", "properties"],
                webEvent =>
                [
                    webEvent.Timestamp.ToString("O", CultureInfo.InvariantCulture),
                    webEvent.Id,
                    webEvent.Server,
                    webEvent.Domain,
                    webEvent.Method,
                    webEvent.Path,
                    webEvent.ClientIp,
                    webEvent.StatusCode.ToString(CultureInfo.InvariantCulture),
                    webEvent.UserAgent,
                    webEvent.IsSuspicious.ToString(),
                    webEvent.DetectionReason,
                    webEvent.RiskScore.ToString(CultureInfo.InvariantCulture),
                    webEvent.RiskSeverity,
                    JsonSerializer.Serialize(webEvent.RiskIndicators ?? [], jsonOptions),
                    JsonSerializer.Serialize(webEvent.Properties, jsonOptions)
                ]);
        }).RequireAuthorization("DashboardAdministrator");

        webApp.MapGet("/api/ban-counts", (IBanCountService banCountService, int? limit, string? domain) =>
            Results.Ok(banCountService.GetBanCounts(limit ?? 250, domain)))
            .RequireAuthorization("DashboardAdministrator");

        webApp.MapPut("/api/ban-counts/{clientIp}", (IBanCountService banCountService, string clientIp, string? domain, BanCountUpdateRequest request) =>
        {
            if (request.BanCount < 0)
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    [nameof(request.BanCount)] = ["Ban count must be non-negative."]
                });
            }

            return Results.Ok(banCountService.SetBanCount(clientIp, request.BanCount, domain));
        }).RequireAuthorization("DashboardAdministrator");

        webApp.MapGet("/api/iis/sites", (IIisSiteDiscoveryService siteDiscoveryService) =>
            Results.Ok(siteDiscoveryService.GetSites()))
            .RequireAuthorization("DashboardAdministrator");

        webApp.MapGet("/api/iis/status", (IDenyListStore denyListStore, IOptions<IisAdminOptions> adminOptions) =>
        {
            var enforcementPolicy = adminOptions.Value.GetEnforcementPolicy();
            return Results.Ok(new
            {
                enableDenyListChanges = adminOptions.Value.EnableDenyListChanges,
                dryRun = adminOptions.Value.DryRun,
                enforcementMode = enforcementPolicy.Mode.ToString(),
                canEnforce = enforcementPolicy.CanMutate,
                temporaryBanMinutes = adminOptions.Value.TemporaryBanMinutes,
                requireMultipleIndicators = adminOptions.Value.RequireMultipleIndicators,
                recentAuditEntries = denyListStore.GetRecentAudit(50)
            });
        }).RequireAuthorization("DashboardAdministrator");

        webApp.MapPost("/api/iis/deny-list/preview", (
            IIisDenyListService denyListService,
            HttpContext context,
            DenyListPreviewRequest request) =>
        {
            try
            {
                var preview = denyListService.PreviewDeniedIp(request, context.User.Identity?.Name ?? "unknown");
                return preview is null
                    ? Results.ValidationProblem(new Dictionary<string, string[]>
                    {
                        ["request"] = ["Site name, client address, reason, or evidence is invalid."]
                    })
                    : Results.Ok(preview);
            }
            catch (InvalidOperationException)
            {
                return Results.NotFound(new { error = "The requested IIS site could not be inspected." });
            }
            catch (Exception)
            {
                return Results.Problem("The IIS deny-list preview could not be completed.", statusCode: StatusCodes.Status503ServiceUnavailable);
            }
        }).RequireAuthorization("DashboardAdministrator");

        webApp.MapGet("/api/iis/sites/{siteName}/deny-list", (IIisDenyListService denyListService, string siteName) =>
            Results.Ok(denyListService.GetDeniedIps(siteName)))
            .RequireAuthorization("DashboardAdministrator");

        webApp.MapPost("/api/iis/sites/{siteName}/deny-list", (
            IIisDenyListService denyListService,
            IIisSiteDiscoveryService siteDiscoveryService,
            IBanCountService banCountService,
            IIpAllowList ipAllowList,
            IOptions<IisAdminOptions> adminOptions,
            HttpContext context,
            string siteName,
            DeniedIpUpdateRequest request) =>
        {
            if (string.IsNullOrWhiteSpace(request.ClientIp))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    [nameof(request.ClientIp)] = ["Client IP is required."]
                });
            }

            if (!IisIpAllowList.TryNormalizeAddress(request.ClientIp, out var normalizedIp))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    [nameof(request.ClientIp)] = ["Client IP must be an exact IPv4 or IPv6 address."]
                });
            }

            var actor = context.User.Identity?.Name ?? "unknown";
            var reason = string.IsNullOrWhiteSpace(request.Reason) ? "Manual deny-list request" : request.Reason.Trim();
            var policy = adminOptions.Value.GetEnforcementPolicy();
            var added = denyListService.AddDeniedIp(siteName, normalizedIp, actor, reason);
            if (ipAllowList.Contains(normalizedIp))
            {
                return Results.Problem("The client IP matches the configured allow-list and cannot be denied.", statusCode: StatusCodes.Status403Forbidden);
            }

            if (!policy.WritesEnabled)
            {
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }

            if (policy.Mode == DenyListEnforcementMode.Observe)
            {
                return Results.Ok(new { siteName, clientIp = normalizedIp, denied = false, observed = true, enforcementMode = policy.Mode.ToString() });
            }

            if (policy.IsSimulation)
            {
                return Results.Ok(new { siteName, clientIp = normalizedIp, denied = false, simulated = true, enforcementMode = policy.Mode.ToString() });
            }

            if (!added && denyListService.GetDeniedIps(siteName).Contains(normalizedIp, StringComparer.OrdinalIgnoreCase))
            {
                return Results.Ok(new { siteName, clientIp = normalizedIp, denied = true, alreadyPresent = true, enforcementMode = policy.Mode.ToString() });
            }

            if (!added)
            {
                return Results.Problem($"Unable to add deny-list entry for '{request.ClientIp}' on '{siteName}'.");
            }

            if (policy.CanMutate)
            {
                var siteDomains = siteDiscoveryService.GetSites()
                    .FirstOrDefault(site => string.Equals(site.Name, siteName, StringComparison.OrdinalIgnoreCase))
                    ?.Domains;
                banCountService.IncrementBanCounts(normalizedIp, siteDomains ?? []);
            }

            return Results.Ok(new { siteName, clientIp = normalizedIp, denied = true, simulated = false, enforcementMode = policy.Mode.ToString() });
        }).RequireAuthorization("DashboardAdministrator");

        webApp.MapPost("/api/iis/deny-list", (
            IIisDenyListService denyListService,
            IIisSiteDiscoveryService siteDiscoveryService,
            IIpAggregationService aggregationService,
            IBanCountService banCountService,
            IIpAllowList ipAllowList,
            IOptions<IisAdminOptions> adminOptions,
            HttpContext context,
            DeniedIpUpdateRequest request) =>
        {
            if (string.IsNullOrWhiteSpace(request.ClientIp))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    [nameof(request.ClientIp)] = ["Client IP is required."]
                });
            }

            if (!IisIpAllowList.TryNormalizeAddress(request.ClientIp, out var normalizedIp))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    [nameof(request.ClientIp)] = ["Client IP must be an exact IPv4 or IPv6 address."]
                });
            }

            var finding = aggregationService.GetFinding(normalizedIp);
            if (finding is null || finding.Domains.Count == 0)
            {
                return Results.NotFound(new { clientIp = normalizedIp, denied = false });
            }

            var actor = context.User.Identity?.Name ?? "unknown";
            var reason = string.IsNullOrWhiteSpace(request.Reason) ? "Manual deny-list request" : request.Reason.Trim();
            var policy = adminOptions.Value.GetEnforcementPolicy();
            var updatedSites = denyListService.AddDeniedIpToDomains(normalizedIp, finding.Domains, actor, reason);
            if (ipAllowList.Contains(normalizedIp))
            {
                return Results.Problem("The client IP matches the configured allow-list and cannot be denied.", statusCode: StatusCodes.Status403Forbidden);
            }

            if (!policy.WritesEnabled)
            {
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }

            if (policy.Mode == DenyListEnforcementMode.Observe)
            {
                return Results.Ok(new { clientIp = normalizedIp, domains = finding.Domains, sites = Array.Empty<string>(), denied = false, observed = true, enforcementMode = policy.Mode.ToString() });
            }

            if (policy.IsSimulation)
            {
                return Results.Ok(new { clientIp = normalizedIp, domains = finding.Domains, sites = Array.Empty<string>(), denied = false, simulated = true, enforcementMode = policy.Mode.ToString() });
            }

            var updatedSiteSet = new HashSet<string>(updatedSites, StringComparer.OrdinalIgnoreCase);
            var matchingSites = siteDiscoveryService.GetSites()
                .Where(site => site.Domains.Any(siteDomain => finding.Domains.Any(domain =>
                    string.Equals(
                        IisSiteDiscoveryService.NormalizeDomain(siteDomain),
                        IisSiteDiscoveryService.NormalizeDomain(domain),
                        StringComparison.OrdinalIgnoreCase))))
                .ToArray();
            var alreadyPresentSites = matchingSites
                .Where(site => !updatedSiteSet.Contains(site.Name))
                .Where(site => denyListService.GetDeniedIps(site.Name).Contains(normalizedIp, StringComparer.OrdinalIgnoreCase))
                .Select(site => site.Name)
                .ToArray();
            var notUpdatedSites = matchingSites
                .Where(site => !updatedSiteSet.Contains(site.Name) && !alreadyPresentSites.Contains(site.Name, StringComparer.OrdinalIgnoreCase))
                .Select(site => site.Name)
                .ToArray();

            if (updatedSites.Count == 0 && alreadyPresentSites.Length == 0 && policy.CanMutate)
            {
                return matchingSites.Length == 0
                    ? Results.NotFound(new { clientIp = normalizedIp, domains = finding.Domains, denied = false })
                    : Results.Conflict(new
                    {
                        clientIp = normalizedIp,
                        denied = false,
                        notUpdatedSites,
                        error = "No matching site was updated; inspect its deny-list preview and audit history."
                    });
            }

            var domainsToIncrement = finding.Domains;
            if (policy.CanMutate && updatedSites.Count > 0)
            {
                var updatedSiteNames = new HashSet<string>(updatedSites, StringComparer.OrdinalIgnoreCase);
                var matchedDomains = siteDiscoveryService.GetSites()
                    .Where(site => updatedSiteNames.Contains(site.Name))
                    .SelectMany(site => site.Domains)
                    .Intersect(finding.Domains, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                domainsToIncrement = matchedDomains.Length > 0 ? matchedDomains : finding.Domains;
                banCountService.IncrementBanCounts(normalizedIp, domainsToIncrement);
            }

            return Results.Ok(new
            {
                clientIp = normalizedIp,
                domains = domainsToIncrement,
                sites = updatedSites,
                alreadyPresentSites,
                notUpdatedSites,
                denied = true,
                simulated = false,
                enforcementMode = policy.Mode.ToString()
            });
        }).RequireAuthorization("DashboardAdministrator");

        webApp.MapDelete("/api/iis/sites/{siteName}/deny-list/{clientIp}", (
            IIisDenyListService denyListService,
            IOptions<IisAdminOptions> adminOptions,
            HttpContext context,
            string siteName,
            string clientIp,
            [FromBody] DeniedIpRemovalRequest request) =>
        {
            if (!IisIpAllowList.TryNormalizeAddress(clientIp, out var normalizedIp))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    [nameof(clientIp)] = ["Client IP must be an exact IPv4 or IPv6 address."]
                });
            }

            var actor = context.User.Identity?.Name ?? "unknown";
            var auditReason = string.IsNullOrWhiteSpace(request.Reason) ? "Manual deny-list removal" : request.Reason.Trim();
            var policy = adminOptions.Value.GetEnforcementPolicy();
            var removalStatus = denyListService.RemoveDeniedIpWithStatus(siteName, normalizedIp, actor, auditReason);
            if (!policy.WritesEnabled)
            {
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }

            if (policy.Mode == DenyListEnforcementMode.Observe)
            {
                return Results.Ok(new { siteName, clientIp = normalizedIp, denied = true, observed = true, enforcementMode = policy.Mode.ToString() });
            }

            if (policy.IsSimulation)
            {
                return Results.Ok(new { siteName, clientIp = normalizedIp, denied = true, simulated = true, enforcementMode = policy.Mode.ToString() });
            }

            return removalStatus switch
            {
                DenyListRemovalStatus.Removed => Results.Ok(new { siteName, clientIp = normalizedIp, denied = false, simulated = false, enforcementMode = policy.Mode.ToString() }),
                DenyListRemovalStatus.NotFound => Results.NotFound(new { siteName, clientIp = normalizedIp, denied = false }),
                DenyListRemovalStatus.NotServiceOwned => Results.Conflict(new
                {
                    siteName,
                    clientIp = normalizedIp,
                    error = "Only active service-owned deny rules can be removed; administrator rules are preserved."
                }),
                DenyListRemovalStatus.RecoveryRequired or DenyListRemovalStatus.ConcurrentChange => Results.Conflict(new
                {
                    siteName,
                    clientIp = normalizedIp,
                    error = "The deny-list ownership state changed; review the audit history before retrying."
                }),
                DenyListRemovalStatus.Invalid => Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    [nameof(siteName)] = ["The IIS site name is invalid."]
                }),
                _ => Results.Problem($"Unable to remove deny-list entry for '{clientIp}' on '{siteName}'.", statusCode: StatusCodes.Status503ServiceUnavailable)
            };
        }).RequireAuthorization("DashboardAdministrator");

        webApp.MapEventStreamEndpoints(jsonOptions);
    }

    private static IResult CreateExportResult<T>(
        IReadOnlyList<T> records,
        string fileName,
        string? format,
        JsonSerializerOptions jsonOptions,
        IReadOnlyList<string> headers,
        Func<T, IReadOnlyList<string?>> getValues)
    {
        var normalizedFormat = string.IsNullOrWhiteSpace(format) ? "json" : format.Trim();
        if (string.Equals(normalizedFormat, "json", StringComparison.OrdinalIgnoreCase))
        {
            return Results.File(
                JsonSerializer.SerializeToUtf8Bytes(records, jsonOptions),
                "application/json",
                $"{fileName}.json");
        }

        if (!string.Equals(normalizedFormat, "csv", StringComparison.OrdinalIgnoreCase))
        {
            return Results.BadRequest(new { error = "format must be either 'json' or 'csv'." });
        }

        var csv = new StringBuilder();
        AppendCsvRow(csv, headers);
        foreach (var record in records)
        {
            AppendCsvRow(csv, getValues(record));
        }

        return Results.File(Encoding.UTF8.GetBytes(csv.ToString()), "text/csv; charset=utf-8", $"{fileName}.csv");
    }

    private static void AppendCsvRow(StringBuilder output, IEnumerable<string?> values)
    {
        var first = true;
        foreach (var value in values)
        {
            if (!first)
            {
                output.Append(',');
            }

            output.Append('"')
                .Append(EscapeCsvValue(value))
                .Append('"');
            first = false;
        }

        output.Append("\r\n");
    }

    private static string EscapeCsvValue(string? value)
    {
        value ??= string.Empty;
        var trimmed = value.AsSpan().TrimStart();
        if (value.Length > 0 &&
            (value[0] is '\t' or '\r' or '\n' ||
             (trimmed.Length > 0 && trimmed[0] is '=' or '+' or '-' or '@')))
        {
            value = $"'{value}";
        }

        return value.Replace("\"", "\"\"", StringComparison.Ordinal);
    }
}
