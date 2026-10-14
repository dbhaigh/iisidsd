using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using iisidsd.Configuration;
using iisidsd.Iis;
using iisidsd.Models;
using iisidsd.Observability;
using iisidsd.Services;
using iisidsd.Storage;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace iisidsd.Api;

public static class DashboardEndpointMappings
{
    public static void MapDashboardEndpoints(this WebApplication webApp, JsonSerializerOptions jsonOptions)
    {
        webApp.MapGet("/health", (
            IisObservability observability,
            SqliteHealthProbe sqliteHealthProbe,
            IDenyListStore denyListStore,
            IOptions<IisAdminOptions> adminOptions) =>
        {
            var sqliteConnectionHealthy = sqliteHealthProbe.IsHealthy();
            var lastAutoDeny = sqliteConnectionHealthy ? denyListStore.GetLastAutoDeny() : null;
            var response = new
            {
                status = sqliteConnectionHealthy ? "ok" : "degraded",
                time = DateTimeOffset.UtcNow,
                queueDepth = observability.QueueDepth,
                lastEventTimestamp = observability.LastEventTimestamp,
                droppedEventCount = observability.EtwEventsDropped,
                sqliteConnectionHealthy,
                dryRun = adminOptions.Value.DryRun,
                lastAutoDeny = lastAutoDeny is null
                    ? null
                    : new LastAutoDenyStatus(
                        lastAutoDeny.ClientIp,
                        lastAutoDeny.OccurredAt,
                        lastAutoDeny.DryRun,
                        lastAutoDeny.Outcome)
            };

            return Results.Json(response, statusCode: sqliteConnectionHealthy
                ? StatusCodes.Status200OK
                : StatusCodes.Status503ServiceUnavailable);
        });

        webApp.MapGet("/metrics", (IisObservability observability) =>
            Results.Text(observability.RenderPrometheus(), contentType: "text/plain; version=0.0.4; charset=utf-8"));

        webApp.MapGet("/api/events", (IEventStore store, int? limit, string? clientIp, string? domain, bool? suspiciousOnly) =>
            Results.Ok(store.GetRecent(limit ?? 100, clientIp, domain, suspiciousOnly ?? false)));

        webApp.MapGet("/api/findings", (IIpAggregationService aggregationService, int? limit, string? domain) =>
            Results.Ok(aggregationService.GetFindings(limit ?? 100, domain)));

        webApp.MapGet("/api/findings/{clientIp}", (IIpAggregationService aggregationService, string clientIp, string? domain) =>
        {
            var finding = aggregationService.GetFinding(clientIp, domain);
            return finding is null ? Results.NotFound() : Results.Ok(finding);
        });

        webApp.MapGet("/api/findings/{clientIp}/events", (IEventStore store, string clientIp, int? limit, string? domain, bool? suspiciousOnly) =>
            Results.Ok(store.GetRecent(limit ?? 250, clientIp, domain, suspiciousOnly ?? false)));

        webApp.MapGet("/api/export/findings", (
            IIpAggregationService aggregationService,
            int? limit,
            string? domain,
            string? format) =>
        {
            var findings = aggregationService.GetFindings(limit ?? 100, domain);
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
            var events = store.GetRecent(limit ?? 100, clientIp, domain, suspiciousOnly ?? false);
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
            Results.Ok(banCountService.GetBanCounts(limit ?? 250, domain)));

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
            Results.Ok(siteDiscoveryService.GetSites()));

        webApp.MapGet("/api/iis/status", (IDenyListStore denyListStore, IOptions<IisAdminOptions> adminOptions) =>
            Results.Ok(new
            {
                enableDenyListChanges = adminOptions.Value.EnableDenyListChanges,
                dryRun = adminOptions.Value.DryRun,
                temporaryBanMinutes = adminOptions.Value.TemporaryBanMinutes,
                requireMultipleIndicators = adminOptions.Value.RequireMultipleIndicators,
                recentAuditEntries = denyListStore.GetRecentAudit(50)
            })).RequireAuthorization("DashboardAdministrator");

        webApp.MapGet("/api/iis/sites/{siteName}/deny-list", (IIisDenyListService denyListService, string siteName) =>
            Results.Ok(denyListService.GetDeniedIps(siteName)));

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
            if (!adminOptions.Value.EnableDenyListChanges)
            {
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }

            if (string.IsNullOrWhiteSpace(request.ClientIp))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    [nameof(request.ClientIp)] = ["Client IP is required."]
                });
            }

            if (!IPAddress.TryParse(request.ClientIp, out _))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    [nameof(request.ClientIp)] = ["Client IP must be an exact IPv4 or IPv6 address."]
                });
            }

            if (ipAllowList.Contains(request.ClientIp))
            {
                return Results.Problem("The client IP matches the configured allow-list and cannot be denied.", statusCode: StatusCodes.Status403Forbidden);
            }

            var actor = context.User.Identity?.Name ?? "unknown";
            var reason = string.IsNullOrWhiteSpace(request.Reason) ? "Manual deny-list request" : request.Reason.Trim();
            if (!denyListService.AddDeniedIp(siteName, request.ClientIp, actor, reason))
            {
                return Results.Problem($"Unable to add deny-list entry for '{request.ClientIp}' on '{siteName}'.");
            }

            if (!adminOptions.Value.DryRun)
            {
                var siteDomains = siteDiscoveryService.GetSites()
                    .FirstOrDefault(site => string.Equals(site.Name, siteName, StringComparison.OrdinalIgnoreCase))
                    ?.Domains;
                banCountService.IncrementBanCounts(request.ClientIp, siteDomains ?? []);
            }

            return Results.Ok(new { siteName, clientIp = request.ClientIp, denied = true, dryRun = adminOptions.Value.DryRun });
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
            if (!adminOptions.Value.EnableDenyListChanges)
            {
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }

            if (string.IsNullOrWhiteSpace(request.ClientIp))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    [nameof(request.ClientIp)] = ["Client IP is required."]
                });
            }

            if (!IPAddress.TryParse(request.ClientIp, out _))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    [nameof(request.ClientIp)] = ["Client IP must be an exact IPv4 or IPv6 address."]
                });
            }

            if (ipAllowList.Contains(request.ClientIp))
            {
                return Results.Problem("The client IP matches the configured allow-list and cannot be denied.", statusCode: StatusCodes.Status403Forbidden);
            }

            var finding = aggregationService.GetFinding(request.ClientIp);
            if (finding is null || finding.Domains.Count == 0)
            {
                return Results.NotFound(new { clientIp = request.ClientIp, denied = false });
            }

            var actor = context.User.Identity?.Name ?? "unknown";
            var reason = string.IsNullOrWhiteSpace(request.Reason) ? "Manual deny-list request" : request.Reason.Trim();
            var updatedSites = denyListService.AddDeniedIpToDomains(request.ClientIp, finding.Domains, actor, reason);
            if (updatedSites.Count == 0 && !adminOptions.Value.DryRun)
            {
                return Results.NotFound(new { clientIp = request.ClientIp, domains = finding.Domains, denied = false });
            }

            var domainsToIncrement = finding.Domains;
            if (!adminOptions.Value.DryRun)
            {
                var updatedSiteNames = new HashSet<string>(updatedSites, StringComparer.OrdinalIgnoreCase);
                var matchedDomains = siteDiscoveryService.GetSites()
                    .Where(site => updatedSiteNames.Contains(site.Name))
                    .SelectMany(site => site.Domains)
                    .Intersect(finding.Domains, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                domainsToIncrement = matchedDomains.Length > 0 ? matchedDomains : finding.Domains;
                banCountService.IncrementBanCounts(request.ClientIp, domainsToIncrement);
            }

            return Results.Ok(new
            {
                clientIp = request.ClientIp,
                domains = domainsToIncrement,
                sites = updatedSites,
                denied = true,
                dryRun = adminOptions.Value.DryRun
            });
        }).RequireAuthorization("DashboardAdministrator");

        webApp.MapDelete("/api/iis/sites/{siteName}/deny-list/{clientIp}", (
            IIisDenyListService denyListService,
            IOptions<IisAdminOptions> adminOptions,
            HttpContext context,
            string siteName,
            string clientIp,
            string? reason) =>
        {
            if (!adminOptions.Value.EnableDenyListChanges)
            {
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }

            if (!IPAddress.TryParse(clientIp, out _))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    [nameof(clientIp)] = ["Client IP must be an exact IPv4 or IPv6 address."]
                });
            }

            var actor = context.User.Identity?.Name ?? "unknown";
            var auditReason = string.IsNullOrWhiteSpace(reason) ? "Manual deny-list removal" : reason.Trim();
            return denyListService.RemoveDeniedIp(siteName, clientIp, actor, auditReason)
                ? Results.Ok(new { siteName, clientIp, denied = false, dryRun = adminOptions.Value.DryRun })
                : Results.Problem($"Unable to remove deny-list entry for '{clientIp}' on '{siteName}'.");
        }).RequireAuthorization("DashboardAdministrator");

        webApp.MapGet("/api/events/stream", async (HttpContext context, IEventStore store, string? clientIp, string? domain, bool? suspiciousOnly) =>
        {
            context.Response.ContentType = "text/event-stream";
            context.Response.Headers.CacheControl = "no-cache";
            await context.Response.StartAsync(context.RequestAborted);
            await context.Response.WriteAsync(": connected\n\n", context.RequestAborted);
            await context.Response.Body.FlushAsync(context.RequestAborted);

            await foreach (var webEvent in store.Subscribe(context.RequestAborted).ReadAllAsync(context.RequestAborted))
            {
                if (clientIp is not null && !string.Equals(webEvent.ClientIp, clientIp, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (domain is not null && !string.Equals(webEvent.Domain, domain, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (suspiciousOnly == true && !webEvent.IsSuspicious)
                {
                    continue;
                }

                await context.Response.WriteAsync($"event: etw\ndata: {JsonSerializer.Serialize(webEvent, jsonOptions)}\n\n", context.RequestAborted);
                await context.Response.Body.FlushAsync(context.RequestAborted);
            }
        });
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
