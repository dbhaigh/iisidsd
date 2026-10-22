using System.Globalization;
using System.Text.Json;
using iisidsd.Configuration;
using iisidsd.Models;
using iisidsd.Storage;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace iisidsd.Api;

public static class EventStreamEndpointMappings
{
    private const int MaximumPageSize = 1_000;
    private const int ReplayBatchSize = 256;
    private const string EventType = "iis.request";
    private const int PayloadVersion = 1;

    public static void MapEventStreamEndpoints(this WebApplication webApp, JsonSerializerOptions jsonOptions)
    {
        webApp.MapGet("/api/v2/events", (
            IReplayableEventStore store,
            int? limit,
            long? afterSequence,
            long? beforeSequence,
            string? clientIp,
            string? domain,
            bool? suspiciousOnly) =>
        {
            if (afterSequence is < 0 || beforeSequence is < 0 || afterSequence is not null && beforeSequence is not null)
            {
                return EventQueryValidation.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["cursor"] = ["Cursors must be non-negative; specify at most one of afterSequence or beforeSequence."]
                });
            }

            if (!EventQueryValidation.TryValidate(limit, 100, MaximumPageSize, clientIp, domain,
                    out var normalizedLimit, out var normalizedClientIp, out var normalizedDomain, out var errors))
            {
                return EventQueryValidation.ValidationProblem(errors);
            }

            var page = afterSequence is long after
                ? store.GetPageAfter(after, normalizedLimit, normalizedClientIp, normalizedDomain, suspiciousOnly ?? false)
                : beforeSequence is long before
                    ? store.GetPageBefore(before, normalizedLimit, normalizedClientIp, normalizedDomain, suspiciousOnly ?? false)
                    : store.GetLatestPage(normalizedLimit, normalizedClientIp, normalizedDomain, suspiciousOnly ?? false);
            var direction = afterSequence is not null ? "after" : beforeSequence is not null ? "before" : "latest";
            var nextCursor = page.HasMore
                ? direction == "after" ? page.LastCursor : page.FirstCursor
                : null;
            var items = page.Items.Select(ToEnvelope).ToArray();
            return Results.Ok(new
            {
                items,
                direction,
                nextCursor,
                page.FirstCursor,
                page.LastCursor,
                page.LatestCursor,
                page.HasMore,
                page.GapDetected,
                page.OldestAvailableCursor,
                page.PrunedThroughCursor
            });
        });

        webApp.MapGet("/api/events/stream", (
            HttpContext context,
            IReplayableEventStore replayableStore,
            string? clientIp,
            string? domain,
            bool? suspiciousOnly,
            string? afterSequence,
            IOptions<DashboardOptions> options) =>
            StreamEventsAsync(context, replayableStore, jsonOptions, clientIp, domain, suspiciousOnly, afterSequence, options.Value, useEnvelope: false));

        webApp.MapGet("/api/v2/events/stream", (
            HttpContext context,
            IReplayableEventStore replayableStore,
            string? clientIp,
            string? domain,
            bool? suspiciousOnly,
            string? afterSequence,
            IOptions<DashboardOptions> options) =>
            StreamEventsAsync(context, replayableStore, jsonOptions, clientIp, domain, suspiciousOnly, afterSequence, options.Value, useEnvelope: true));
    }

    private static async Task<IResult> StreamEventsAsync(
        HttpContext context,
        IReplayableEventStore replayableStore,
        JsonSerializerOptions jsonOptions,
        string? clientIp,
        string? domain,
        bool? suspiciousOnly,
        string? afterSequence,
        DashboardOptions options,
        bool useEnvelope)
    {
        if (!EventQueryValidation.TryValidate(null, 100, MaximumPageSize, clientIp, domain,
                out _, out var normalizedClientIp, out var normalizedDomain, out var errors))
        {
            return EventQueryValidation.ValidationProblem(errors);
        }

        var lastEventId = context.Request.Headers["Last-Event-ID"].FirstOrDefault();
        var requestedCursorText = string.IsNullOrWhiteSpace(lastEventId) ? afterSequence : lastEventId;
        long? requestedCursor = null;
        if (!string.IsNullOrWhiteSpace(requestedCursorText))
        {
            if (!long.TryParse(requestedCursorText, NumberStyles.None, CultureInfo.InvariantCulture, out var parsedCursor) || parsedCursor < 0)
            {
                return EventQueryValidation.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["cursor"] = ["Last-Event-ID and afterSequence must be non-negative integer cursors."]
                });
            }

            requestedCursor = parsedCursor;
        }

        using var subscriberLifetime = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
        EventStreamSubscription subscription;
        try
        {
            subscription = replayableStore.SubscribeWithCursor(subscriberLifetime.Token);
        }
        catch (EventStreamSubscriberLimitException)
        {
            context.Response.Headers.RetryAfter = "1";
            return Results.Problem(
                "The event stream is at its configured concurrent-client limit. Retry after another client disconnects.",
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        var cursor = requestedCursor ?? subscription.InitialCursor;
        if (cursor > subscription.InitialCursor)
        {
            subscriberLifetime.Cancel();
            return EventQueryValidation.ValidationProblem(new Dictionary<string, string[]>
            {
                ["cursor"] = ["Cursor is newer than the latest persisted event."]
            });
        }

        var cancellationToken = context.RequestAborted;
        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "text/event-stream; charset=utf-8";
        context.Response.Headers.CacheControl = "no-cache, no-transform";
        context.Response.Headers["X-Accel-Buffering"] = "no";
        try
        {
            await context.Response.StartAsync(cancellationToken);
            if (!await WriteFrameAsync(context, ": connected\nretry: 1000\n\n", options.EventStreamWriteTimeoutSeconds, cancellationToken))
            {
                return Results.Empty;
            }

            if (requestedCursor is not null)
            {
                var warnedOfGap = false;
                while (!cancellationToken.IsCancellationRequested)
                {
                    var page = replayableStore.GetPageAfter(cursor, ReplayBatchSize);
                    if (page.GapDetected && !warnedOfGap)
                    {
                        warnedOfGap = true;
                        var recovery = JsonSerializer.Serialize(new
                        {
                            type = "stream.recovery",
                            reason = "retention_gap",
                            afterCursor = cursor,
                            oldestAvailableCursor = page.OldestAvailableCursor,
                            message = "Some events after this cursor have expired from retention; only currently retained events can be replayed."
                        }, jsonOptions);
                        if (!await WriteEventAsync(context, "recovery", cursor, recovery, options.EventStreamWriteTimeoutSeconds, cancellationToken))
                        {
                            return Results.Empty;
                        }
                    }

                    if (page.Items.Count == 0)
                    {
                        if (warnedOfGap && page.LatestCursor is long latestCursor && latestCursor > cursor)
                        {
                            cursor = latestCursor;
                            var checkpoint = JsonSerializer.Serialize(new { type = "stream.checkpoint", cursor }, jsonOptions);
                            if (!await WriteEventAsync(context, "checkpoint", cursor, checkpoint, options.EventStreamWriteTimeoutSeconds, cancellationToken))
                            {
                                return Results.Empty;
                            }
                        }

                        break;
                    }

                    foreach (var item in page.Items)
                    {
                        if (item.SequenceId <= cursor) continue;
                        cursor = item.SequenceId;
                        if (!Matches(item, normalizedClientIp, normalizedDomain, suspiciousOnly == true))
                        {
                            var checkpoint = JsonSerializer.Serialize(new { type = "stream.checkpoint", cursor }, jsonOptions);
                            if (!await WriteEventAsync(context, "checkpoint", cursor, checkpoint, options.EventStreamWriteTimeoutSeconds, cancellationToken))
                            {
                                return Results.Empty;
                            }

                            continue;
                        }

                        if (!await WriteSecurityEventAsync(context, item.ToSecurityEvent(), cursor, useEnvelope, jsonOptions, options.EventStreamWriteTimeoutSeconds, cancellationToken))
                        {
                            return Results.Empty;
                        }
                    }

                    if (!page.HasMore)
                    {
                        if (warnedOfGap && page.LatestCursor is long latestCursor && latestCursor > cursor)
                        {
                            cursor = latestCursor;
                            var checkpoint = JsonSerializer.Serialize(new { type = "stream.checkpoint", cursor }, jsonOptions);
                            if (!await WriteEventAsync(context, "checkpoint", cursor, checkpoint, options.EventStreamWriteTimeoutSeconds, cancellationToken))
                            {
                                return Results.Empty;
                            }
                        }

                        break;
                    }
                }
            }

            while (!cancellationToken.IsCancellationRequested)
            {
                using var heartbeatCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                var readTask = subscription.Reader.WaitToReadAsync(heartbeatCancellation.Token).AsTask();
                var heartbeatTask = Task.Delay(TimeSpan.FromSeconds(options.EventStreamHeartbeatSeconds), heartbeatCancellation.Token);
                var completedTask = await Task.WhenAny(readTask, heartbeatTask);
                if (completedTask == heartbeatTask)
                {
                    heartbeatCancellation.Cancel();
                    try
                    {
                        await readTask;
                    }
                    catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                    {
                    }

                    if (!await WriteFrameAsync(context, $": heartbeat {DateTimeOffset.UtcNow:O}\n\n", options.EventStreamWriteTimeoutSeconds, cancellationToken))
                    {
                        break;
                    }

                    continue;
                }

                heartbeatCancellation.Cancel();
                if (!await readTask) break;
                while (subscription.Reader.TryRead(out var webEvent))
                {
                    if (webEvent.SequenceId <= cursor) continue;
                    cursor = webEvent.SequenceId;
                    if (!Matches(webEvent, normalizedClientIp, normalizedDomain, suspiciousOnly == true))
                    {
                        var checkpoint = JsonSerializer.Serialize(new { type = "stream.checkpoint", cursor }, jsonOptions);
                        if (!await WriteEventAsync(context, "checkpoint", cursor, checkpoint, options.EventStreamWriteTimeoutSeconds, cancellationToken))
                        {
                            return Results.Empty;
                        }

                        continue;
                    }

                    if (!await WriteSecurityEventAsync(context, webEvent, cursor, useEnvelope, jsonOptions, options.EventStreamWriteTimeoutSeconds, cancellationToken))
                    {
                        return Results.Empty;
                    }
                }
            }
        }
        catch (EventStreamSlowConsumerException)
        {
            var recovery = JsonSerializer.Serialize(new
            {
                type = "stream.recovery",
                reason = "slow_consumer",
                afterCursor = cursor,
                message = "This stream exceeded its bounded buffer and was closed. Reconnect to replay retained events from this cursor."
            }, jsonOptions);
            await WriteEventAsync(context, "recovery", cursor, recovery, options.EventStreamWriteTimeoutSeconds, cancellationToken);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
        }
        catch (IOException) when (context.RequestAborted.IsCancellationRequested)
        {
        }
        finally
        {
            subscriberLifetime.Cancel();
        }

        return Results.Empty;
    }

    private static EventEnvelope<SecurityEvent> ToEnvelope(StoredSecurityEvent stored)
        => new(stored.EventId, stored.Timestamp.ToUniversalTime(), EventType, PayloadVersion, stored.SequenceId, stored.ToSecurityEvent());

    private static bool Matches(SecurityEvent webEvent, string? clientIp, string? domain, bool suspiciousOnly)
        => (clientIp is null || string.Equals(webEvent.ClientIp, clientIp, StringComparison.OrdinalIgnoreCase)) &&
           (domain is null || string.Equals(webEvent.Domain, domain, StringComparison.OrdinalIgnoreCase)) &&
           (!suspiciousOnly || webEvent.IsSuspicious);

    private static bool Matches(StoredSecurityEvent webEvent, string? clientIp, string? domain, bool suspiciousOnly)
        => (clientIp is null || string.Equals(webEvent.ClientIp, clientIp, StringComparison.OrdinalIgnoreCase)) &&
           (domain is null || string.Equals(webEvent.Domain, domain, StringComparison.OrdinalIgnoreCase)) &&
           (!suspiciousOnly || webEvent.IsSuspicious);

    private static Task<bool> WriteSecurityEventAsync(
        HttpContext context,
        SecurityEvent webEvent,
        long cursor,
        bool useEnvelope,
        JsonSerializerOptions jsonOptions,
        int writeTimeoutSeconds,
        CancellationToken cancellationToken)
    {
        var eventType = useEnvelope ? "iis.event.v1" : "etw";
        var payload = useEnvelope
            ? JsonSerializer.Serialize(new EventEnvelope<SecurityEvent>(
                webEvent.Id,
                webEvent.Timestamp.ToUniversalTime(),
                EventType,
                PayloadVersion,
                cursor,
                webEvent), jsonOptions)
            : JsonSerializer.Serialize(webEvent, jsonOptions);
        return WriteEventAsync(context, eventType, cursor, payload, writeTimeoutSeconds, cancellationToken);
    }

    private static Task<bool> WriteEventAsync(
        HttpContext context,
        string eventType,
        long cursor,
        string payload,
        int writeTimeoutSeconds,
        CancellationToken cancellationToken)
        => WriteFrameAsync(context, $"id: {cursor}\nevent: {eventType}\ndata: {payload}\n\n", writeTimeoutSeconds, cancellationToken);

    private static async Task<bool> WriteFrameAsync(
        HttpContext context,
        string frame,
        int writeTimeoutSeconds,
        CancellationToken requestAborted)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(writeTimeoutSeconds));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(requestAborted, timeout.Token);
        try
        {
            await context.Response.WriteAsync(frame, linked.Token);
            await context.Response.Body.FlushAsync(linked.Token);
            return true;
        }
        catch (OperationCanceledException) when (!requestAborted.IsCancellationRequested)
        {
            return false;
        }
    }
}
