# Notifications

Notifications are a separate delivery workflow, not part of detection or IIS enforcement. Eligible suspicious events are added to a durable SQLite outbox in the event transaction. A notification enqueue failure is isolated from event persistence; provider delivery failures update notification state and do not mark detection as failed.

## Defaults and Provider

Delivery is disabled by default. `Notifications:Enabled` must be `true` and `Notifications:Provider` must be explicitly set to `WindowsEventLog`. The only implemented provider writes to the local Windows Application event log. No SMTP or webhook destination is accepted, and notification APIs do not accept delivery destinations.

Create the event source once from an elevated PowerShell session:

```powershell
New-EventLog -LogName Application -Source iisidsd
```

Then configure the provider in `appsettings.json` or through the administrator-only system configuration view:

```json
{
  "Notifications": {
    "Enabled": true,
    "Provider": "WindowsEventLog",
    "MinimumSeverity": "High",
    "MinimumRiskScore": 8
  }
}
```

An alert must be marked suspicious and meet both the configured minimum severity and risk score. Severity is based on the detection engine result. The default threshold is High and score 8. Dashboard links are restricted to loopback HTTP or HTTPS URLs; the service never makes a request to that URL.

## Queue and Acknowledgement

Repeated alerts are grouped by a stable hash of client IP and target site. The incident is refreshed during the cooldown; after the cooldown, a new delivery can be queued for the same incident. The pending/retry queue and total retained incident history have separate configurable limits. Capacity overflow increments the dropped count and never drops or changes the underlying security event.

The worker uses bounded batches, a configured delivery timeout, exponential retry delay capped by `MaximumRetryDelaySeconds`, and a maximum attempt count. Exhausted records become `failed`. Delivery is at-least-once: a process failure after writing to Event Log but before saving the delivery outcome can cause a duplicate on restart. The worker prunes terminal records older than `RetentionDays`; pending and retrying records are not aged out. `StoredIncidentLimit` provides a hard bound on all retained notification records.

Administrator-only endpoints are available at `GET /api/notifications`, `GET /api/notifications/status`, and `POST /api/notifications/{notificationId}/acknowledge`. The dashboard Notifications tab shows delivery outcomes and provides acknowledgement. Acknowledgement time and authenticated operator identity are retained with the record. Acknowledgement stops future retry of that incident; it does not alter the analyst incident state or the detection result.

Messages include severity, incident summary, client IP, target site, event/first/last timestamps, bounded detector evidence, and the configured local dashboard link. Sensitive key/value patterns in evidence are redacted. Delivery and enqueue logs contain only an opaque notification ID and exception type, never the notification body or exception message.

## Privacy and Retention

Notification records contain client IP addresses, target site names, timestamps, risk scores, summaries, and detector explanations. They share the configured SQLite database and its filesystem permissions; the application does not encrypt SQLite contents. Restrict access to the database and protect its volume with the host's storage controls.

Terminal notification records are retained for `RetentionDays` (30 by default) and are pruned by the delivery worker. Active pending/retry records remain until delivery, failure exhaustion, or acknowledgement, subject to `StoredIncidentLimit`. Queue drops are retained in a counter. Event Viewer entries have a separate lifetime governed by the Windows Application log size and retention policy; configure that policy to match local privacy requirements. Deleting notification rows does not remove existing Event Viewer entries.

Only the local Windows Event Log provider is implemented. Notification settings contain no credentials. If a future SMTP or webhook provider is added, its secrets must come from a dedicated secret store or protected environment configuration, never source-controlled JSON or ordinary configuration responses. Webhooks will additionally require strict destination allowlisting and DNS/IP protections against SSRF.

## Validation

Run the focused deterministic workflow tests with:

```powershell
dotnet test Tests/iisidsd.Tests/iisidsd.Tests.csproj --filter FullyQualifiedName~NotificationWorkflowTests
```

The tests use a temporary SQLite database, a manual clock, and fake providers/writers; they do not write to the machine's Windows Event Log.