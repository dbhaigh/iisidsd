# iisidsd

`iisidsd` is a .NET 10 Windows-hosted IIS monitoring dashboard that ingests IIS ETW events, scores suspicious request targets, persists events to SQLite, and exposes both live event and aggregated IP-finding views through a local web UI.

## Current capabilities

- Real-time IIS ETW ingestion from `Microsoft-Windows-IIS-Logging`
- Persistent event storage in SQLite
- Heuristic URL risk scoring with severity bands
- Modular detector composition with structured, user-visible evidence
- Aggregated suspicious-IP findings
- Durable, opt-in security notifications with a local Windows Event Log provider
- Shared administrator incident state and analyst notes
- Per-IP ban-count tracking
- IIS site discovery and deny-list inspection
- Optional IIS deny-list modifications guarded by configuration
- Browser dashboard with live events, findings, detail, and IIS views
- Notification-area icon with dashboard launch and service controls that request elevation when needed

## Release 0.2.11 highlights

- Start, Stop, and Restart are enabled for installed services in the tray menu; non-elevated companions prompt for Windows elevation only when the user selects an action.
- The tray companion can control an installed service even when its version differs; Install and Uninstall remain administrator-only.

## Release 0.2.10 highlights

- ETW access failures no longer take down the service host; the listener retries with bounded backoff while the dashboard remains available.
- Service installation grants its virtual identity the Performance Log Users permission needed for ETW provider access and cleans up installer-added membership on uninstall.

## Release 0.2.8 highlights

- Service install/start from an interactive host preserves the open dashboard during graceful handoff; the service starts after the old host exits and the dashboard reconnects to its live event stream.
- The handoff no longer abandons service startup when graceful shutdown takes longer than an arbitrary timeout.

## Release 0.2.4 highlights

- Detection is modular: the built-in heuristic remains the default contributor, while new modules are observe-only until explicitly configured to contribute.
- Structured explanations and contribution status survive SQLite persistence and appear in the dashboard; per-module timing and health are observable.
- Eligible security incidents enter a durable, deduplicated SQLite notification queue and can be delivered to the local Windows Event Log, retried, inspected, and acknowledged. Delivery is disabled by default.
- Bounded notification retries, queue/history limits, cooldowns, privacy redaction, and retention are covered by deterministic tests. See [docs/NOTIFICATIONS.md](docs/NOTIFICATIONS.md) and [docs/DETECTION_MODULES.md](docs/DETECTION_MODULES.md).
- Operational diagnostics and standalone upgrade validation cover event ingestion, SQLite, configuration, tray lifecycle, and preservation of runtime data.

## Release 0.2.3 highlights

- IIS deny-list changes no longer alter application-pool recycling settings; previews identify shared-pool impact.
- Deny-list enforcement supports Observe, Simulate, and Enforce modes, with SQLite ownership journaling, audit history, temporary expiry, and pending-operation recovery.
- Existing unmanaged deny rules and administrator allow rules are preserved; enforcement remains disabled by default.

## Release 0.2.2 highlights

- Windows service and single-file launches serve the dashboard and assets from beside the executable and honor the configured `Urls` listener address.
- Administrators can edit supported non-secret backend settings from the dashboard. Changes are validated, credentials are redacted, and a service restart is required to apply them.
- The standalone Windows x64 package contains only the executable, `appsettings.json`, and required `wwwroot` assets; runtime SQLite data is not included.

## Release 0.2.1 highlights

- Dashboard access is loopback-only by default. Optional remote access requires Windows Authentication and HTTPS.
- Windows Authentication uses the patched `Microsoft.AspNetCore.Authentication.Negotiate` 10.0.13 package ([GHSA-vrrp-6v32-2p8g](https://github.com/advisories/GHSA-vrrp-6v32-2p8g)).
- Ban-count and IIS deny-list HTTP writes require an authenticated Windows Administrator; deny-list changes also require `IisAdmin:EnableDenyListChanges`.
- Automatic IIS blocking requires a repeated-404 signal or a critical event with multiple distinct indicators.
- Per-IP findings and per-domain summaries are updated incrementally in SQLite rather than re-aggregated from the event retention window for every request.
- All scoring weights are configurable; request-rate and unique-path scanning signals use short, per-IP sliding windows and expanded configurable exploit/scanner patterns.
- Allow-listed addresses are never denied. Temporary bans expire through a background cleaner; existing IIS rules are not assigned a service-owned expiry.
- The dashboard provides sortable/searchable findings, bulk deny, live-event pause and reconnection, IP timelines, risk indicators, and risk/top-IP charts.
- ETW capture is decoupled from database and IIS operations through a bounded ingestion queue.
- Tray service lifecycle actions run asynchronously to keep the Windows Forms UI responsive.
- Option values are validated at startup; invalid limits, thresholds, URLs, provider IDs, or allow-list ranges stop startup with validation errors.
- Event retention is bounded by both `Storage:EventRetentionLimit` and `Storage:EventRetentionDays`; IP findings are pruned separately by `Storage:FindingRetentionDays`.
- Findings and retained events can be exported as CSV or JSON by authenticated Windows Administrators.
- The tray menu shows the deny-list dry-run state, dropped ETW event count, and most recent automatic deny-list action.
- Health status includes SQLite, ETW queue and dropped-event details, dry-run state, and the last automatic deny-list action. `/metrics` exposes Prometheus-formatted counters and histograms.
- Automatic and manual deny-list mutations are audited. Allow-listed addresses are never denied, and temporary entries are removed after their configured expiry.

## Project layout

- `Program.cs` - host configuration and minimal API routes
- `Etw/` - IIS ETW ingestion background service
- `Detection/` - suspicious activity and risk scoring logic
- `Storage/` - SQLite event persistence and schema initialization
- `Services/` - IP aggregation and ban-count services
- `Iis/` - IIS site discovery and deny-list operations
- `Models/` - API, persistence, and workflow models
- `wwwroot/` - dashboard UI assets
- `Tests/iisidsd.Tests/` - dashboard access, detector, aggregation, and persistence tests
- [docs/DETECTION_MODULES.md](docs/DETECTION_MODULES.md) - module contract, registration, configuration, and evaluation guide
- [docs/NOTIFICATIONS.md](docs/NOTIFICATIONS.md) - opt-in Windows Event Log notifications, queue operation, privacy, and retention

## Configuration

Main configuration lives in `appsettings.json`.

Administrators can inspect and edit supported non-secret settings from the dashboard's **System configuration** view. The editor validates and saves changes to the `appsettings.json` file beside `iisidsd.exe`; restart the service to apply them. Certificate passwords and unsupported sections are not shown or changed, and environment variables or command-line settings can override file values.

### `IisEtw`

Controls ETW ingestion.

- `Enabled`
- `ProviderName`
- `ProviderId`
- `SessionName`
- `SubscriptionBufferSize`
- `IngestionBufferSize`
- `ProcessingBatchSize`
- `ProviderName` and `SessionName` must be non-empty; both buffer sizes must be positive, `ProcessingBatchSize` must be from 1 to 1024, and `ProviderId` must not be empty.

### `Detection`

Controls URL-risk heuristics.

- `MinimumSuspiciousStatusCode`
- `RequestPathLengthThreshold`
- `NotFoundBurstThreshold`
- `NotFoundBurstLookbackLimit`
- `StatusScoreWeight`
- `LongPathScoreWeight`
- `RepeatedNotFoundScoreWeight`
- `UnusualMethodScoreWeight`
- `PathFragmentScoreWeight`
- `UnknownExtensionScoreWeight`
- `ScannerUserAgentScoreWeight`
- `RequestRateScoreWeight`
- `PathScanScoreWeight`
- `RateThreshold`
- `RateWindowSeconds`
- `PathScanUniquePathThreshold`
- `PathScanWindowSeconds`
- `AuthenticationFailureThreshold`
- `AuthenticationFailureWindowSeconds`
- `NotFoundBurstWindowSeconds`
- `MaximumTrackedClientHistories` - default `1024`, maximum `8192`
- `MaximumTrackedHistoryBuckets` - default `131072`, maximum `262144`
- `MaximumTrackedPathsPerHistory` - default `128`, maximum `1024`
- `MaximumTrackedPathsTotal` - default `65536`, maximum `131072`
- `MaximumTrackedPathLengthCharacters` - default `1024`, maximum `1024`
- `MaximumTrackedExtensionSites` - default `256`, maximum `512`
- `MaximumExtensionsPerSite` - default `128`, maximum `256`
- `MaximumEventLatenessSeconds` - defaults to `2`, maximum `30`
- `SuspiciousPathFragments`
- `ScannerUserAgents`

All score weights must be non-negative; setting a weight to zero disables its scoring contribution. Thresholds and windows must be positive, except `RateThreshold` may be zero. All four detection windows are limited to 300 seconds. `NotFoundBurstLookbackLimit` caps the number of 404 responses counted inside its time window; it is not a database-row limit.

Temporal history is in memory and keyed by canonical client IP plus normalized server, host, and IIS site identity. IPv4-mapped IPv6 is treated as IPv4; host names are IDN-normalized, lowercased, and stripped of trailing dots. Ports and distinct IIS sites remain distinct. Events without usable IP and host/site identity do not contribute to temporal signals. Histories, buckets, unique-path hashes, and extension caches have the limits listed above; at capacity, new history is rejected and the related metrics record the rejection. A system clock rollback clears temporal windows. These counters intentionally reset on application restart and are not rebuilt from SQLite event history.

### `TrustedProxies`

Forwarded headers are disabled by default. To enable them, set `Enabled` to `true` and list the exact proxy IP addresses in `TrustedProxyIps`; CIDR ranges and ambiguous IP forms are rejected. `ForwardLimit` defaults to `1` and is limited to `10`. Only `X-Forwarded-For` and `X-Forwarded-Proto` are enabled. This trust applies to dashboard HTTP requests, not IIS ETW event client IPs. Never enable forwarding with an empty or overly broad proxy allowlist.

### `Storage`

Controls persistent storage.

- `DatabasePath` - defaults to `data/iisidsd.sqlite3`
- `JournalMode` - defaults to `WAL`; use `DELETE` for filesystems that do not support SQLite WAL shared-memory semantics
- `SynchronousMode` - defaults to `FULL` for durable commits; `NORMAL` is a performance/durability tradeoff and `EXTRA` requests the strongest SQLite sync mode
- `BusyTimeoutSeconds` - defaults to `5`, maximum `120`
- `EventRetentionLimit` - maximum retained event rows
- `EventRetentionDays` - maximum age of retained events; age and row-count pruning are both enforced
- `FindingRetentionDays` - age after which inactive IP findings and expired per-domain summaries are pruned

SQLite data should live on a local filesystem. WAL with `FULL` synchronous mode is selected for reader/writer concurrency without opting into the weaker `NORMAL` durability tradeoff. Keep the database, `-wal`/`-shm` files while the service is running, and the ETW diagnostics sidecar together when backing up or moving storage. Event and finding retention runs in bounded chunks; `/health` performs a lightweight connection check and throttles `quick_check(1)` to once per hour.

Legacy event-list APIs accept up to 1,000 rows per request; event exports accept up to 10,000 rows. Finding and ban-count lists are bounded to 500 rows. The versioned event page accepts 1 to 1,000 rows and rejects out-of-range limits rather than silently clamping them.

### Event replay and timestamps

`GET /api/v2/events` returns cursor pages of event envelopes. Omit both cursors for the latest page, pass `afterSequence` to fetch newer events, or `beforeSequence` to fetch an older page; the two cursors are mutually exclusive and exclusive of the returned boundary. Items are ordered by ascending persisted sequence. Each envelope contains `eventId`, UTC `timestamp`, `type`, `payloadVersion`, `cursor`, and the legacy-compatible event `payload`. The response includes page cursors, `hasMore`, and retention-gap metadata. `limit` is 1-1,000; `clientIp` must be a valid IPv4/IPv6 address, and `domain` is limited to 253 non-control characters.

`GET /api/v2/events/stream` uses the same filters and accepts `afterSequence`; an EventSource `Last-Event-ID` takes precedence on reconnect. It emits `iis.event.v1` envelopes, `checkpoint` events for filtered sequence progress, and `recovery` events for retention gaps or slow consumers. The existing `/api/events/stream` route remains available with its legacy `etw` event payload shape. Concurrent streams default to a maximum of 64 (configurable from 1 to 256); heartbeat and write-timeout defaults are 15 and 30 seconds, each configurable from 1 to 120 seconds.

The store subscribes before replaying retained rows, so events arriving during reconnect are either replayed or read from the live queue without cursor duplication. Cursors are stable only for the lifetime of retained rows: if retention removed history, the API and stream report a gap and continue from the retained boundary. This is not exactly-once delivery; a successful server write or flush does not prove the browser received or processed an event. Clients should deduplicate by event ID/cursor and persist their cursor only after processing. API timestamps are UTC; the dashboard formats them in the viewer's local browser time zone.

### `IisAdmin`

Controls IIS deny-list write safety.

- `EnableDenyListChanges` - defaults to `false`
- `EnforcementMode` - `Observe`, `Simulate`, or `Enforce`; when omitted, legacy `DryRun` maps to `Simulate` or `Enforce`
- `AllowList` - exact IPv4/IPv6 addresses or CIDR ranges that are never added to an IIS deny list
- `TemporaryBanMinutes` - positive values set an expiry; `0` means permanent
- `DryRun` - defaults to `true`; records intended actions without changing IIS
- `RequireMultipleIndicators` - when enabled, below-High automatic denial requires multiple distinct indicators; High and Critical events qualify on severity alone

`EnableDenyListChanges` is the master switch for IIS writes. When it is false, the effective mode is `Observe`. `Simulate` records intended actions without invoking IIS mutation commands. `DryRun=true` also prevents an explicit `Enforce` mode from writing. Keep the defaults until an administrator has reviewed the preview and audit behavior.

The SQLite journal tracks service ownership and pending IIS transitions. Existing unmanaged deny rules are not adopted or removed, and administrator allow rules are preserved. Temporary expiry applies only to service-owned entries. Pending transitions are reconciled while enforcement is active; ambiguous cases are preserved for administrator review. Do not delete the configured SQLite database as a way to reset IIS ownership. See [docs/Operations.md](docs/Operations.md#iis-deny-list-workflow) for the change and rollback runbook.

### `Tray`

Controls the notification-area shortcut.

- `BrowserUrl`

The tray menu also displays operational status fetched from the local `/health` endpoint. `BrowserUrl` must be an absolute HTTP or HTTPS URL.

### `OpenTelemetry`

- `OtlpEndpoint` - optional absolute HTTP or HTTPS OTLP exporter endpoint; leave empty to disable remote exporting. `/metrics` remains available in Prometheus text format.

### Dashboard network access

The `Urls` setting controls the dashboard listener. The default listens only on loopback at `http://localhost:5080/`.

By default `Urls` is `http://localhost:5080` and non-loopback requests are rejected. Anonymous local users may view the dashboard and read-only event/finding APIs. Management APIs use Windows Negotiate with same-origin browser credentials and require a Windows Administrator. For loopback requests, an authenticated admin account is recognized even when UAC marks its Administrators SID as deny-only; remote requests still require enabled Administrator membership. The tray opens the `localhost` URL so the browser can silently use the signed-in Windows account when integrated authentication is enabled; users who are not Windows Administrators retain dashboard viewing but cannot access management features.

Existing installations preserve their configured URLs during upgrade. To use the `localhost` sign-in behavior, set both `Urls` and `Tray:BrowserUrl` to `http://localhost:5080` (include the trailing slash for `Tray:BrowserUrl`) and restart the service.

`Dashboard:MaximumEventStreamSubscribers` defaults to 64 and is limited to 1-256. `Dashboard:EventStreamHeartbeatSeconds` defaults to 15 seconds and `Dashboard:EventStreamWriteTimeoutSeconds` to 30 seconds; both are limited to 1-120 seconds.

To enable remote access, set `Dashboard:RemoteAccessEnabled` to `true`, bind `Urls` to an HTTPS address, configure a Kestrel server certificate, and add every DNS name or exact IP used in the request Host header to `Dashboard:AllowedHosts`. Remote mode requires HTTPS and Windows Authentication on all requests, including loopback requests, so a reverse proxy cannot gain local exemptions. Allowed hosts default to `localhost`, `127.0.0.1`, and `::1`; wildcards and host:port entries are rejected. For a proxy, separately configure `TrustedProxies` with its exact peer IP and ensure it overwrites forwarded headers. Do not put certificate passwords in source-controlled configuration.

Unsafe browser requests require a same-origin `Origin` (or same-origin `Referer` when Origin is unavailable); cross-origin and missing-origin writes are rejected. Host validation mitigates DNS rebinding and hostile Host headers. Do not expose the listener or trusted proxy to unintended networks. IIS deny-list changes additionally require `IisAdmin:EnableDenyListChanges=true`, which is disabled by default. See [docs/SECURITY.md](docs/SECURITY.md) for the endpoint matrix, threat model, migration steps, and residual risks.

The findings and events export endpoints return retained data and may contain client addresses, paths, host names, and user-agent values. They are administrator-only. CSV output quotes fields and prefixes spreadsheet formula-like values to prevent CSV formula execution.

## Running locally

Requirements:

- Windows
- .NET 10 SDK
- IIS ETW provider availability
- IIS `appcmd.exe` available under `%WINDIR%\System32\inetsrv\appcmd.exe` for IIS administration features

Run:

- `dotnet build`
- `dotnet run --project iisidsd.csproj`

The dashboard is served from the configured `Urls` value in `appsettings.json`. Remote access must also be explicitly enabled and served over HTTPS.

Installing the Windows service through the tray configures automatic startup and service recovery restarts. Interactive launches open the dashboard once the listener is ready. During handoff, a tray companion waits for the interactive host to release the dashboard port before starting the service; the open browser tab remains at the same URL. At user logon, the tray companion opens the dashboard after the service health endpoint responds. The tray menu reports service state, dashboard health, deny-list dry-run status, dropped events, and the latest automatic deny-list action.

The `Urls` value in `appsettings.json` controls the dashboard listener. For single-file and Windows service runs, configuration and dashboard assets are loaded from the executable's directory, not the process working directory or single-file extraction directory. Keep `appsettings.json` and the `wwwroot/` directory alongside `iisidsd.exe`.

## Dashboard views

### Events

Shows recent request events, live SSE updates, risk score, severity, and detection reasons.

### Findings

Shows aggregated suspicious-IP findings including:

- request count
- suspicious request count
- highest observed risk
- domains targeted
- persisted ban count
- merged detection reasons
- explicit detector evidence and analyst workflow states (Open, Acknowledged, Suppressed, Resolved)

Analyst states and notes are stored in SQLite and shared by authorized administrators. They do not change detector scores, findings, or automatic deny decisions. Detector explanations are heuristic leads; configured weight contributions are not available in the existing event API.

### Details

Separates observed request facts, heuristic detector interpretation, and the shared analyst conclusion. Related findings are linked by observed domain. Analyst notes and workflow states require administrator access; unauthorized users can still view regular event and finding data.

### IIS

Shows discovered IIS sites and the deny list for the selected site.

- Refreshing sites and reading deny lists is allowed by default.
- Adding or removing deny-list entries requires `IisAdmin:EnableDenyListChanges=true`.

### System configuration

Provides an administrator-only JSON editor for ETW, detection, storage, IIS safety, dashboard access, tray, logging, listener, and OpenTelemetry settings. `GET /api/configuration` returns supported non-secret settings; `PATCH /api/configuration` accepts partial `{ "settings": { ... } }` updates. Saved configuration is validated; restart the service to apply it.

## API summary

### Health and events

- `GET /health`
- `GET /metrics`
- `GET /api/events?limit=&clientIp=&domain=&suspiciousOnly=`
- `GET /api/events/stream?clientIp=&domain=&suspiciousOnly=`

### Findings

- `GET /api/findings?limit=&domain=` (maximum 500 findings per response)
- `GET /api/findings/{clientIp}?domain=`
- `GET /api/findings/{clientIp}/events?limit=&domain=&suspiciousOnly=`
- `GET /api/incidents?limit=` (Windows Administrator; shared analyst state)
- `PUT /api/incidents/{clientIp}` with `{ "status": "open|acknowledged|suppressed|resolved", "note": "..." }` (Windows Administrator)
- `GET /api/export/findings?format=json|csv&limit=&domain=` (Windows Administrator)
- `GET /api/export/events?format=json|csv&limit=&clientIp=&domain=&suspiciousOnly=` (Windows Administrator)

### Ban counts

- `GET /api/ban-counts?limit=`
- `PUT /api/ban-counts/{clientIp}` with `{ "banCount": number }`

### IIS administration

- `GET /api/iis/sites`
- `GET /api/iis/sites/{siteName}/deny-list`
- `POST /api/iis/deny-list/preview` with `{ "siteName": "...", "clientIp": "x.x.x.x" }`
- `POST /api/iis/sites/{siteName}/deny-list` with `{ "clientIp": "x.x.x.x" }`
- `DELETE /api/iis/sites/{siteName}/deny-list/{clientIp}`

## Validation

Current automated validation includes:

- suspicious activity detector tests
- IP aggregation tests
- SQLite event store and retention tests
- configuration fail-fast validation tests
- export endpoint happy-path and authorization tests
- deny-list, allow-list, audit, and integration tests

Run tests with:

- `dotnet test`

Publish the self-contained standalone Windows x64 release with:

- `dotnet publish iisidsd.csproj --configuration Release --runtime win-x64 --self-contained true -p:PublishProfile=StandaloneWinX64`

The standalone package is written under `artifacts/iisidsd-0.2.4-standalone-win-x64` and includes only the executable, `appsettings.json`, and required dashboard assets. Runtime SQLite data is created beside the executable on first launch.

Publish framework-dependent Windows x64 binaries with:

- `dotnet publish iisidsd.csproj --configuration Release --runtime win-x64 --self-contained false`

The output is written under `bin/Release/net10.0-windows/win-x64/publish`; the target machine must have the .NET 10 runtime installed.

## Notes

- URL risk scoring is heuristic and does not provide threat-intelligence reputation.
- ETW ingestion observes IIS activity; it does not block requests directly.
- IIS deny-list write operations may require elevation depending on the host environment.
