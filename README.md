# iisidsd

`iisidsd` is a .NET 10 Windows-hosted IIS monitoring dashboard that ingests IIS ETW events, scores suspicious request targets, persists events to SQLite, and exposes both live event and aggregated IP-finding views through a local web UI.

## Current capabilities

- Real-time IIS ETW ingestion from `Microsoft-Windows-IIS-Logging`
- Persistent event storage in SQLite
- Heuristic URL risk scoring with severity bands
- Aggregated suspicious-IP findings
- Per-IP ban-count tracking
- IIS site discovery and deny-list inspection
- Optional IIS deny-list modifications guarded by configuration
- Browser dashboard with live events, findings, detail, and IIS views
- Notification-area icon with dashboard launch and service controls

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

## Configuration

Main configuration lives in `appsettings.json`.

### `IisEtw`

Controls ETW ingestion.

- `Enabled`
- `ProviderName`
- `ProviderId`
- `SessionName`
- `SubscriptionBufferSize`
- `IngestionBufferSize`
- `ProviderName` and `SessionName` must be non-empty; both buffer sizes must be positive and `ProviderId` must not be empty.

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
- `SuspiciousPathFragments`
- `ScannerUserAgents`

All score weights must be non-negative; setting a weight to zero disables its scoring contribution. Thresholds and windows must be positive, except `RateThreshold` may be zero.

### `Storage`

Controls persistent storage.

- `DatabasePath` - defaults to `data/iisidsd.sqlite3`
- `EventRetentionLimit` - maximum retained event rows
- `EventRetentionDays` - maximum age of retained events; age and row-count pruning are both enforced
- `FindingRetentionDays` - age after which inactive IP findings and expired per-domain summaries are pruned

### `IisAdmin`

Controls IIS deny-list write safety.

- `EnableDenyListChanges` - defaults to `false`
- `AllowList` - exact IPv4/IPv6 addresses or CIDR ranges that are never added to an IIS deny list
- `TemporaryBanMinutes` - positive values set an expiry; `0` means permanent
- `DryRun` - defaults to `true`; records intended actions without changing IIS
- `RequireMultipleIndicators` - when enabled, automatic denial requires multiple distinct indicators

`EnableDenyListChanges` is the master switch for all deny-list writes. Dry-run mode does not invoke IIS mutation commands. Manual and automatic actions, including dry-run intentions, are recorded in the SQLite audit log.

### `Tray`

Controls the notification-area shortcut.

- `BrowserUrl`

The tray menu also displays operational status fetched from the local `/health` endpoint. `BrowserUrl` must be an absolute HTTP or HTTPS URL.

### `OpenTelemetry`

- `OtlpEndpoint` - optional absolute HTTP or HTTPS OTLP exporter endpoint; leave empty to disable remote exporting. `/metrics` remains available in Prometheus text format.

### Dashboard network access

The `Urls` setting controls the dashboard listener. The default listens only on loopback at `http://127.0.0.1:5080/`.

By default `Urls` is `http://127.0.0.1:5080` and non-loopback requests are rejected, even if the listener is rebound externally. To enable remote access, set `Dashboard:RemoteAccessEnabled` to `true`, bind `Urls` to an HTTPS address, and configure a Kestrel server certificate using the standard Kestrel certificate settings. Remote requests require Windows Authentication and HTTPS. Do not put certificate passwords in source-controlled configuration.

Loopback dashboard requests do not require Windows Authentication. When the host process is running as a Windows Administrator, loopback requests can also use administrator-only APIs without per-user authentication; this grants those permissions to all local processes that can connect to the dashboard. If the host is not elevated, administrator-only APIs require an authenticated Windows Administrator. Remote requests always require HTTPS and an authenticated Windows Administrator when remote access is enabled. IIS deny-list changes also require `IisAdmin:EnableDenyListChanges=true`, which is disabled by default. Restrict inbound firewall rules to the intended clients.

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

When running as a Windows service, configuration and dashboard assets are loaded from the executable directory. Keep `appsettings.json` and the `wwwroot/` directory alongside `iisidsd.exe`.

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

### Details

Shows recent events for the selected IP and allows editing the stored ban count.

### IIS

Shows discovered IIS sites and the deny list for the selected site.

- Refreshing sites and reading deny lists is allowed by default.
- Adding or removing deny-list entries requires `IisAdmin:EnableDenyListChanges=true`.

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
- `GET /api/export/findings?format=json|csv&limit=&domain=` (Windows Administrator)
- `GET /api/export/events?format=json|csv&limit=&clientIp=&domain=&suspiciousOnly=` (Windows Administrator)

### Ban counts

- `GET /api/ban-counts?limit=`
- `PUT /api/ban-counts/{clientIp}` with `{ "banCount": number }`

### IIS administration

- `GET /api/iis/sites`
- `GET /api/iis/sites/{siteName}/deny-list`
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

Publish the framework-dependent Windows x64 release binaries with:

- `dotnet publish iisidsd.csproj --configuration Release --runtime win-x64 --self-contained false`

The output is written under `bin/Release/net10.0-windows/win-x64/publish`; the target machine must have the .NET 10 runtime installed.

## Notes

- URL risk scoring is heuristic and does not provide threat-intelligence reputation.
- ETW ingestion observes IIS activity; it does not block requests directly.
- IIS deny-list write operations may require elevation depending on the host environment.
