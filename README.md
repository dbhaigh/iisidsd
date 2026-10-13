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

## Release 0.1.4 highlights

- Dashboard access is loopback-only by default. Optional remote access requires Windows Authentication and HTTPS.
- Ban-count and IIS deny-list HTTP writes require an authenticated Windows Administrator; deny-list changes also require `IisAdmin:EnableDenyListChanges`.
- Automatic IIS blocking requires a repeated-404 signal or a critical event with multiple distinct indicators.
- ETW capture is decoupled from database and IIS operations through a bounded ingestion queue.
- Tray service lifecycle actions run asynchronously to keep the Windows Forms UI responsive.

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

### `Detection`

Controls URL-risk heuristics.

- `MinimumSuspiciousStatusCode`
- `RequestPathLengthThreshold`
- `NotFoundBurstThreshold`
- `NotFoundBurstLookbackLimit`
- `SuspiciousPathFragments`

### `Storage`

Controls persistent storage.

- `DatabasePath` - defaults to `data/iisidsd.sqlite3`
- `EventRetentionLimit` - max retained event rows
- `FindingRetentionDays` - reserved for future retention workflows

### `IisAdmin`

Controls IIS deny-list write safety.

- `EnableDenyListChanges` - defaults to `false`

### `Tray`

Controls the notification-area shortcut.

- `BrowserUrl`

### Dashboard network access

The `Urls` setting controls the dashboard listener. The default listens only on loopback at `http://127.0.0.1:5080/`.

By default `Urls` is `http://127.0.0.1:5080` and non-loopback requests are rejected, even if the listener is rebound externally. To enable remote access, set `Dashboard:RemoteAccessEnabled` to `true`, bind `Urls` to an HTTPS address, and configure a Kestrel server certificate using the standard Kestrel certificate settings. Remote requests require Windows Authentication and HTTPS. Do not put certificate passwords in source-controlled configuration.

When remote access is enabled, the dashboard requires Windows Authentication. Ban-count and IIS deny-list write APIs additionally require the caller to be a member of the local Windows Administrators group. IIS deny-list changes also require `IisAdmin:EnableDenyListChanges=true`, which is disabled by default. Restrict inbound firewall rules to the intended clients.

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

Installing the Windows service through the tray configures automatic startup and service recovery restarts. The tray menu reports both service state and dashboard health.

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
- `GET /api/events?limit=&clientIp=&domain=&suspiciousOnly=`
- `GET /api/events/stream?clientIp=&domain=&suspiciousOnly=`

### Findings

- `GET /api/findings?limit=&domain=`
- `GET /api/findings/{clientIp}?domain=`
- `GET /api/findings/{clientIp}/events?limit=&domain=&suspiciousOnly=`

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
- SQLite event store tests

Run tests with:

- `dotnet test`

## Notes

- URL risk scoring is heuristic and does not provide threat-intelligence reputation.
- ETW ingestion observes IIS activity; it does not block requests directly.
- IIS deny-list write operations may require elevation depending on the host environment.
