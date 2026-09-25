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
- Notification-area icon for opening the dashboard

## Project layout

- `Program.cs` - host configuration and minimal API routes
- `Etw/` - IIS ETW ingestion background service
- `Detection/` - suspicious activity and risk scoring logic
- `Storage/` - SQLite event persistence and schema initialization
- `Services/` - IP aggregation and ban-count services
- `Iis/` - IIS site discovery and deny-list operations
- `Models/` - API, persistence, and workflow models
- `wwwroot/` - dashboard UI assets
- `Tests/iisidsd.Tests/` - detector, aggregation, and persistence tests

## Configuration

Main configuration lives in `appsettings.json`.

### `IisEtw`

Controls ETW ingestion.

- `Enabled`
- `ProviderName`
- `ProviderId`
- `SessionName`
- `RetentionLimit`
- `SubscriptionBufferSize`

### `Detection`

Controls URL-risk heuristics.

- `MinimumSuspiciousStatusCode`
- `RequestPathLengthThreshold`
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

## Running locally

Requirements:

- Windows
- .NET 10 SDK
- IIS ETW provider availability
- IIS `appcmd.exe` available under `%WINDIR%\System32\inetsrv\appcmd.exe` for IIS administration features

Run:

- `dotnet build`
- `dotnet run --project iisidsd.csproj`

The dashboard is served from the configured `Urls` value in `appsettings.json`.

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
