# Operations guide

## Storage workflow

Event data is persisted to the SQLite database configured by `Storage:DatabasePath`.

Current persisted areas:

- `events` - request events and risk metadata
- `ban_counts` - per-IP repeat-offender counts

The database schema is initialized at startup by `Storage/EventDbInitializer.cs`.

## Backend configuration editor

The administrator-only **System configuration** dashboard view edits supported non-secret settings in `appsettings.json` beside `iisidsd.exe`. `GET /api/configuration` reads the editor's supported settings, and `PATCH /api/configuration` accepts partial updates in a `{ "settings": { ... } }` object. It validates settings before writing and reports that a service restart is required before changes take effect. Unrecognized sections, including Kestrel certificate settings, are preserved but not exposed. Credentials embedded in URL settings are redacted and preserved when unchanged. Environment variables and command-line settings may override values in the file.

The editor uses the existing `DashboardAdministrator` policy. In an elevated service, loopback clients inherit the existing local administrator-API access behavior; restrict local access to trusted processes.

## Findings workflow

Suspicious request activity is processed in two layers:

1. `Detection/SuspiciousActivityDetector.cs` scores the incoming request target and returns a request-level suspicious event when indicators are present.
2. `Services/IpAggregationService.cs` groups recent stored events by client IP to produce dashboard findings.

Important detection behavior:

- repeated `404` responses from the same client IP are treated as exploit-probing/scanning behavior
- this repeated-not-found signal adds extra risk and can raise an event to `High` severity
- automatic deny-list updates require this repeated-not-found signal or a `Critical` event with at least two distinct indicators
- unfamiliar file extensions contribute risk but cannot independently make an event eligible for automatic blocking

Each finding includes:

- client IP
- total request count
- suspicious request count
- highest observed risk score and severity
- distinct target domains
- merged detection reasons
- merged risk indicators
- persisted ban count

## Ban-count workflow

Ban counts are operator-managed metadata stored separately from request events.

Use cases:

- tracking repeat offenders
- carrying forward operator decisions between sessions
- preparing later deny-list or escalation policies

Current interfaces:

- Dashboard Details view
- `GET /api/ban-counts`
- `PUT /api/ban-counts/{clientIp}`

Rules:

- counts must be whole numbers
- counts must be non-negative

## IIS discovery workflow

IIS site discovery is implemented through `appcmd.exe` wrappers in `Iis/`.

Current behavior:

- enumerate sites
- parse bindings and domains
- match a selected finding to an IIS site by observed domain
- retrieve deny-list entries for the selected site

If `appcmd.exe` is unavailable, site discovery and deny-list views will remain empty.

## IIS deny-list workflow

Read access:

- enabled by default through the IIS API endpoints and dashboard tab

Write access:

- disabled by default
- enabled only when `IisAdmin:EnableDenyListChanges` is set to `true`

Available actions:

- add deny-list entry for selected finding IP
- remove deny-list entry for a site/IP combination

Operational cautions:

- modifying deny lists may require administrative privileges
- confirm the selected IIS site before applying changes
- deny-list actions are site-specific, not global
- current deny-list state is not yet stored as an audit history table in SQLite

## Tray service operations

The notification-area icon now exposes service lifecycle actions:

- Install service
- Start service
- Stop service
- Restart service
- Uninstall service

Notes:

- Service operations require administrative privileges.
- Install configures automatic startup and Windows Service Control Manager recovery actions, then attempts to start the service immediately.
- Starting an existing service refreshes its automatic-start and recovery configuration.
- Unexpected service failures trigger restart attempts after 5, 15, and 60 seconds.
- Install/service management also registers a Startup scheduled task (`iisidsd Tray Companion`) to launch tray companion mode at user logon.
- When the service is already running, interactive launches switch directly to tray companion mode.
- During install/start from a full interactive host, the dashboard remains available while handoff completes, then the original host closes gracefully after readiness checks.
- Stop and restart wait for the Windows service to stop gracefully; restart waits for the dashboard health endpoint before reporting success.
- The context menu reports Windows service state and dashboard health separately. Lifecycle actions are enabled only for stable service states.

## Dashboard network access

The dashboard binds to `http://127.0.0.1:5080` by default and rejects non-loopback clients. Loopback dashboard requests do not require Windows Authentication. If the host process is elevated, local loopback clients can use administrator-only APIs without per-user authentication; only run elevated on a trusted machine because all local processes can access those APIs. If the host is not elevated, local administrator operations require an authenticated Windows Administrator. For remote access, explicitly set `Dashboard:RemoteAccessEnabled=true`, bind `Urls` to an HTTPS address, configure a Kestrel certificate, and allow the port only from intended clients through Windows Firewall. Remote clients must authenticate with Windows Authentication; remote HTTP requests are rejected.

Ban-count and IIS deny-list write APIs require an authenticated Windows Administrator, including for local requests. IIS deny-list changes additionally require `IisAdmin:EnableDenyListChanges=true`; this setting is disabled by default. Do not expose the listener through a reverse proxy unless remote access is enabled and the proxy preserves the required authentication and TLS protections.

## Recommended runbook

### Review suspicious activity

1. Open the dashboard.
2. Review the Findings view for highest-risk IPs.
3. Open the Details view for the selected IP.
4. Inspect recent request paths, risk scores, and detection reasons.

### Record repeat offender state

1. Select the IP in Findings.
2. Open Details.
3. Update the ban count.
4. Confirm the value is saved.

### Review IIS deny-list state

1. Open the IIS view.
2. Refresh sites.
3. Select the target site.
4. Review existing deny-list entries.

### Apply a deny-list change

1. Set `IisAdmin:EnableDenyListChanges` to `true`.
2. Restart the application if configuration reload is not active.
3. Select a finding and confirm the target site.
4. Add or remove the deny-list entry.
5. Verify the updated deny list in the IIS view.

## Troubleshooting

### Service dashboard returns 404

Check:

- The service is running the current single-file build.
- `appsettings.json` and the `wwwroot/` directory are beside the service executable.
- The service log reports the web root under the executable directory, not the .NET single-file extraction directory.
- The configured `Urls` value matches the address used by the browser.

### No live events

Check:

- The dashboard reports `Live` once the SSE connection opens, even if no events have arrived yet. If it remains `Reconnecting`, verify that `GET /api/events/stream` returns `text/event-stream`.
- `IisEtw:Enabled`
- ETW provider configuration
- Windows environment support
- application logs for ETW startup failures
- `/metrics` values `etw_events_received` and `events_processed` to distinguish provider capture from event persistence

### No IIS sites shown

Check:

- IIS is installed
- `%WINDIR%\System32\inetsrv\appcmd.exe` exists
- the process has permission to query IIS configuration

### Deny-list changes return forbidden

Check:

- `IisAdmin:EnableDenyListChanges` is set to `true`

### Deny-list changes fail even when enabled

Check:

- process elevation
- correct site selection
- IIS configuration locking or permission issues

### Ban count does not appear in findings

Check:

- the save request succeeded
- the selected IP still exists in the current findings set
- the dashboard has refreshed after the save
