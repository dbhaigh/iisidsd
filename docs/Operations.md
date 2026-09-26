# Operations guide

## Storage workflow

Event data is persisted to the SQLite database configured by `Storage:DatabasePath`.

Current persisted areas:

- `events` - request events and risk metadata
- `ban_counts` - per-IP repeat-offender counts

The database schema is initialized at startup by `Storage/EventDbInitializer.cs`.

## Findings workflow

Suspicious request activity is processed in two layers:

1. `Detection/SuspiciousActivityDetector.cs` scores the incoming request target and returns a request-level suspicious event when indicators are present.
2. `Services/IpAggregationService.cs` groups recent stored events by client IP to produce dashboard findings.

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
- Install now attempts to start the service immediately after creation.
- Menu options are enabled or disabled automatically from current service state.

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

### No live events

Check:

- `IisEtw:Enabled`
- ETW provider configuration
- Windows environment support
- application logs for ETW startup failures

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
