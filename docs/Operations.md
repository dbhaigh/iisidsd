# Operations guide

## Storage workflow

Event data is persisted to the SQLite database configured by `Storage:DatabasePath`.

Connections use the configured busy timeout and foreign-key checks. The default journal is WAL with `SynchronousMode=FULL`; WAL is intended for a local filesystem and may not work correctly on network shares. `NORMAL` is available as an explicit durability/performance tradeoff, not as an implicit optimization. Keep the database and its `-wal`/`-shm` files together while the service is running. `/health` checks connectivity on each request and runs a throttled `quick_check(1)` integrity check hourly. `/metrics` exposes SQLite write failures, lock/busy errors, corruption errors, disk-full errors, and event-write duration.

Current persisted areas:

- `events` - request events and risk metadata
- `ban_counts` - per-IP repeat-offender counts

The database schema is initialized at startup by `Storage/EventDbInitializer.cs`.

## ETW ingestion and recovery

ETW callbacks take a bounded payload snapshot and enqueue it without waiting for SQLite or IIS work. `IisEtw:IngestionBufferSize` defaults to 10,000 queued events and `IisEtw:ProcessingBatchSize` defaults to 64. One ordered worker preserves detector history and storage ordering while publishing each batch in a SQLite transaction. When the queue is full, the newest event is rejected; callback delivery is never blocked to wait for capacity.

SQLite busy/locked and other classified transient failures retain the current batch for retry with exponential backoff from 100 ms to 5 seconds. Accepted events drain on graceful shutdown, which can wait indefinitely while a transient database failure continues. A permanent batch failure is recorded and that batch is not retried. A forced process termination can lose events still held in the in-memory queue, so this pipeline does not provide zero-loss delivery.

Ingestion counters are persisted to SQLite after batches and to an atomically replaced `<database-path>.etw-diagnostics.json` sidecar every five seconds. The sidecar is read as a fallback if SQLite diagnostics are unavailable; keep it with the database when moving the data directory. `/metrics` exposes `etw_events_received`, `etw_events_accepted`, `etw_events_dropped`, `etw_events_malformed`, `events_processed`, `event_processing_failures`, `event_processing_retries`, `auto_deny_failures`, `queue_depth`, `queue_high_water_mark`, and `etw_pipeline_latency`. Use the received/accepted/dropped counters to distinguish provider capture from queue saturation, and retries/failures to identify persistence trouble.

## Health and operational diagnostics

When iisidsd runs as a Windows service, the tray icon is provided by the interactive tray companion, not by the service process in Session 0. Start, Stop, and Restart remain available in the tray menu for an installed service; Windows requests elevation when a non-elevated companion performs one of these actions. Install and Uninstall require an administrator session. The tray companion is configured to start at user logon.

Use `/health/live` for process liveness. It does not query SQLite or depend on ETW. `/health/ready` checks SQLite and, when `IisEtw:Enabled=true`, requires the ETW listener to be in `Listening`. A failed readiness check returns HTTP 503 while liveness remains HTTP 200. `/health` preserves the concise `status` field and adds readiness, SQLite/ETW checks, version, a short revision hash of selected non-secret operational settings, and an operational snapshot. Use liveness for restart policy and readiness for traffic/service availability.

Example responses (timestamps and revision vary):

```text
GET /health/live
{"status":"ok","liveness":"live"}
```

```text
GET /health/ready
```

```json
{
	"status": "ok",
	"readiness": "ready",
	"checks": {
		"sqlite": {
			"status": "ok",
			"lastCheckedAtUtc": "2026-04-18T12:00:00+00:00",
			"failureCount": 0,
			"lastFailureType": null
		},
		"etw": {
			"status": "ok",
			"required": true,
			"state": "listening",
			"etwSubscriptionChangedAtUtc": "2026-04-18T11:59:58+00:00"
		}
	}
}
```

Selected fields from `/health` (the live response contains the complete `operational` record):

```json
{
	"status": "ok",
	"liveness": "live",
	"readiness": "ready",
		"version": "0.2.4",
	"configurationRevision": "a1b2c3d4e5f6",
	"dryRun": false,
	"enforcementMode": "enforce",
	"droppedEventCount": 0,
	"lastEnforcement": null,
	"checks": {
		"sqlite": { "status": "ok", "failureCount": 0, "lastFailureType": null },
		"etw": { "status": "ok", "required": true, "state": "listening" }
	},
	"operational": {
		"etwSubscriptionState": "listening",
		"queueDepth": 0,
		"queueCapacity": 10000,
		"etwEventsDropped": 0,
		"detectionEventsAnalyzed": 53,
		"detectionEventsBySeverity": { "low": 12, "medium": 7, "high": 3, "critical": 1, "other": 0 },
		"activeEventStreams": 1,
		"retentionFailures": 0,
		"iisAdministrationFailures": 0,
		"recentOperationalEvents": []
	}
}
```

The full `operational` record includes the last-enforcement summary (outcome/time/simulation only) and counters for ETW, detector score/severity distributions, active event streams, SQLite write failures, retention, IIS expiry, recoveries, and fatal errors. Recent operational events are capped at 20 and contain only fixed component/kind/failure categories. These health payloads do not contain client IPs, request paths, domains, user-agent values, database paths, exception messages, or IIS site names.

`/metrics` is administrator-only and renders local Prometheus text. Example lines:

```text
# HELP queue_depth Current ETW ingestion queue depth.
# TYPE queue_depth gauge
queue_depth 0
# HELP queue_capacity Configured ETW ingestion queue capacity.
# TYPE queue_capacity gauge
queue_capacity 10000
# HELP detection_events_by_severity Analyzed events by fixed risk severity.
# TYPE detection_events_by_severity counter
detection_events_by_severity{severity="low"} 12
detection_events_by_severity{severity="medium"} 7
detection_events_by_severity{severity="high"} 3
detection_events_by_severity{severity="critical"} 1
detection_events_by_severity{severity="other"} 0
etw_subscription_state{state="listening"} 1
event_stream_active_clients 1
```

Risk scores and indicator counts are exported as aggregate histograms. Severity and ETW state labels come from fixed allowlists; request-derived values are never metric labels. Most new operational counters are process-local. Existing ETW ingestion counters continue to restore from SQLite/sidecar diagnostics after restart.

OpenTelemetry metrics export is opt-in. With `OpenTelemetry:OtlpEndpoint` unset, no OTLP exporter is registered and telemetry remains local. When configured, aggregate metric points are sent to that endpoint: counters, durations, queue gauges, score/indicator distributions, the last-event timestamp, and fixed severity/state labels. This service configures metrics only; it does not configure OTLP logs or traces. No event payloads, IP addresses, paths, domains, user agents, or arbitrary hostnames are exported in metric attributes.

## Performance benchmarks

Correctness tests remain in `Tests/iisidsd.Tests`; the opt-in synthetic performance runner is separate so timing variance does not make correctness runs noisy. Run it on Windows from the repository root:

```powershell
dotnet run --project Tests/iisidsd.Performance/iisidsd.Performance.csproj -- --events 50000
```

The runner uses a fixed seed, 1,000 events/second sustained input, repeated 500-event bursts, a 10,000-event ingestion queue, 64-event write batches, 32 synthetic IIS domains/sites, and a 50,000-event default retained history. It exercises the production ETW normalizer, detector, bounded queue, SQLite stores, dashboard filters/exports, and SSE endpoint through in-process TestServer. It also injects queue saturation and a held SQLite write lock. It writes JSON and Markdown reports under `docs/reports/`; `--events`, `--output`, and `--compare` override the dataset, report path, and prior JSON report. `IISIDSD_BENCHMARK_EVENTS` sets the event count when `--events` is omitted.

Reports capture source revision and dirty state, OS/CPU/runtime, dataset cardinality, settings, throughput, loss, queue high-water, end-to-end p50/p95/p99 latency, process CPU/memory, database growth, API latency/throughput, exports, SSE delivery, and recovery. Comparisons are descriptive only. No CI performance thresholds are set until repeated runs on matched hardware/runtime establish stable variance. TestServer results exclude network, TLS, Windows Authentication, real IIS ETW delivery, and production traffic; CPU/memory values are process-wide. Treat a report as a synthetic baseline, not an IIS capacity guarantee.

## Backend configuration editor

The administrator-only **System configuration** dashboard view edits supported non-secret settings in `appsettings.json` beside `iisidsd.exe`. `GET /api/configuration` reads the editor's supported settings, and `PATCH /api/configuration` accepts partial updates in a `{ "settings": { ... } }` object. It validates settings before writing and reports that a service restart is required before changes take effect. Unrecognized sections, including Kestrel certificate settings, are preserved but not exposed. Credentials embedded in URL settings are redacted and preserved when unchanged. Environment variables and command-line settings may override values in the file.

The editor uses the `DashboardAdministrator` policy and requires an authenticated Windows Administrator, even for local loopback requests and elevated service processes. Loopback provides a network exposure boundary, not proof of caller identity.

## Findings workflow

Suspicious request activity is processed in two layers:

1. `Detection/SuspiciousActivityDetector.cs` scores the incoming request target and returns a request-level suspicious event when indicators are present.
2. `Services/IpAggregationService.cs` groups recent stored events by client IP to produce dashboard findings.

Important detection behavior:

- repeated `404` responses from the same canonical client IP and normalized IIS site are treated as a probing signal when they fall within the configured event-time window
- repeated-not-found contributes its configured score (default `3`); by itself, that score is `Medium`, not `High`
- automatic deny-list updates require this repeated-not-found signal or a `Critical` event with at least two distinct indicators
- unfamiliar file extensions contribute risk but cannot independently make an event eligible for automatic blocking
- temporal counters are process-local and reset at restart; SQLite rows do not restore rate, path, authentication, or 404 windows
- a wall-clock rollback clears those temporal windows and increments `detection_clock_resets`

Each finding includes:

- client IP
- total request count
- suspicious request count
- highest observed risk score and severity
- distinct target domains
- merged detection reasons
- merged risk indicators
- persisted ban count

## Analyst incident workflow

The dashboard Findings queue separates detector output from operator disposition. A finding starts in `open`; administrators can mark it `acknowledged`, `suppressed`, or `resolved` and add a note. State and notes are shared through the SQLite analyst incident store and are available only through administrator-authorized `/api/incidents` routes. They do not change event data, risk scores, finding generation, or automatic deny policy. Suppressed and resolved are workflow labels, not detector suppressions.

Use the IP Details view to review retained request facts, heuristic evidence, and related findings before recording a conclusion. Configured detector-weight contributions are not returned by the existing events API, so the dashboard identifies any displayed weights as defaults rather than measured contributions. Bulk deny actions preview each selected address, evidence, observed domains, and the current Observe/Simulate/Enforce mode; confirm again if the mode changes before submission. The outcome text distinguishes applied, simulated, observed, and failed requests.

The store retains at most 5,000 analyst records, pruning the least recently updated entries when the cap is exceeded. The incident API returns at most 500 records per list request:

- `GET /api/incidents?limit=`
- `PUT /api/incidents/{clientIp}`

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
When discovery returns no sites, check the application logs for the `appcmd` error details. Automatic deny matches the IIS host binding when present and falls back to the exact IIS site name reported by ETW, which supports wildcard bindings without host names.

## IIS deny-list workflow

New installations default to `EnableDenyListChanges=true`, `EnforcementMode=Enforce`, and `DryRun=false`. Suspicious High and Critical events qualify for automatic deny on severity alone, while lower-severity repeated-404 activity remains subject to `RequireMultipleIndicators`. Allow-listed IPs are never denied. `TemporaryBanMinutes=0` means automatic bans are permanent. Configure the allow-list and verify IIS site mappings before event ingestion; IIS writes also require the process to have IIS configuration permissions. To pause writes, set `EnableDenyListChanges=false`, select `Observe` or `Simulate`, or set `DryRun=true`.

The dashboard preview reports the selected site/IP, allow-list status, existing rule ownership, expiry, and application pools or other sites that share those pools. Review it before confirming a change. The service does not modify app-pool recycling settings. Changes apply only to the selected IIS site.

Ownership and recovery rules:

- The SQLite managed-deny journal records ownership before a new IIS deny rule is committed. An existing unmanaged deny rule is never adopted or removed by the service.
- Allow-listed IPs are never added. Existing IIS allow rules are preserved. Manual removal and expiry cleanup remove only an active exact-address deny that the journal identifies as service-owned.
- Temporary expiry is tracked only for service-owned entries. Disabling enforcement stops expiry cleanup; existing IIS rules remain in place until cleanup is enabled again or an administrator removes an owned rule through the service.
- Pending IIS/database transitions are reconciled by the background cleaner while enforcement is active. Ambiguous rules are preserved and marked `recovery-required` for administrator review.
- The audit history and ownership journal are stored in the configured SQLite database. Keep that database intact during upgrades and recovery. Multiple processes using the same database serialize deny-list mutations.
- IIS writes require an authenticated Windows Administrator and may also require the process to have IIS configuration permissions.

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
- During install/start from a full interactive host, the browser dashboard stays open while the original host shuts down gracefully. The tray companion starts the service after that host exits and waits for the service health endpoint and dashboard assets to become ready; the open dashboard reconnects its live event stream automatically.
- Stop and restart wait for the Windows service to stop gracefully; restart waits for the dashboard health endpoint before reporting success.
- The context menu reports Windows service state and dashboard health separately. Lifecycle actions are enabled only for stable service states.
- A fresh install runs as the virtual account `NT SERVICE\iisidsd`, not LocalSystem or an administrator. Installation grants it read/execute access to the application directory, modify access to `appsettings.json` and `data/`, and membership in **Performance Log Users** for ETW collection. It does not grant IIS configuration rights. Existing service identities are preserved on upgrade.
- The tray companion runs in the installing user's interactive session at logon with limited privileges. It is separate from the long-running service and is guarded against duplicate instances in that session.
- The default ETW listener is required for readiness. Fresh service installation adds the `NT SERVICE\iisidsd` virtual identity to the local **Performance Log Users** group so it can enable the IIS ETW provider without running as an administrator. The listener retries after access failures and keeps the dashboard online, but `/health/ready` remains degraded until the `etw` check reports `listening`. Preserve this permission when applying host policies; do not make the service an administrator to work around an ETW access failure.

### Standalone install, upgrade, rollback, and removal

Release builds are self-contained `win-x64` bundles. The ZIP contains exactly `iisidsd.exe`, the default `appsettings.json`, and the four referenced dashboard assets under `wwwroot/`. It excludes `data/`, development settings, repository reports, and environment-specific databases. CI validates the payload and emits a SHA-256 sidecar.

1. Download the ZIP and matching `.sha256` file from the same release. Verify before extraction:

	```powershell
	$expected = ((Get-Content .\iisidsd-0.2.4-standalone-win-x64.zip.sha256) -split '\s+')[0]
	$actual = (Get-FileHash .\iisidsd-0.2.4-standalone-win-x64.zip -Algorithm SHA256).Hash.ToLowerInvariant()
	if ($actual -ne $expected) { throw 'Release checksum mismatch.' }
	```

2. Extract the versioned folder to a stable, administrator-controlled directory such as `C:\Program Files\iisidsd`. Keep the directory writable only by administrators and the service identity. The release settings retain loopback-only binding, remote access disabled, and IIS modifications disabled/dry-run by default.
3. For a fresh install, run `iisidsd.exe` as an administrator and select **Install service** in the tray menu. The installer creates the automatic service, configures bounded SCM recovery actions, grants the virtual account its runtime file access and ETW trace permission, and registers the limited logon task for the current user. Confirm `http://127.0.0.1:5080/health/ready` reports `readiness=ready` and ETW is `listening` when enabled. A virtual account is intentionally not an IIS administrator; live IIS writes remain disabled until an operator reviews and explicitly configures the required host permissions and application settings.
4. Before upgrading, stop the service and take a consistent backup of `appsettings.json` and the entire `data/` directory, including SQLite WAL/SHM files and the ETW diagnostics sidecar. Keep a copy of the current executable and `wwwroot/` for rollback. Do not copy release `appsettings.json` over the operator's file and do not replace or merge `data/`.
5. Extract the new package to a temporary directory. Replace `iisidsd.exe` and the complete `wwwroot/` directory in the stable install directory; leave `appsettings.json` and `data/` in place. Run the new executable as an administrator and select **Install service** to reconcile the SCM binary path/start mode and recovery configuration. Upgrades preserve the existing service account and do not rewrite its ACLs. Start the service, then verify the expected version and `readiness=ready` at `/health/ready`; check ETW and dashboard assets separately.
6. To roll back, stop the service, restore the saved executable and complete `wwwroot/` directory, and start the service. Keep the current configuration and database unless a release-specific migration requires restoring the matching backup. SQLite schema changes are not guaranteed to be reversible by restoring only the executable; confirm the release notes and validate the database backup before rollback.
7. To remove the service, use **Uninstall service** from an elevated tray companion. This removes the SCM entry, current-user logon task, and the Performance Log Users membership only if the installer added it; pre-existing membership is preserved. The installation directory, configuration, database, audit history, and existing ACLs are left untouched. After verifying retention requirements and backups, an administrator may remove the directory separately. Deleting application data is not part of service uninstallation.

`eng/Package-Standalone.ps1` builds the strict release ZIP and checksum; `eng/Test-StandaloneUpgrade.ps1` stages an upgrade/rollback and verifies that configuration, SQLite, and diagnostics bytes are preserved. CI runs the staging check against a package-shaped prior install. A local run also exercised the staging check with the available 0.2.3 standalone bundle. These checks do not install a Windows service or prove virtual-account ETW/IIS access.

The tray's stop action waits up to 60 seconds for SCM to report `Stopped`. Accepted ETW events are drained before graceful process shutdown; if SQLite remains transiently unavailable, the ingestion worker retries without a fixed retry limit, so a stop can exceed that UI wait. Forced termination can lose queued, not-yet-persisted events. Check service status and SQLite health before forcing termination.

## Dashboard network access

The dashboard binds to `http://localhost:5080` by default and rejects non-loopback clients. Anonymous local users can view the dashboard and read event/finding data, but all management APIs require an authenticated Windows Administrator, regardless of host elevation. The tray launches `localhost`; same-origin dashboard requests, including health and metrics checks, use Windows Negotiate credentials so the signed-in account can authenticate without a separate application login when browser integrated authentication is enabled. The access notice waits for the administrator-status request before reporting whether the account is authorized. For remote access, set `Dashboard:RemoteAccessEnabled=true`, bind remote clients to HTTPS, configure a Kestrel certificate, add the requested host to `Dashboard:AllowedHosts`, and allow the port only from intended clients through Windows Firewall. Remote clients require HTTPS and Windows Authentication; loopback clients may use HTTP but still require Windows Authentication in remote mode. Management APIs additionally require Windows Administrator membership.

Ban-count and IIS deny-list write APIs require an authenticated Windows Administrator, including for local requests. IIS deny-list changes additionally require `IisAdmin:EnableDenyListChanges=true` and process-level IIS configuration permissions; the setting is enabled by default for new installations. Do not expose the listener through a reverse proxy unless remote access is enabled and the proxy preserves the required authentication and TLS protections.

For a trusted reverse proxy, configure `TrustedProxies:Enabled=true` and list each exact proxy IP under `TrustedProxies:TrustedProxyIps`. Forwarded headers are otherwise ignored. Only `X-Forwarded-For` and `X-Forwarded-Proto` are processed, up to `ForwardLimit`; forwarded host is not used. The proxy must remove untrusted client-supplied forwarded headers before adding its own and must be restricted to intended clients. Set `Dashboard:AllowedHosts` to the public request host. See [SECURITY.md](SECURITY.md) for the full endpoint matrix and threat model.

### Detector history and metrics

Detection windows use bounded in-memory buckets keyed by canonical client IP and normalized server/host/IIS site. IPv4-mapped IPv6 addresses normalize to IPv4. DNS hosts normalize case, trailing dots, and IDN; host ports and distinct site names remain separate. Missing or malformed IP and host/site identity is omitted from temporal history rather than grouped under a shared fallback identity. See `RiskScoring.md` for detailed window, capacity, and event-lateness behavior.

History resets on restart by design. This avoids persisting additional per-client request behavior just to preserve heuristic counters. Configure `MaximumTrackedClientHistories`, `MaximumTrackedHistoryBuckets`, path-token limits, and extension-cache limits under `Detection` for memory bounds. At capacity, new history/path tokens are rejected; extension inference fails conservatively when its cache saturates. Inspect `/metrics` for `detection_client_histories`, `detection_history_buckets`, `detection_extension_sites`, `detection_path_tokens`, `detection_history_pruned`, `detection_history_capacity_rejections`, `detection_path_capacity_rejections`, `detection_extension_cache_capacity_rejections`, `detection_events_out_of_order`, and `detection_clock_resets`. These metrics do not include IP or host labels.

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

1. Before enabling event ingestion on a new installation, review the allow-list and target IIS sites. To review without writes, set `EnableDenyListChanges=false` or use `Observe`, `Simulate`, or `DryRun=true`.
2. Select the site and IP, inspect the preview, and resolve any allow-list, unmanaged-rule, or shared-pool warning.
3. For live enforcement, set `EnableDenyListChanges=true`, `EnforcementMode=Enforce`, and `DryRun=false`. These are now the new-install defaults. Restart if required for configuration changes to take effect.
4. Apply the site-specific change. Removal is available only for service-owned deny rules; administrator-owned or unmanaged rules are left untouched.
5. Verify the IIS view and the audit history. Keep the SQLite database available so pending operations can be recovered after a restart.

### Disable or roll back enforcement

1. Set `EnableDenyListChanges=false` and restart if needed. This stops new writes and expiry cleanup; it does not remove rules already present in IIS.
2. Review the deny-list audit history and service status for pending or `recovery-required` operations.
3. To remove an already-applied service-owned rule, re-enable `Enforce` under an administrator-controlled change window and use the service's site-specific removal action. Do not bulk-delete IIS rules or delete the SQLite database to clear ownership records.
4. Verify the resulting IIS deny list and audit entries, then return to the intended safe mode.

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
- `/health/live` versus `/health/ready`; inspect `checks.etw.state` and `checks.sqlite` to identify which dependency is not ready
- `queue_depth`, `queue_capacity`, and `etw_events_dropped` for saturation; `event_processing_retries` and `recovery_attempts` for transient storage trouble

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
