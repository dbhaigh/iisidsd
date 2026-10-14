# Change Log

## 0.2.1 - 2026-10-14

This release collects the changes made since 0.1.4.

### Added
- Durable per-IP and per-domain findings in SQLite, incrementally updated in the same transaction as each event and independently pruned by retention.
- Configurable scoring for all detector signals, with per-IP request-rate and unique-path scanning windows and expanded exploit/scanner patterns.
- Auditing for manual and automatic IIS deny-list actions, CIDR/exact-IP allow lists, temporary bans with expiry cleanup, and dry-run status.
- OpenTelemetry metrics, Prometheus-formatted `/metrics`, and expanded health details for the ETW queue, dropped events, SQLite, and recent automatic denies.
- Responsive dashboard improvements, including theme selection, searchable/sortable findings, bulk deny, resumable/pausable live events, IP timelines, risk indicators, and charts.
- Administrator-only CSV and JSON exports for findings and retained events; CSV output protects against spreadsheet formula execution.
- Startup validation for option groups and time-based event retention through `Storage:EventRetentionDays`, alongside the row-count limit.
- Tray status for dry-run, dropped-event count, and the most recent automatic deny.

### Changed
- SQLite stores now share per-database write synchronization; transient finding-prune lock errors are retried.
- Findings responses are capped at 500 entries, and detector scores saturate instead of overflowing.
- README and risk-scoring documentation describe the release features, configuration, retention, and security model.
- Expanded deterministic tests cover detector signals, persistence and concurrency, allow-list and temporary-ban safety, exports, and authorization.

### Security
- Updated `Microsoft.AspNetCore.Authentication.Negotiate` to 10.0.13 to address [GHSA-vrrp-6v32-2p8g](https://github.com/advisories/GHSA-vrrp-6v32-2p8g).

### Fixed
- Marked the tray context's `ExitThread` method as an intentional hide of `ApplicationContext.ExitThread`, removing the compiler warning.

## 0.1.4 - 2026-10-12

### Security
- Dashboard access is loopback-only by default; opt-in remote access requires Windows Authentication and HTTPS.
- Ban-count and IIS write APIs require an authenticated Windows Administrator, and deny-list changes are disabled by default.
- Automatic blocking now requires repeated 404 evidence or a critical event with multiple distinct indicators.

### Changed
- ETW capture uses a bounded ingestion queue so SQLite and IIS operations do not run on the ETW callback.
- Detection thresholds and suspicious path fragments now use their documented configuration values, and unfamiliar file types contribute less risk.
- Tray service lifecycle operations no longer block the Windows Forms UI while waiting for service or dashboard readiness.
- ETW queue capacity is configurable, and dropped events are reported when the queue is saturated.

## 0.1.2 - 2026-09-28

### Added
- Repeated `404 Not Found` burst detection for a single client IP to identify exploit-scanning behavior.
- New detection configuration knobs: `NotFoundBurstThreshold` and `NotFoundBurstLookbackLimit`.

### Changed
- Repeated `404` probing now contributes additional risk (`+3`) and can elevate events to `High` severity for automatic IIS deny-list action.
- Documentation updated to describe repeated-404 heuristics and release behavior.

## 0.1.1 - 2026-09-27

### Added
- Automatic Startup task registration (`iisidsd Tray Companion`) to launch tray companion mode at user logon when service installation is managed from the tray.

### Changed
- Interactive startup now enters tray companion mode automatically when the Windows service is already running.
- Dashboard availability is preserved during install/start handoff while service startup transitions to background operation.
- Interactive console window is hidden during tray-interactive runs, with graceful shutdown after service and dashboard readiness checks.

## 0.1.0 - 2026-09-26

### Added
- Expanded tray icon right-click context menu for Windows service lifecycle management.
- Service actions in tray menu: install, start, stop, restart, and uninstall.
- Dynamic tray menu enablement based on administrator privileges and service state.

### Changed
- Install service action now attempts to start the `iisidsd` service immediately after successful installation.
- Documentation updates for tray service operations and release highlights.
