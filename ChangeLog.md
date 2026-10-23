# Change Log

## 0.2.5 - 2026-10-22

### Changed
- Local dashboard defaults now use `localhost` so supported browsers can silently negotiate with the signed-in Windows account.
- Dashboard API requests explicitly send same-origin Windows credentials; read-only local viewing remains anonymous.

### Security
- Management routes continue to require an authenticated Windows Administrator; local loopback access does not bypass authorization.

## 0.2.4 - 2026-10-22

### Added
- Modular detection engine preserving built-in HTTP heuristics as the default contributor; new detectors are observe-only unless explicitly enabled for scoring.
- Structured detector evidence, deterministic cross-module deduplication, per-module health and timing metrics, and an authoring/evaluation guide.
- Durable SQLite notification outbox with severity/score thresholds, client-and-site deduplication, cooldown, bounded retries and retention, administrator acknowledgement, and an opt-in Windows Event Log provider.
- Shared SQLite-backed analyst incident states and notes, administrator-only incident APIs, prioritized findings, evidence-focused IP investigation, system health indicators, and mode-aware bulk action review.
- Notification queue dashboard, status API, acknowledgement audit identity, privacy and retention documentation.

### Changed
- Event persistence now includes structured detector evidence and the notification outbox while keeping notification enqueue failures separate from detection and event persistence.
- Operational health and metrics expose bounded ETW, SQLite, detection-module, tray, and notification state.
- Standalone release packaging and upgrade validation preserve operator configuration, SQLite data, and diagnostics while retaining safe defaults.

### Security
- External notification delivery remains disabled by default. Only the local Windows Event Log provider is implemented; no request-supplied destination or secret-bearing notification configuration is accepted.
- Notification templates redact common credential fields, bound evidence and payload size, and logs omit message bodies and exception text.

### Validation
- Added deterministic coverage for detector composition, observation-only evidence, notification deduplication/cooldown, retry and recovery, queue floods, retention, acknowledgement, and secret redaction.

## 0.2.3 - 2026-10-16

### Fixed
- IIS deny-list operations no longer change app-pool recycling settings; previews report shared-pool impact instead.

### Added
- Observe, Simulate, and Enforce policies, with enforcement disabled by default and legacy `DryRun` compatibility.
- SQLite ownership journaling, audit phases, conditional state transitions, and recovery of interrupted IIS mutations.
- Safe site-specific preview, temporary expiry for service-owned rules, and protection for unmanaged deny and administrator allow rules.
- Cross-process serialization for deny-list operations sharing the same SQLite database.

## 0.2.2 - 2026-10-14

### Added
- An administrator-only dashboard editor for supported non-secret backend settings, with validation, secret redaction, partial updates, and restart-required status.

### Changed
- Single-file service and tray launches resolve configuration and dashboard assets beside the executable, independent of the working directory or .NET extraction directory.
- The configured `Urls` value is applied to Kestrel, keeping the dashboard listener consistent with `appsettings.json`.
- The standalone package contains only the executable, configuration, and required dashboard assets; runtime SQLite data is created separately.

### Fixed
- The dashboard and its static assets are available consistently when the application runs as a Windows service.

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
- Regression coverage for local elevated-process access and live event streams that open before the first event arrives.

### Changed
- SQLite stores now share per-database write synchronization; transient finding-prune lock errors are retried.
- Findings responses are capped at 500 entries, and detector scores saturate instead of overflowing.
- Loopback dashboard viewing no longer prompts for Windows Authentication. When the host process is elevated, loopback administrator APIs are also available without another prompt; remote access continues to require HTTPS and an authenticated Windows Administrator.
- Service and tray launches use the executable directory for configuration and dashboard assets. Interactive startup opens the dashboard, and service handoff waits for the interactive host to release the port and verifies the UI assets before reporting readiness.
- Warning and danger notices can be dismissed while remaining logged in the browser console.
- The standalone x64 package contains only the executable, configuration, and required dashboard assets; runtime SQLite data is kept out of the package.
- README and risk-scoring documentation describe the release features, configuration, retention, and security model.
- Expanded deterministic tests cover detector signals, persistence and concurrency, allow-list and temporary-ban safety, exports, and authorization.

### Security
- Updated `Microsoft.AspNetCore.Authentication.Negotiate` to 10.0.13 to address [GHSA-vrrp-6v32-2p8g](https://github.com/advisories/GHSA-vrrp-6v32-2p8g).

### Fixed
- The live event stream now flushes its SSE handshake immediately, so the dashboard connects even before ETW produces its first event.
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
