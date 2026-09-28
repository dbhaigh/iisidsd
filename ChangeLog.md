# Change Log

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

