# Engineering Audit

- **Audit date:** 2026-10-21
- **Repository version:** 0.2.3 / .NET 10 Windows
- **Validation:** `dotnet build iisidsd.slnx --no-restore` succeeded; `dotnet test iisidsd.slnx --no-build --no-restore` passed 79/79 tests. These are baseline results captured before this document was added. No source changes were made during the audit.

**Security follow-up:** This is a historical audit snapshot. The elevated-loopback authorization finding and the listed HTTP-hardening gaps were addressed after the audit; see [SECURITY.md](SECURITY.md) for the current route matrix and trust assumptions. The baseline test count and findings below are not current validation results.

## Scope and Method

Reviewed the application and test C# source, solution and project files, appsettings, publish profile, dashboard HTML/JavaScript/CSS, and repository documentation. Inspected dependency versions and test inventory. The repository has no `.github/workflows` files or other CI workflow configuration. Generated `bin/`, `obj/`, and publish artifacts were not treated as source; the runtime SQLite database contents were not inspected. Build and tests ran on the available Windows environment; IIS/ETW and service installation were not exercised against a production IIS host.

The worktree already contained extensive deletions of older `artifacts/` packages and untracked 0.2.x publish outputs at audit start. They were left untouched and are not part of this report or its change set.

## 1. Architecture and Dependency Map

```text
Program.cs
  ├─ configuration and validated Options
  ├─ Windows Negotiate authentication + DashboardAdministrator policy
  ├─ ASP.NET Core minimal API + static dashboard
  ├─ SQLite stores / finding and ban-count services
  ├─ IIS discovery, allow-list, deny-list, audit, expiry cleanup
  ├─ hosted ETW listener, database initialization and retention jobs
  └─ optional Windows Forms tray companion

IIS ETW provider
  └─ Etw/IisEtwListener callback
      └─ bounded ingestion Channel<SecurityEvent>
          └─ Detection/SuspiciousActivityDetector
              ├─ request scoring + in-memory rate/path history
              ├─ recent SQLite history reads for 404 / extension signals
              └─ SqliteEventStore.Publish
                  ├─ event insert + retention prune
                  ├─ incremental IP/domain finding upsert (same transaction)
                  └─ per-subscriber bounded channels → SSE

Dashboard (wwwroot)
  ├─ events/findings/exports/health/metrics endpoints
  ├─ administrator-only configuration and mutation endpoints
  └─ IIS mutation → IisDenyListService → allow-list + SQLite audit/expiry
      ├─ Microsoft.Web.Administration writer for mutations
      └─ appcmd.exe for site discovery and deny-list reads

TrayIconService
  ├─ STA Windows Forms context and dashboard health polling
  └─ sc.exe / schtasks.exe for service and logon-task lifecycle
```

`Program.cs` is the composition root. `IisEtwListener` is the sole event-processing consumer; it synchronously analyzes, persists, and may invoke automatic IIS deny logic. SQLite event, finding, ban-count, and deny-list stores share a process-local per-database write lock (`SqliteDatabaseLock`); event insertion and finding upsert share a transaction. Event SSE subscribers have independent bounded drop-oldest channels. The static dashboard uses fetch plus `EventSource` and renders server data using DOM text nodes rather than interpolated HTML.

Primary external dependencies are TraceEvent for ETW, ASP.NET Core Negotiate auth, Microsoft.Data.Sqlite / SQLitePCLRaw, Microsoft.Web.Administration, Windows Services/Forms, and OpenTelemetry. The standalone publish profile targets self-contained single-file `win-x64`; it publishes configuration and dashboard assets beside the executable and excludes Development settings.

## 2. Confirmed Defects and Security-Relevant Behavior

### F-01: Repeated-404 scoring has no time window (Resolved)

**Severity: High (P1)**

**Evidence:** `SuspiciousActivityDetector.IsRepeatedNotFoundScan` calls `IEventStore.GetRecent(lookbackLimit, clientIp: ...)` and counts all 404 rows in that row limit. Neither the query nor detector applies a timestamp cutoff. `NotFoundBurstLookbackLimit` therefore limits rows, not elapsed time. The resulting indicator is consumed by `IisAutoDenyService.Apply`; with the configured default `RequireMultipleIndicators=true`, a 404 also contributes the status indicator, satisfying the two-indicator gate. If deny writes are enabled and dry-run is off, widely separated 404s can qualify for automatic denial. Temporary bans default to permanent (`TemporaryBanMinutes=0`).

The current detector test verifies a three-event threshold, but does not assert expiry after a time gap. `RiskScoring.md` calls this a burst/recent signal, which the implementation does not enforce.

**Impact:** False-positive automatic IIS blocks, potentially permanent, from low-rate requests spread across the event-retention period.

**Status:** Resolved after this audit. Repeated-404 scoring now uses bounded event-time request history and a validated time window. Keep the close-in-time threshold and stale-event tests as regression coverage; the historical finding above does not describe the current detector.

### F-02: Elevated service grants administrator APIs to every loopback caller (Resolved)

**Severity: High (P1), confirmed trust-boundary exposure**

**Evidence:** The tray creates the service with `sc.exe create ...` and does not specify a service account; Windows defaults this service to LocalSystem. `Program.cs` computes `hostIsAdministrator` once at startup. `DashboardAccessPolicy.CanAccessAdministratorFeatures` grants administrator features to any local request when that value is true. Local requests bypass dashboard authentication in `DashboardAccessPolicy.Evaluate` / middleware. The configuration editor, export, ban-count write, IIS status, and deny-list mutations use the `DashboardAdministrator` policy. The README explicitly notes that elevated-host loopback access is available to all local processes.

**Historical impact:** An unprivileged local process could invoke administrator-only dashboard functions against an elevated service without presenting a Windows administrator identity, including supported configuration writes.

**Status:** Resolved after this audit. The process-elevation bypass was removed. Every administrator-only endpoint now requires an authenticated Windows identity in the Administrators group, regardless of loopback address or service elevation. Default loopback viewing remains available. `LocalDashboardAccessTests` verifies that anonymous and forged generic administrator-role callers cannot invoke a management handler. Route-level tests cover administrator success using a synthetic test policy; a real Windows administrator identity was not exercised in this environment.

### F-03: IIS binding parser does not safely parse IPv6 bindings

**Severity: Medium (P2)**

**Evidence:** `IisSiteDiscoveryService.ParseDomain` splits each binding on every colon and takes `parts[2]` as the host. IIS binding information includes colon-delimited address and port fields; an IPv6 address itself contains colons. An IPv6 binding can therefore yield a fragment of the address instead of the hostname. Domain-to-site matching in manual and automatic deny flows depends on these parsed domains.

**Impact:** Sites with explicit IPv6 bindings may be absent from finding-to-site matching, causing deny actions to miss the correct site or report no matching site.

**Required regression:** Unit-test supported IPv4, wildcard, hostname, and bracketed IPv6 binding forms against actual IIS binding serialization; then add a Windows integration check where IIS is available.

## 3. Potential Risks Requiring Further Verification

- **Reverse-proxy deployment:** Forwarded client address and scheme are now accepted only when `TrustedProxies:Enabled` is true and the immediate peer matches an exact configured proxy IP. Forwarded host is not enabled; configure the public host in `Dashboard:AllowedHosts`. Remote mode still requires HTTPS and Windows authentication after trusted forwarding is applied. The application cannot verify that a proxy strips client-supplied forwarded headers or that its listener is unreachable directly; those remain deployment requirements.
- **Attacker-driven domain cardinality:** ETW domain extraction prefers `cshost` (the IIS `cs-host` field). If clients can supply arbitrary host values on an accepted binding, `SuspiciousActivityDetector._knownExtensionsByDomain` has no eviction, and `ip_finding_domains` stores per-IP/domain rows while an active IP's aggregate JSON carries the domain set. Finding retention is age-based, not a global cardinality cap. Repeated unique Host values could increase memory, row count, and per-event JSON aggregation cost. Confirm the provider field semantics, accepted-host behavior, and expected workload; add cardinality limits/eviction if inputs are client-controlled.
- **ETW memory/backpressure:** The 10,000-item ingestion queue is bounded by item count, not payload bytes. Each event retains all payload fields and request strings. On saturation, `TryWrite` drops events (counted and logged); synchronous SQLite and recent-history reads on the sole consumer can increase drops during load. There is no sustained-overload or maximum-event-size test.
- **SSE fan-out:** Each connected client gets a channel sized by `SubscriptionBufferSize` (default 1,000); subscriber count is not capped. Many local or enabled remote clients can multiply event-buffer memory. Confirm expected client counts and consider admission limits/metrics.
- **Subprocess liveness:** `AppCmdRunner.Run`, `TrayIconService.RunScCommand`, and `RunSchtasksCommand` lack timeouts/cancellation. Tray helpers wait for exit before reading redirected streams; `AppCmdRunner` drains stdout then stderr. Large output on the unread pipe can block a child and leave service-management or IIS operations hung. Outputs are usually small, so reproduce against representative failures before classifying as a field defect.
- **Dry-run expiry accumulation:** `TemporaryDenyListCleaner` leaves expired `iis_temporary_denies` rows in place when dry-run is active. It records each processed entry in `_dryRunActionsLogged`, an unbounded in-memory `HashSet`, and the next scan still pages through the expired rows. This is conditional on previously persisted temporary denies being present while dry-run is enabled (for example, after a configuration change); verify expected dry-run semantics and restart behavior. The existing service test explicitly asserts that dry-run expiry keeps the stored expiry, so cleanup must not silently change the simulation contract.
- **IIS app-pool setting side effect (Resolved after audit):** The audit-time implementation permanently set `DisallowRotationOnConfigChange=true` on application pools used by target sites. That mutation was removed; deny-list writes no longer change app-pool settings, and previews report shared-pool impact. See [Operations.md](Operations.md#iis-deny-list-workflow) for current behavior.
- **SQLite deployment/migration:** Schema initialization uses `CREATE TABLE IF NOT EXISTS` plus a hand-coded `ban_counts` shape migration; there is no schema-version table or documented rollback path. The migration SQL does not create an explicit transaction. Verify SQLite command/autocommit behavior on interruption and test backups/upgrades from every shipped schema before relying on in-place upgrades.
- **Database and export sizing:** The event table is capped by count and age, but finding aggregates are not capped globally and active IPs retain cumulative counts. Event/export endpoints can materialize up to the configured event retention limit in memory; payload sizes are not constrained. Establish disk/RAM budgets and test high-volume and large-field behavior.
- **HTTP hardening (Resolved):** The dashboard now applies a same-origin Content Security Policy, `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy`; HSTS is emitted for remote HTTPS responses. Unsafe methods are subject to same-origin checks and exact Host allowlisting. Browser-level verification and XSS regression tests remain desirable.
- **Supply-chain/release controls:** Package versions are pinned in the project, but no committed lock file, CI workflow, signed release manifest, checksum/SBOM workflow, or automated publish verification was found. `SQLitePCLRaw.lib.e_sqlite3` is pinned to a prerelease version. Confirm provenance and support status before release and add reproducible dependency/release checks.

## 4. Security Threat Model and Trust Boundaries

**Assets:** IIS site security configuration and application-pool behavior; service identity and service control; `appsettings.json`; SQLite event/finding/audit data; dashboard access and export data; ETW capture continuity; OTLP telemetry credentials/data.

**Inputs and actors:** IIS clients influence request path, method, status, user-agent, and potentially host values recorded by ETW. Local processes can connect to loopback. Dashboard administrators can edit supported settings and request IIS changes. Remote dashboard clients are possible only when enabled. The service interacts with ETW, SQLite on local disk, `appcmd.exe`, IIS configuration APIs, Windows service/task control, and an optional OTLP endpoint.

**Trust boundaries and existing controls:**

- Network boundary: loopback-only listener and non-loopback rejection by default; opt-in remote access requires HTTPS and Negotiate authentication.
- Authorization boundary: administrator-only routes require an authenticated Windows administrator identity in all modes. Loopback and service elevation do not establish caller authorization.
- IIS mutation boundary: writes disabled by default, dry-run enabled by default, exact-IP validation, CIDR/exact-IP allow-list, audit rows, and automatic-deny indicator gates.
- Persistence boundary: parameterized SQL, event retention, and same-transaction event/finding updates; database file ACL, backup, restore, and cross-process coordination remain operator responsibilities.
- Telemetry boundary: optional HTTP(S) OTLP exporter sends configured metrics to an operator-selected endpoint.

**Primary threats:** Anonymous local access to event/finding data in default mode; remote access misconfiguration or proxy trust confusion; false-positive automatic denial; resource exhaustion through event rate/cardinality or slow storage; IIS configuration side effects; loss or corruption during upgrade/recovery; exposure of client IPs, URLs, user-agent strings, and properties through database/log/export handling.

**Security posture summary:** The defaults are deliberately conservative for remote access and IIS writes. Anonymous local viewing exposes retained event/finding data, while management requires an authenticated Windows Administrator identity. Elevated loopback callers no longer bypass authorization. Remaining deployment risks include proxy topology, local data visibility, IIS behavior, resource/cardinality limits, and recovery evidence.

## 5. Performance Bottlenecks and Resource Growth

- One ETW consumer processes each event serially. It may perform repeated-event SQLite reads, extension-history loads, an event insert, retention delete, finding and domain UPSERTs, and an automatic deny path before dequeuing the next event.
- `SqliteEventStore.Publish` opens a connection and runs transaction work per event. No batching, explicit WAL mode, or write-latency backpressure policy is configured. Queue depth and dropped-event metrics exist, but no queue high-water alert is configured in-repository.
- Finding JSON arrays are merged with `json_each`/`UNION` during each upsert. Cost grows with an active IP's accumulated domains, reasons, and indicators until pruning changes the domain set.
- Detector state includes per-IP sliding windows and an unbounded per-domain extension cache. Inactive IP histories are periodically swept; domain cache entries are not.
- The queue is item-bounded, each SSE subscriber has its own item-bounded channel, and neither bounds serialized payload bytes or total clients.
- Event retention limits the `events` table to the configured count/age, but active finding aggregates can outlive individual retained events and remain cumulative until their last-seen time expires. Clarify this distinction in dashboard/API semantics.
- Startup backfill reads retained events into a list before rebuilding findings. It is bounded by event count under normal retention, but can increase startup memory and delay after migration or recovery.

## 6. Test Coverage Gaps

The 79-test suite has useful coverage for detector signals, startup option validation, SQLite retention/backfill/concurrent writes, finding pruning, access-policy decisions, API authorization/exports/SSE handshake, allow-listing, deny-list dry-run/expiry/audit, and service-independent aggregation. No tests failed in the baseline run.

High-value gaps:

- Full detector-to-auto-deny behavior with stale evidence, beyond the focused repeated-404 window regression tests.
- ETW payload field mapping, provider/session startup failures, queue saturation/drop accounting, and shutdown/drain behavior; no ETW listener tests were found.
- IIS site binding parser (especially IPv6), real `Microsoft.Web.Administration` mutation behavior, app-pool setting lifecycle, and appcmd failure/timeout behavior.
- Tray service install/start/stop/restart/uninstall, scheduled-task setup, process pipe saturation, and handoff failures.
- Browser-level tests for accessible dashboard flows, SSE reconnect/filter behavior, rendering of hostile strings, and error handling; no frontend test runner or browser automation was found.
- Successful management authorization with a real Windows Administrator identity, and end-to-end proxy/forwarded-header behavior on a deployed Windows host.
- Migration interruption/rollback and upgrade/restore tests across historical databases; no versioned migration harness was found.
- Load tests for ETW queue capacity, SQLite write throughput, finding/domain cardinality, subscriber count, and peak export memory.
- No repository CI workflow currently runs the build/tests or validates Windows publish output.

## 7. Deployment, Upgrade, Recovery, and Operational Risks

- Runtime requires Windows, .NET 10 (unless self-contained), IIS ETW provider availability, and IIS tooling/permissions for administrative functions. Service hosting and tray code are Windows-specific; build/test success does not prove ETW provider or IIS compatibility on a target host.
- Fresh tray installation creates an automatic Windows service under `NT SERVICE\iisidsd`, grants runtime file permissions, configures bounded SCM recovery actions, and registers a limited logon task. Upgrades preserve existing service identities and permissions. ETW session access and any IIS configuration permissions remain host-specific and require real Windows/IIS validation; see `docs/Operations.md`.
- The default listener is `http://127.0.0.1:5080`; non-loopback access is rejected by default. Loopback viewers are not automatically administrators. Remote access requires explicit configuration, HTTPS certificate setup, Windows Authentication, and firewall restriction. Do not assume a reverse proxy is safe without trusted forwarding and identity behavior being verified.
- `appsettings.json` and `wwwroot/` must be beside the executable for service/single-file launches. Configuration edits write the executable-adjacent `appsettings.json`; filesystem permissions and backup/restore of this file are operationally important. Environment variables/command-line values may override saved settings.
- Publish profile is versioned with the project (`0.2.3`) and writes into `artifacts/`. Runtime database content is intentionally separate and should not be copied into release artifacts. The workspace had generated publish artifacts and a runtime data directory; neither was modified or included in this audit document.
- Upgrade safety depends on implicit schema checks rather than a schema version. Stop the service and take a consistent backup of `data/iisidsd.sqlite3` and `appsettings.json` before upgrades; validate restore, not merely backup creation. Keep previous executable/configuration available for rollback.
- Event/finding pruning is daily and age/count based. Deny-list audit rows have no retention cleanup; long-running deployments will accumulate audit history unless operators manage it externally.
- Health and metrics are available locally; event drops are observable but no alerting policy or dashboard threshold is shipped. Define an alert for sustained queue depth/drop counts and SQLite health degradation.
- Windows CI now publishes through an exact runtime allowlist, checks safe defaults and excluded state, creates a reproducible-timestamp ZIP with a SHA-256 sidecar, and stages upgrade/rollback state preservation. This is not a signature or provenance attestation. CI's staged upgrade is a filesystem test; it does not exercise SCM account creation, ETW provider permissions, tray logon behavior, or IIS writes on a target host.

## 8. Prioritized Remediation Backlog

Effort: S = small, M = medium, L = large. Priority is recommended sequencing; acceptance criteria are required before marking an item complete.

| Priority / severity | Remediation | Expected benefit | Effort / dependencies | Acceptance criteria |
|---|---|---|---|---|
| P1 / High (Completed) | Resolve the elevated loopback authorization boundary. Privileged APIs now require an authenticated Windows Administrator identity even for loopback callers and elevated service processes. | Prevents untrusted local processes from using service-level configuration, export, and IIS controls. | Completed; real Windows administrator success-path validation remains deployment evidence. | Default-loopback integration test denies anonymous and forged-role callers before mutation; route-level authorization tests cover admin success with a synthetic test identity; deployment docs state the trust boundary. |
| P1 / High (Completed) | Add an event-time interval to repeated-404 detection and align naming/docs/options. | Avoids automatic blocks based on sparse historical 404s. | Completed; broader detector-to-auto-deny integration remains useful. | Focused tests cover the threshold within the window and exclusion of events outside it; options clamp the configured window. |
| P2 / Medium | Replace colon-splitting IIS binding parsing with format-aware parsing and fixture tests. | Makes IPv6 and unusual binding sites discoverable for safe targeting. | M; verify actual Windows/IIS serialization. | Unit tests cover wildcard, IPv4, hostname, and IPv6 bindings; Windows integration verifies matched site/domain. |
| P2 / High | Bound attacker-influenced domain and detector state; establish aggregate cardinality and payload limits. | Limits memory/SQLite growth and per-event UPSERT cost. | M/L; verify ETW `cshost` semantics and define retention/cardinality policy. | Load test with many unique hosts/IPs demonstrates bounded memory/database growth and acceptable event processing/drop rate; normal findings behavior remains covered. |
| P2 / Medium | Add cancellation, timeouts, and concurrent stdout/stderr draining to process runners. | Prevents a stalled child process from hanging IIS or service lifecycle actions. | M; shared runner abstraction can be considered without changing command semantics. | Simulated slow/noisy child exits or times out within a documented bound; output/error are both captured without deadlock; tray remains responsive. |
| P2 / Medium | Revisit app-pool rotation suppression and make the global side effect reversible or narrowly scoped. | Prevents deny-list changes from silently changing behavior of unrelated IIS configuration updates. | L; IIS behavior validation and rollback design. | Windows integration proves deny-list changes meet the intended recycle behavior while unrelated config changes retain expected recycling; cleanup/upgrade restores prior settings safely. |
| P2 / Medium | Bound and retire expired temporary-deny metadata in dry-run mode without pretending IIS was changed; cap/expire corresponding in-memory deduplication state. | Prevents repeated scans and memory/database growth after a dry-run transition. | M; define whether simulation should persist expiry metadata and how retries/audits remain visible. | A test with many expired records in dry-run remains bounded over repeated cleaner cycles, preserves audit truth, and does not mutate IIS; normal expiry still removes real denied entries. |
| P2 / Medium | Add versioned, transactional SQLite migrations and a tested upgrade/restore procedure. | Reduces data-loss risk and improves diagnosability across releases. | M/L; define supported historical schemas and backup strategy. | Upgrade tests from each supported schema preserve events, findings, bans, audit, and expiry data; interrupted migration leaves old or new schema recoverable; restore runbook is exercised. |
| P3 / Medium | Add Windows CI for build/tests/publish and dependency/release provenance checks; review the pinned prerelease SQLite native package. | Detects regressions and supply-chain/runtime packaging issues before release. | M; CI environment and release ownership. | CI runs restore, build, all 79+ tests, and standalone publish; dependency audit and release checksum/signature/SBOM outputs are retained. |
| P3 / Low | Add ETW, IIS, tray, browser, and overload-focused tests in proportion to the changed surfaces. | Closes the largest untested behavior paths and protects future fixes. | M/L; Windows integration runner and browser test environment. | Tests cover ETW mapping/overflow, IIS parser/writer, tray command timeouts, UI SSE/reconnect, hostile data rendering, and high-cardinality resource budgets. |

## Audit Conclusion

The existing architecture is coherent and preserves useful safeguards: loopback-only default exposure, authenticated Windows-administrator authorization for management, opt-in IIS writes, dry-run default, allow-list checks, parameterized SQLite access, bounded event queues, incremental transactional findings, and the historical passing baseline test suite. The elevated-loopback bypass and unbounded repeated-404 evidence were resolved after this snapshot. IIS-specific behavior, cardinality/load behavior, subprocess liveness, and migration recovery still need Windows integration evidence before operational guarantees are made.
