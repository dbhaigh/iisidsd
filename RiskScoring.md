# Request risk scoring

The detector assigns an additive heuristic score from request metadata and short-window behavior. It is an indicator of suspicious behavior, not a malware verdict or a replacement for threat intelligence.

## Severity bands

| Score | Severity | Meaning |
|---:|---|---|
| 0 | Low | No suspicious indicator matched. |
| 1–3 | Medium | Lightweight probing behavior detected. |
| 4–7 | High | Strong suspicious request trait detected. |
| 8+ | Critical | Multiple high-confidence suspicious traits detected. |

## Request-level scoring

Weights and thresholds are configurable in the `Detection` section of `appsettings.json`. Scores are additive.

| Signal | Default score | Default condition |
|---|---:|---|
| Suspicious status | +1 | Status code is at least `MinimumSuspiciousStatusCode` (default `400`). |
| Long path | +2 | Path length is at least `RequestPathLengthThreshold` (default `512`). |
| Repeated 404 | +3 | The current 404 brings recent 404 responses from the same IP to `NotFoundBurstThreshold` (default `3`). |
| Unusual method | +3 | Method is `TRACE`, `CONNECT`, or `DEBUG`. |
| Suspicious path fragment | +5 | Path contains a configured `SuspiciousPathFragments` value. |
| Unknown extension | +2 | An unsuccessful request targets an extension not observed in successful requests for that domain. |
| Scanner user-agent | +6 | User-agent contains a configured `ScannerUserAgents` value. |
| High request rate | +2 | Requests from the same IP in `RateWindowSeconds` (default `60`) exceed `RateThreshold` (default `60`). |
| Path scanning | +2 | Unique normalized paths from the same IP in `PathScanWindowSeconds` (default `60`) reach `PathScanUniquePathThreshold` (default `20`). Query strings and fragments are excluded when counting unique paths. |

Each score is configurable through `StatusScoreWeight`, `LongPathScoreWeight`, `RepeatedNotFoundScoreWeight`, `UnusualMethodScoreWeight`, `PathFragmentScoreWeight`, `UnknownExtensionScoreWeight`, `ScannerUserAgentScoreWeight`, `RequestRateScoreWeight`, and `PathScanScoreWeight`. Setting a weight to zero disables that signal's scoring contribution.

`IsSuspicious` is set when the resulting total score is greater than zero. Each returned event retains the existing `SecurityEvent` contract, including `RiskScore`, `RiskSeverity`, `RiskIndicators`, and `DetectionReason`.

## History and windows

- Repeated-404 detection continues to query recent events for the same client IP and counts only 404 responses in that event lookback.
- Known file extensions are loaded from successful (`2xx`/`3xx`) events for the domain and remain cached per domain.
- Request-rate and unique-path signals use per-IP, per-second buckets in a concurrent in-memory history. Stale buckets and inactive IP histories are pruned as new requests arrive.
- Event history is bounded by both `Storage:EventRetentionLimit` and `Storage:EventRetentionDays`; repeated-404 and known-extension history can therefore only use retained events.
- Each `Detection` numeric setting is validated at startup. Score weights must be non-negative; thresholds and window lengths must be positive, except `RateThreshold` may be zero.

## Default pattern lists

The default path fragments cover traversal and encoding variants, common CMS/admin paths, exposed configuration and source-control files, command execution and SQL injection markers, JNDI, and common management endpoints. The default scanner user-agent list includes common web scanners, fuzzers, and security testing tools. Both lists are configuration-driven and can be replaced in `appsettings.json`.

## Findings workflow

Per-request scores are projected into IP-level findings by the findings store. Each finding summarizes the highest observed risk score and severity, suspicious and total request counts, domains, detection reasons, risk indicators, and persisted ban count.

Ban counts are not part of the score formula. Scores remain heuristic and require analyst validation before confirming an incident.

## Operational safety

- Findings are maintained incrementally in SQLite and pruned independently using `Storage:FindingRetentionDays`.
- Automatic deny-list eligibility uses the configured suspicious indicators and `IisAdmin:RequireMultipleIndicators`; `IisAdmin:AllowList` always takes precedence.
- `IisAdmin:EnableDenyListChanges` is the master write switch. `IisAdmin:DryRun` defaults to `true`, records intended actions, and prevents IIS mutations. A positive `TemporaryBanMinutes` configures expiry; zero means a permanent entry.
- Deny-list mutations and dry-run intentions are written to the audit log. Administrator-only CSV/JSON exports contain retained finding or event data; CSV formula-like fields are neutralized for spreadsheet safety.
- Loopback-only access is the default and does not require dashboard-level Windows Authentication. If the host process is elevated, loopback administrator APIs bypass per-user authentication; remote dashboard access requires explicit enablement, HTTPS, and an authenticated Windows Administrator.
