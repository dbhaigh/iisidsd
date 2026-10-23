# Request risk scoring

The detector assigns an additive heuristic score from request metadata and short-window behavior. It is an indicator of suspicious behavior, not a malware verdict or a replacement for threat intelligence.

## Severity bands

| Score | Severity | Meaning |
|---:|---|---|
| 0 | Low | No suspicious indicator matched. |
| 1–3 | Medium | Lightweight probing behavior detected. |
| 4–7 | High | Strong suspicious request trait detected. |
| 8+ | Critical | Multiple high-confidence suspicious traits detected. |

## Detection evaluation

The production detector can be replayed over deterministic, labeled IIS-like sequences without connecting to IIS or writing to production storage. The synthetic fixture is `Tests/DetectionEvaluation/Fixtures/baseline-v1.json`. `docs/reports/detection-evaluation-original.json` preserves the pre-refinement result; `docs/reports/detection-evaluation-baseline.json` is the current refined report.

Generate a report with the current `Detection` settings:

```powershell
dotnet run --project Tests/DetectionEvaluation -- --fixture Tests/DetectionEvaluation/Fixtures/baseline-v1.json --output $env:TEMP\detection-evaluation.json
```

Compare a candidate report with the preserved original. The output contains per-class and overall metric deltas, matched-event detection and score changes, and whether both reports used identical fixture bytes:

```powershell
dotnet run --project Tests/DetectionEvaluation -- --fixture Tests/DetectionEvaluation/Fixtures/baseline-v1.json --compare docs/reports/detection-evaluation-original.json --output $env:TEMP\detection-evaluation-comparison.json
```

The fixture contains 225 event rows across 22 scenarios. The original and current reports use the same fixture hash and retain 31 true positives, 17 false positives, 145 true negatives, and 32 false negatives: precision 0.6458, recall 0.4921, false-positive rate 0.1049, and false-negative rate 0.5079. The event comparison reports zero added or removed detections, eight lower risk scores (seven by 1 and one by 3), one score increase by 2, and 216 unchanged scores. The increase reflects the corrected repeated-404 time-window history. These results show score changes without a detection-rate change. They are a reproducible synthetic reference, not a target; do not adjust production thresholds solely to improve this fixture.

Metrics are event-level: precision is `TP / (TP + FP)`, recall is `TP / (TP + FN)`, false-positive rate is `FP / (FP + TN)`, and false-negative rate is `FN / (FN + TP)`. A metric is `null` when its denominator is zero. Per-class results group events by fixture label. Detection latency is measured only for scenarios with an explicit `activityStartEventId`, from that event timestamp to the first detected event at or after it; mean and median include detected scenarios only, and the report separately counts scenarios with no detection.

Labels are constructed hypotheses, not verified incident ground truth. No sanitized production corpus was supplied, so all checked-in traffic is synthetic and uses reserved IP ranges and `.invalid` domains; the fixture format can also replay appropriately sanitized IIS events. The dataset is intentionally small and balanced rather than representative of production prevalence, and each scenario is isolated with fresh detector history. Sequence-level slow, distributed, and rotating-source labels mark a coordinated scenario hostile even though its individual requests can be benign-looking. `SecurityEvent` has no authentication identity or outcome fields beyond HTTP status, so repeated 401s can only represent a credential-stuffing-like pattern, not confirmed account-targeted stuffing. A single 404 or 500 can be scored by the existing status rule even when the scenario label is benign. Current misses and false positives are useful baselines, not reasons by themselves to tune the detector.

## Request-level scoring

Weights and thresholds are configurable in the `Detection` section of `appsettings.json`. Scores add across evidence families, but do not stack within a family: only the matched signal with the highest positive configured weight contributes. Lower-weight matched signals remain visible in detailed evidence with a zero contribution. `ResponseOutcome` groups suspicious status, repeated 404, repeated authentication failure, and unknown extension; `TrafficPattern` groups high request rate and path enumeration. Path shape, request method, path content, and user-agent are separate families.

| Signal | Default score | Default condition |
|---|---:|---|
| Suspicious status | +1 | Status code is at least `MinimumSuspiciousStatusCode` (default `400`). |
| Long path | +2 | Path length is at least `RequestPathLengthThreshold` (default `512`). |
| Repeated 404 | +3 | The current 404 brings same-client-IP, same-site 404 responses to `NotFoundBurstThreshold` (default `3`) within `NotFoundBurstWindowSeconds` (default `60`), capped at `NotFoundBurstLookbackLimit` (default `250`) responses. |
| Repeated authentication failure | +1 | The current 401/403 brings same-client-IP, same-site authentication failures to `AuthenticationFailureThreshold` (default `5`) within `AuthenticationFailureWindowSeconds` (default `60`). This shares the response-outcome family with status scoring. |
| Unusual method | +3 | Method is `TRACE`, `CONNECT`, or `DEBUG`. |
| Suspicious path fragment | +5 | Path contains a configured `SuspiciousPathFragments` value. |
| Unknown extension | +2 | An unsuccessful request targets an extension not observed in successful requests for that site. |
| Scanner user-agent | +6 | User-agent contains a configured `ScannerUserAgents` value. |
| High request rate | +2 | Requests from the same client IP and site in `RateWindowSeconds` (default `60`) exceed `RateThreshold` (default `60`). |
| Path scanning | +2 | Unique normalized paths from the same client IP and site in `PathScanWindowSeconds` (default `60`) reach `PathScanUniquePathThreshold` (default `20`). Query strings and fragments are excluded when counting unique paths. |

Each score is configurable through its corresponding `...ScoreWeight` setting, including `AuthenticationFailureScoreWeight`. Setting a weight to zero disables that signal's scoring contribution. The default authentication weight equals the status weight, so repeated failures add behavioral evidence but do not increase the response-family score by themselves.

`IsSuspicious` is set when the resulting total score is greater than zero. Each returned event retains the existing `SecurityEvent` contract, including `RiskScore`, `RiskSeverity`, `RiskIndicators`, and `DetectionReason`.

`AnalyzeDetailed` additionally reports evidence scope (`SingleRequest`, `RepeatedBehavior`, or `CorrelatedAttackSequence`) and strength (`Limited`, `Supported`, or `Corroborated`). Strength is based on the number of contributing evidence families; these labels are qualitative metadata, not probabilities or calibrated confidence. Repeated-behavior scope is limited to the same canonical client IP and normalized site history; it does not imply cross-client, cross-site, or account-level correlation.

## History and windows

- Temporal signals use bounded, process-local event-time buckets. The history key is the normalized client IP plus server, normalized host (including port), and IIS site name when present. DNS names are IDN-normalized, lowercased, and stripped of trailing dots; IPv4-mapped IPv6 client addresses are canonicalized to IPv4. Distinct servers, hosts, ports, and IIS sites do not share counters. An event without a valid client IP and usable host/site identity cannot update temporal history.
- `MaximumEventLatenessSeconds` defaults to `2` (allowed range `0`-`30`). An event older than the latest accepted bucket for that client/site by more than this allowance, or timestamped later than system UTC plus the allowance, is skipped for temporal signals and counted in `detection_events_out_of_order`. Accepted events are assigned to UTC Unix-second buckets; window boundaries include both endpoint seconds.
- System wall-clock rollback, detected against monotonic elapsed time, clears request-rate, path, authentication, and 404 windows. These counters are not restored after restart. Persisted event rows remain available to other application features and to initialize known-extension history, but do not rebuild temporal counters.
- History is bounded by `MaximumTrackedClientHistories` (default `1024`, maximum `8192`), `MaximumTrackedHistoryBuckets` (`131072`, maximum `262144`), `MaximumTrackedPathsPerHistory` (`128`, maximum `1024`), and `MaximumTrackedPathsTotal` (`65536`, maximum `131072`). Unique paths are retained only as SHA-256 tokens after query/fragment removal, and paths longer than `MaximumTrackedPathLengthCharacters` (default `1024`) are not retained. At capacity, new history/buckets or path tokens are rejected; no source IP or host is attached to metrics.
- The extension cache is bounded by `MaximumTrackedExtensionSites` (default `256`, maximum `512`) and `MaximumExtensionsPerSite` (`128`, maximum `256`). A full site cache declines new-site inference. If one site's learned extensions saturate, unknown-extension inference is disabled for that site rather than treating unseen extensions as suspicious.
- `NotFoundBurstLookbackLimit` remains a maximum count of 404 responses that can contribute within the configured event-time window. It does not represent a number of SQLite rows or elapsed time.
- Low-cardinality metrics expose active history/bucket/site/path counts and pruning, capacity rejection, excessive-lateness, and clock-reset totals: `detection_client_histories`, `detection_history_buckets`, `detection_extension_sites`, `detection_path_tokens`, `detection_history_pruned`, `detection_history_capacity_rejections`, `detection_path_capacity_rejections`, `detection_extension_cache_capacity_rejections`, `detection_events_out_of_order`, and `detection_clock_resets`.
- Trusted forwarded headers are disabled by default. When enabled, only explicitly configured exact proxy IPs are trusted, and forwarded client/protocol values apply to dashboard HTTP requests only; IIS ETW client attribution is never taken from forwarded headers. See `TrustedProxies` in the README configuration section.
- Each `Detection` numeric setting is validated at startup. Score weights must be non-negative; thresholds and window lengths must be positive, except `RateThreshold` may be zero.

## Default pattern lists

The default path fragments cover traversal and encoding variants, common CMS/admin paths, exposed configuration and source-control files, command execution and SQL injection markers, JNDI, and common management endpoints. The default scanner user-agent list includes common web scanners, fuzzers, and security testing tools. Both lists are configuration-driven and can be replaced in `appsettings.json`.

## Findings workflow

Per-request scores are projected into IP-level findings by the findings store. Each finding summarizes the highest observed risk score and severity, suspicious and total request counts, domains, detection reasons, risk indicators, and persisted ban count.

Ban counts are not part of the score formula. Scores remain heuristic and require analyst validation before confirming an incident.

## Operational safety

- Findings are maintained incrementally in SQLite and pruned independently using `Storage:FindingRetentionDays`.
- Automatic deny-list eligibility remains governed by the existing rules, configured suspicious indicators, and `IisAdmin:RequireMultipleIndicators`; this detector refinement adds no blocking rule. `IisAdmin:AllowList` always takes precedence.
- `IisAdmin:EnableDenyListChanges` is the master write switch and defaults to `true`; `IisAdmin:DryRun` defaults to `false`, so new installations enforce automatic deny actions. High/Critical suspicious events qualify on severity alone. A positive `TemporaryBanMinutes` configures expiry; zero means a permanent entry. Set the master switch off or enable `DryRun` to prevent IIS mutations.
- Deny-list mutations and dry-run intentions are written to the audit log. Administrator-only CSV/JSON exports contain retained finding or event data; CSV formula-like fields are neutralized for spreadsheet safety.
- Loopback-only access is the default and permits anonymous dashboard viewing. Management operations require an authenticated Windows Administrator even on loopback or when the service process is elevated. Remote mode is opt-in and requires HTTPS and Windows Authentication for every request; administrator-only endpoints additionally require Windows Administrator membership.
