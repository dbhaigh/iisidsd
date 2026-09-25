# Incoming URL risk scoring

The detector assigns a heuristic score from 0 to 100 to the IIS request target. The score is an indicator of suspiciousness, not a malware verdict or a replacement for threat-intelligence reputation checks.

The current implementation stores this assessment with each persisted event and exposes it through the events feed, aggregated findings, and per-IP detail views.

## Severity bands

| Score | Severity | Meaning |
|---:|---|---|
| 0–19 | Low | No material URL anomaly detected. |
| 20–49 | Medium | Suspicious URL characteristic; investigate with request context. |
| 50–79 | High | Multiple or significant suspicious characteristics. |
| 80–100 | Critical | Strong combination of indicators; prioritize investigation or blocking according to policy. |

## Request-level scoring

Scores are additive and capped at 100. Indicators currently contribute:

- Request target exceeding the configured length threshold: **10**
- Invalid percent encoding: **20**
- Control character: **25**
- Path traversal (`../`, `..\\`, encoded or literal): **35**
- Configured suspicious path fragment: **25** per matching fragment
- Unexpected absolute-URI scheme: **40**
- User-info component in a requested URL: **25**
- Numeric IP host: **15**
- Punycode (`xn--`) host: **10**

`IsSuspicious` is set for existing detector findings or a score of 20 or higher.

Each stored event currently carries:

- `RiskScore`
- `RiskSeverity`
- `RiskIndicators`
- `DetectionReason`

## Persistence workflow

Risk-assessed events are persisted in SQLite by the event store.

Current storage behavior:

- all ingested events are written to the `events` table
- recent-event queries are served from SQLite rather than memory
- old rows are pruned according to `Storage:EventRetentionLimit`
- SSE subscribers still receive live in-process event delivery

This means the dashboard uses one model for both live and historical investigation.

## Findings workflow

Per-request scores are projected into IP-level findings by the aggregation service.

Each finding summarizes:

- highest observed risk score and severity for the IP
- suspicious request count
- total request count
- distinct domains targeted
- merged detection reasons
- merged risk indicators
- persisted ban count

A finding is therefore an operational summary of many scored events rather than a separate detection engine.

## Ban-count workflow

Ban counts are not part of the scoring formula. They are operator-managed metadata stored alongside the monitoring data.

Current behavior:

- ban counts are stored in the `ban_counts` table
- findings include the current ban count for the IP
- operators can update ban counts from the dashboard and API

This keeps risk scoring explainable while still supporting repeat-offender workflows.

## IIS workflow

The dashboard can correlate findings with IIS sites and show each site's deny list.

Current behavior:

- sites are discovered from IIS bindings
- selected findings can be matched to sites by observed domain
- deny-list entries can be viewed without enabling write operations
- deny-list modifications are gated by `IisAdmin:EnableDenyListChanges`

The IIS deny-list workflow is operational response around the score; it does not change how the score itself is calculated.

## Limits of the score

The score does not establish that a URL is malicious. Confirmation still requires reputation or threat-intelligence data and analyst validation.