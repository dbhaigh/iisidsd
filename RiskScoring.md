# Request risk scoring

The detector now mirrors the legacy C++ ETW implementation and assigns an additive heuristic score based on request metadata (status, method, URI, user-agent).

The score is an indicator of suspicious behavior, not a malware verdict or a threat-intelligence replacement.

## Severity bands

| Score | Severity | Meaning |
|---:|---|---|
| 0 | Low | No suspicious indicator matched. |
| 1–3 | Medium | Lightweight probing behavior detected. |
| 4–7 | High | Strong suspicious request trait detected. |
| 8+ | Critical | Multiple high-confidence suspicious traits detected. |

## Request-level scoring (legacy C++ parity)

Scores are additive.

- HTTP status `401`, `403`, or `404`: **+1** (`probing/error response`)
- HTTP method `TRACE`, `CONNECT`, or `DEBUG`: **+3** (`unusual HTTP method`)
- URI contains one of `../`, `%2e`, `wp-admin`, `phpmyadmin`, `/.env`: **+5** (`suspicious request URI`)
- User-agent contains one of `sqlmap`, `nikto`, `nmap`, `masscan`, `burp`: **+6** (`known security scanner user-agent`)

`IsSuspicious` is set when total score is greater than `0`.

Each stored event carries:

- `RiskScore`
- `RiskSeverity`
- `RiskIndicators`
- `DetectionReason`

## Findings workflow

Per-request scores are projected into IP-level findings by the aggregation service.

Each finding summarizes:

- highest observed risk score and severity for the IP
- suspicious request count (score > 0 or explicitly suspicious)
- total request count
- distinct domains targeted
- merged detection reasons
- merged risk indicators
- persisted ban count

## Notes

- Ban counts are not part of the score formula.
- The score remains heuristic and requires analyst validation for incident confirmation.
