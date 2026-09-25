# Incoming URL risk scoring

The detector assigns a heuristic score from 0 to 100 to the IIS request target. The score is an indicator of suspiciousness, not a malware verdict or a replacement for threat-intelligence reputation checks.

## Severity bands

| Score | Severity | Meaning |
|---:|---|---|
| 0–19 | Low | No material URL anomaly detected. |
| 20–49 | Medium | Suspicious URL characteristic; investigate with request context. |
| 50–79 | High | Multiple or significant suspicious characteristics. |
| 80–100 | Critical | Strong combination of indicators; prioritize investigation or blocking according to policy. |

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

`IsSuspicious` is set for existing detector findings or a score of 20 or higher. The score does not establish that a URL is malicious; confirmation requires reputation or threat-intelligence data and analyst validation.
