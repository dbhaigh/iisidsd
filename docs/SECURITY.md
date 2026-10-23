# Dashboard Security

## Authorization Matrix

The global dashboard gate runs before routing. With `Dashboard:RemoteAccessEnabled=false` (the default), only loopback peers are accepted; loopback is a network exposure boundary and is not caller authentication. With remote access enabled, every request, including a loopback request, must use HTTPS and authenticate through Windows Negotiate. Administrator-only routes additionally require the authenticated Windows identity to belong to the Windows Administrators group.

- `GET /`, static dashboard assets, `GET /health`, `GET /health/live`, `GET /health/ready`: anonymous on loopback in default mode; authenticated Windows user in remote mode. Health reports liveness/readiness and aggregate operational diagnostics, but not request identifiers or payloads.
- `GET /openapi/v1.json` (Development environment only): anonymous on loopback in default mode; authenticated Windows user in remote mode. It exposes the API schema, not application data or a management operation.
- `GET /api/events`, `/api/v2/events`, `/api/findings`, `/api/findings/{clientIp}`, `/api/findings/{clientIp}/events`, `/api/events/stream`, `/api/v2/events/stream`: anonymous on loopback in default mode; any authenticated Windows user in remote mode. These are read-only but disclose request metadata, including client IPs, paths, domains, and user agents.
- `GET /api/incidents`, `PUT /api/incidents/{clientIp}`: Windows Administrator only. Analyst notes and workflow states are shared operational data stored in SQLite; they do not alter detector results or enforcement policy.
- `GET /metrics`: Windows Administrator only in all modes. Metrics use aggregate values and fixed-category labels; optional OTLP export sends these metrics to the configured collector when enabled.
- `GET /api/ban-counts`: Windows Administrator only in all modes.
- `PUT /api/ban-counts/{clientIp}`: Windows Administrator only; updates ban-count metadata, not the IIS deny list.
- `GET /api/iis/sites`, `/api/iis/status`, `/api/iis/sites/{siteName}/deny-list`: Windows Administrator only.
- `POST /api/iis/deny-list/preview`: Windows Administrator only; reports the current safety checks and enforcement mode without applying a deny rule.
- `GET /api/export/findings`, `GET /api/export/events`: Windows Administrator only; exports include retained client and request data.
- `GET /api/configuration`, `PATCH /api/configuration`: Windows Administrator only. Reads return supported non-secret settings; writes validate and atomically replace supported settings while preserving unexposed sections and redacted credentials.
- `POST /api/iis/sites/{siteName}/deny-list`, `POST /api/iis/deny-list`, `DELETE /api/iis/sites/{siteName}/deny-list/{clientIp}`: Windows Administrator only and additionally gated by `IisAdmin:EnableDenyListChanges`, the allow-list, and the service's IIS mutation rules. Dry-run remains enabled by default.
- `OPTIONS` and other unmapped methods do not grant access to a mapped operation. No CORS policy is enabled.

Automatic deny-list and expiry-cleanup operations are service-to-IIS background operations, not HTTP routes. Automatic additions require `EnableDenyListChanges`; dry-run, allow-list, risk-indicator, and `RequireMultipleIndicators` rules still apply. Expiry cleanup uses the same mutation master switch and service-owned expiry records.

IIS mutation safety is independently enforced by the deny-list service: `EnableDenyListChanges` is off by default; `Observe` and `Simulate` never write to IIS; allow-listed addresses are refused; and only exact-address rules recorded as service-owned may be removed. Existing unmanaged deny rules and administrator allow rules are preserved. A SQLite journal records pending transitions for recovery, and the preview endpoint reports current rule state and shared application-pool impact. See [Operations.md](Operations.md#iis-deny-list-workflow) for enforcement and rollback procedures.

## Request Protections

- `Dashboard:AllowedHosts` is an exact host allowlist. It defaults to `localhost`, `127.0.0.1`, and `::1`; wildcards, ports, malformed names, and ambiguous numeric hosts are rejected. Configure every public/request host explicitly when binding beyond loopback.
- Unsafe methods require a same-origin `Origin`, or a same-origin `Referer` when `Origin` is absent. If present, `Sec-Fetch-Site` must be `same-origin`. Missing, malformed, cross-origin, or multi-valued origin metadata is rejected before endpoint handlers execute. This blocks ordinary cross-site form/fetch CSRF; it is not a substitute for authentication.
- Remote access always requires HTTPS and Windows Authentication, even if a reverse proxy connects to the app over loopback. Trusted forwarding is disabled unless `TrustedProxies` is enabled and exact proxy IPs are configured. Forwarded host is not accepted; operators must configure the expected public host in `Dashboard:AllowedHosts`.
- Responses set a restrictive same-origin Content Security Policy, deny framing, disable MIME sniffing, and suppress referrers. HSTS is sent only in remote mode over HTTPS.
- Management authorization executes before route handlers. Denied operations return a generic `Unauthorized` or `Forbidden` response and do not invoke state-changing services. Domain-specific validation or allow-list refusals may return their own non-sensitive 4xx response.
- Request URL logging is reduced by default; free-form deny-list reasons are kept out of application logs and DELETE audit reasons are sent in the JSON request body, not the URL. Do not place credentials or tokens in URLs. Secret-bearing certificate and endpoint credentials remain unexposed by the configuration editor.

## Threat Model and Assumptions

Protected assets include IIS configuration and deny-list entries, ban-count metadata, editable service configuration, retained request events/findings, and operational metrics. The service may run elevated to manage IIS; its Windows token is never used as proof that an HTTP caller is trusted.

The default local workflow assumes anonymous local users may view the dashboard and event/finding data. A process that can connect to loopback can read those views. Every management operation still requires an authenticated Windows Administrator, regardless of whether the process is elevated. Local malware running as an administrator can of course use that administrator's identity and is outside this boundary.

Remote mode assumes Windows Negotiate correctly identifies the user, the authenticated account is controlled by the Windows domain/local security boundary, TLS terminates at the application or at a correctly configured trusted proxy, and the proxy removes client-supplied forwarded headers before adding its own. The proxy must be the only network peer allowed to reach a proxied listener. `Origin` and Fetch Metadata are browser CSRF signals, not identity claims; authorization always comes from Windows authentication and the administrator group check.

Exact Host validation mitigates DNS rebinding and hostile Host headers by refusing hosts not configured for the dashboard. It does not protect an operator who deliberately allowlists attacker-controlled names or exposes the listener/firewall broadly. Same-origin policy does not stop malicious same-origin script or browser-extension code; XSS prevention and host hygiene remain important. Local applications can still inspect anonymous local dashboard data and denial-of-service the listener. The application cannot establish trust in an arbitrary process merely because it connects through loopback.

Response headers and origin checks are defense-in-depth. Do not treat a reverse proxy, DNS name, loopback interface, or request header as a substitute for authentication, TLS, Windows firewall policy, and administrator authorization.

## Migration and Safe Setup

1. Keep the default `Urls` listener on `http://localhost:5080` for local dashboard use. Existing elevated installations must stop relying on process elevation to authorize management calls.
2. Sign in to Windows as an account in the local Administrators group, then open the dashboard. The tray launches `localhost`; same-origin API requests use Negotiate with the signed-in Windows identity when browser integrated authentication is enabled. If the interactive user is not an administrator, use an approved Windows account switch/run-as workflow or have an administrator perform the management task; do not re-enable loopback privilege bypasses.
3. For remote access, set `Dashboard:RemoteAccessEnabled` to `true`, bind `Urls` to an HTTPS address, configure the Kestrel certificate securely, add the exact public DNS name/IP to `Dashboard:AllowedHosts`, and restrict inbound firewall access. Use a Windows Administrator account for management; other authenticated Windows users may view read-only event/finding endpoints.
4. For a reverse proxy, configure `TrustedProxies:Enabled=true` and list only its exact peer IPs in `TrustedProxies:TrustedProxyIps`. Configure the public Host under `Dashboard:AllowedHosts`; have the proxy preserve that Host while overwriting `X-Forwarded-For` and `X-Forwarded-Proto`, preserve TLS, and reject direct access to the app listener. When remote mode is enabled, forwarded scheme must resolve to HTTPS.
5. Keep `IisAdmin:EnableDenyListChanges=false` until an administrator explicitly approves the IIS mutation workflow. The safe defaults are `EnableDenyListChanges=false` and `DryRun=true`; use `Observe` or `Simulate` to review behavior. Before live writes, review the preview and audit history. Disabling the master switch later stops writes but does not remove existing IIS rules; use the Operations rollback runbook for owned-rule cleanup.

The configuration editor is administrator-only. Existing installations preserve configured URLs during upgrade; to use silent local Windows sign-in, set `Urls` to `http://localhost:5080` and `Tray:BrowserUrl` to `http://localhost:5080/`. If migration requires changing `Urls`, `Tray:BrowserUrl`, `Dashboard:AllowedHosts`, or `Dashboard:RemoteAccessEnabled` before an administrator can reach it, edit the executable-adjacent `appsettings.json` from a local Windows Administrator account, preserve secret-bearing Kestrel settings, validate the JSON, back up the file, and restart the service. Do not copy certificate passwords into support logs or source control.
