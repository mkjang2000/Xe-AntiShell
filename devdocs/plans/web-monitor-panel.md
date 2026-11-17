# Local Web Monitoring Panel

## Purpose

Provide a small, self-hosted web panel for the standalone Xe-AntiShell agent.
The panel is read-only and focuses on detections, candidate events, process
context, capability state, and collection health. It must not add response,
policy mutation, or central-management behavior.

## Completion Criteria

- A separate unprivileged `sentinel-web` service reads the existing local API
  through its Unix socket; it never opens SQLite directly.
- The packaged listener binds `0.0.0.0:9088` only with an explicit
  non-loopback opt-in. The RPM does not alter host firewall policy.
- An Argon2id-protected administrator login and signed, expiring session cookie
  protect every dashboard and API route.
- The UI presents agent health, telemetry loss counters, capability state,
  finding history, candidate event detail, and process ancestry.
- Static assets are embedded in the Go binary and require no CDN or external
  browser dependencies.
- The RPM creates a dedicated system account, installs a hardened systemd unit,
  and does not expose a password in source, command arguments, or logs.

## Current Structure

`sentineld` exposes a read-mostly HTTP/JSON API over a mode-0660 Unix socket.
The `sentinel` CLI is the only current human interface. Findings and events are
already bounded by the local API and contain the data needed by the initial
panel.

## Design

### Process boundary

```text
Browser on administrator workstation
-> host firewall
-> 0.0.0.0:9088 listener on monitored host
-> sentinel-web (unprivileged)
-> /run/xe-antishell/sentineld.sock
-> sentineld local API
-> SQLite
```

`sentinel-web` runs as `xe-antishell-web` with supplementary access to the
`xe-antishell` socket group. The privileged agent remains a separate process.

### Authentication

- One local administrator username is sufficient for the standalone version.
- Passwords use Argon2id with a random salt and bounded parameters.
- A random HMAC key signs stateless session cookies with an eight-hour expiry.
- Cookies are HttpOnly and SameSite=Strict. Secure is omitted because the
  current service is plain HTTP; deployment must therefore keep port 9088 on a
  trusted network until TLS termination is designed.
- Login attempts are rate-limited and failures use a generic response.
- An opaque browser `Origin` is accepted only when both the requested host and
  the TCP peer are loopback, covering local IDE forwarding without weakening
  direct network-origin checks.
- The auth file is root-only and passed to the unprivileged service through
  systemd credentials.
- Initial plaintext password delivery uses a separate root-only file and is
  deleted by the administrator after first login.

### User interface

- Overview cards: health, collector, last event, dropped/parse counters, open
  findings, and platform/kernel.
- Detection history: time, severity, rule, confidence, summary, process key,
  evidence identifiers, and an explicit self-test badge.
- Candidate events: time, origin service, executable, UID/EUID, PID/PPID, CWD,
  argv, completeness, and process-tree inspection.
- System section: capability states and reasons.
- Client-side search/severity filters and periodic refresh. Browser code uses
  DOM text nodes rather than injecting event strings as HTML.
- A future monitoring view should group health, events, and findings by exact
  `origin_service` so noisy or unhealthy application services are easier to
  review without changing detection policy.

## Change Scope

- Add `cmd/sentinel-web` and `internal/webpanel`.
- Add embedded HTML, CSS, and JavaScript assets.
- Add the web systemd unit and package account creation.
- Give the existing agent socket a dedicated group while keeping world access
  disabled.
- Extend RPM/static build targets and operational documentation.

## Failure Handling

- Failure to parse credentials, connect to the Unix socket, or bind the
  configured address prevents startup with a clear error.
- Agent API failures appear as a dashboard error without exposing internal
  filesystem details to unauthenticated clients.
- API responses and authenticated pages are no-store.
- Authentication never falls back to an open dashboard.
- The panel remains read-only if the agent is degraded.

## Security Boundaries

- Non-loopback binding requires the explicit `--allow-non-loopback` option and
  a literal IP. Hostnames are not resolved by the service.
- RPM installation does not add or alter firewall rules.
- Plain HTTP must not be exposed to an untrusted network because credentials
  and sessions lack transport encryption.
- No remote scripts, fonts, analytics, or CDNs.
- CSP, frame denial, MIME sniffing denial, and referrer restrictions are set on
  every response.
- Request bodies, header sizes, API limits, and login field lengths are bounded.
- No raw database or audit-ingest endpoint is proxied to the browser.

## Compatibility / Impact

- Initial packaging targets the installed Rocky Linux 9 systemd environment.
- The dashboard does not change the current detector, collector, or evidence
  schema.
- Existing CLI commands continue to work for root and socket-group members.
- CentOS 7 systemd credential support requires separate validation before the
  web unit is declared compatible there.

## Validation Plan

1. Unit-test password verification, session tampering/expiry, rate limiting,
   protected routes, security headers, API bounds, and agent failures.
2. Run full tests, race detector, vet, and static builds.
3. Validate the RPM contents and systemd units.
4. Install without changing audit or detector configuration.
5. Verify the web process is unprivileged, listens on the configured wildcard
   address, does not change firewall policy, and can read the Unix-socket API.
6. Verify wrong-password rejection, successful login, dashboard/API rendering,
   logout, and unauthenticated redirects through a local HTTP client.
7. Confirm `sentineld`, audit loss/backlog, and existing CLI results remain
   unchanged.
