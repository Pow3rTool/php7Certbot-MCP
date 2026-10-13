# php7certbot-mcp

A small [MCP](https://modelcontextprotocol.io) server that exposes a **read-first, on-behalf-of**
tool surface over an enterprise PHP7/Laravel certificate-management API ("CertBot" — an ACME +
internal-CA management app, *not* Let's Encrypt's `certbot` client). It lets an agent inventory
certificates, retrieve delivery links, and (optionally) request or re-sign **server** certificates
— always as the calling user, never as a shared service identity.

## Security model — read this first

This server is a thin broker. **It does not implement its own authorization model, and it is not a
floor.** It is an *artificial ceiling* layered on top of whatever permissions the calling user
already has in CertBot.

- **On-behalf-of (OBO).** The front door validates the caller's Entra (Azure AD) bearer token, then
  performs an RFC 8693 on-behalf-of exchange to mint a token **audienced to CertBot and carrying the
  real user's identity**. Every backend call is made as that user — not as the MCP's app identity.
- **Authorization is CertBot's, not the MCP's.** CertBot enforces its own per-account authorization
  (its Bouncer roles/abilities) against the OBO'd user. If the user can't do something directly in
  CertBot, they can't do it through this MCP either. The MCP adds **no** access of its own — a user
  with no CertBot grants sees nothing here.
- **The MCP only ever *restricts*, never expands.** On top of the user's CertBot permissions it caps
  the surface further: read-only by default (issuance is opt-in, see below), **server certificates
  only** (it cannot create or re-sign CA/intermediate or client/user certs), and it re-validates
  requested hostnames against the account's permitted zones. So the effective capability is always
  `min(what CertBot grants the user, what this MCP allows)` — a tighter ceiling, never a floor.
- **Auditing is mostly CertBot's too.** CertBot is the system-of-record for who did what to which
  certificate; it authorizes and logs the actual operations. The MCP keeps a **supplementary** local
  audit log (and an issuance journal) for MCP-level visibility, but it is not the authoritative
  record — CertBot is.

Net: think of this as a convenience/guardrail layer in front of CertBot for agents, not a new
authority. All the real security decisions still happen in CertBot.

## The `trust` axis

Every tool that needs to pick an issuing authority takes `trust`:

- `public` — ACME / Let's Encrypt accounts (publicly trusted certs)
- `private` — internal enterprise CA accounts (privately trusted certs)

(There is deliberately no `ca`/`type` selector on the surface — this tool only issues server certs.)

## Tools

**Read (always available):**
- `list_accounts(trust?)` — issuing accounts (both pools if `trust` omitted): id, name, trust, zones.
- `search_certificates(trust, query, account_id?)` — find certs by hostname/name/id across accounts
  (or one account); returns full context for disambiguation. Use this in a large estate.
- `list_certificates(trust, account_id, query?)` — certs in one account.
- `get_certificate(trust, account_id, certificate_id)` — one cert's detail (no key material).
- `get_pem_link(trust, account_id, certificate_id, fmt?)` — a download URL the target host curls
  directly from CertBot; the key bytes never pass through this server or the model.
- `list_expiring` / `list_expired` — fleet-wide expiry monitors.

**Issuance (only when `CERTBOT_ENABLE_ISSUANCE=true`):**
- `request_server_certificate(trust, account_id, name, subjects)` — create + sign a new server cert.
- `update_certificate_hostnames(trust, account_id, certificate_id, subjects)` — replace the SAN set
  on an existing **server** cert and re-sign, **keeping the existing private key**.
- `check_issuance(trust, account_id, certificate_id)` — poll a sign that returned `issuing`
  (public/ACME signs run DNS-01 and can take minutes). Reconciles against CertBot's own cert record,
  so it survives an MCP restart.

## Configuration

All configuration is environment-driven; see [`.env.example`](.env.example) for the full list and
notes (Entra app identity, the OBO client-credential cert, the CertBot API base, the front-door
audience/scope/allowed-client, and the issuance toggles). Config is validated fail-closed at import
— the server refuses to start with missing values or unreplaced placeholders.

Secrets (the `.env` file and the client-credential `*.pem`) are **mounted at runtime, never baked
into the image and never committed** (see [`.gitignore`](.gitignore)).

## Deployment

Build the self-contained image from the included `Dockerfile` and run it behind a TLS-terminating
reverse proxy that forwards the `Authorization` header. It runs non-root, validates every incoming
bearer (JWKS signature, audience, issuer, expiry, required scope, allowed client), and talks to
CertBot only over HTTPS.

## HTTP authentication and client compatibility

HTTP initialization, discovery, and tool calls require a valid Entra bearer on every request. Missing or invalid credentials receive HTTP 401 with a `WWW-Authenticate` challenge. Tool-specific role and backend authorization checks still apply. A session ID is not a credential.

Public OAuth metadata is served at `/.well-known/oauth-protected-resource/certbot` (reverse-proxy alias) and `/certbot/.well-known/oauth-protected-resource`. Only OAuth connection metadata is public; tool descriptions and schemas require authentication. The root alias must proxy to the application path `/.well-known/oauth-protected-resource`.

The existing JSON/SSE response mode, stateful/stateless behavior, tool schemas, audiences, scopes, and caller restrictions are retained. Clients may send a configured bearer directly or use an authenticated bridge. They must forward the bearer on initialization, subsequent POST/GET requests, and session deletion. No browser redirect, new registration flow, or new protocol-version requirement is introduced. Stateful clients reconnect after a service restart.

Run `python -m unittest discover -s tests -p test_http_auth.py` to check authentication, metadata, JSON/SSE sessions, session-only rejection, and legacy SSE protection.
