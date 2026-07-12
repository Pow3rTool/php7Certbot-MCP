"""php7certbot-mcp — a read-first MCP tool surface over an enterprise certificate-management
API (a ~10yr-old PHP7/Laravel app; "CertBot" below refers to that app, not Let's Encrypt's
certbot client).

Design (mirrors cloudflare-dns-mcp; the back end is on-behalf-of, not app identity):
  - front door : validate the operator's Entra bearer (JWKS signature, audience, issuer,
                 required exp, tenant pin, required scope, allowed client) — same fail-closed
                 validation as cloudflare-dns-mcp. The audience is THIS mcp's own app
                 registration, which is also the OBO client below (one identity, not two).
  - back end   : ON-BEHALF-OF. Despite certbot's Laravel auth guard predating OBO as a
                 concept, it only checks token shape (RS256, known kid, aud == its own
                 client_id, oid/name/preferred_username claims) — it doesn't care whether the
                 token arrived via a direct login or an OBO exchange. So the MCP exchanges the
                 CALLER's own front-door-validated bearer (aud=this app, scp=access_as_user)
                 for a new token audienced to certbot's app (CERTBOT_RESOURCE, scope
                 access_as_user) via RFC 8693-style OBO
                 (grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer,
                 requested_token_use=on_behalf_of), authenticated with the same
                 client-credentials cert used before. certbot now sees the REAL calling user
                 and enforces its OWN per-account authorization on that real user — no more
                 flattening every caller to one shared app identity. Requires this app's
                 registration to hold a delegated permission grant (or pre-authorization) for
                 certbot's access_as_user scope — see Entra setup notes in .env.example.
  - read-first : list accounts / list+get certificates / expiry monitors. Issuance (sign) is
                 deliberately NOT here — certbot signing is a blocking multi-minute call
                 (DNS-01 + ACME verification); it needs an async job pattern (phase 2).
"""
import os, re, json, time, threading, base64, uuid, shlex
from urllib.parse import urlparse, urljoin
import httpx
import jwt
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings

os.umask(0o077)

# --- identity of THIS app (php7Certbot-MCP) — used for BOTH the front-door audience
#     and the back-end OBO client (client_assertion) to certbot ------------------
MCP_CLIENT    = os.environ.get("CERTBOT_MCP_CLIENT_ID", "").strip()   # php7Certbot-MCP app id
MCP_TENANT    = os.environ.get("CERTBOT_MCP_TENANT_ID", "").strip()
MCP_CERT_FILE = os.environ.get("CERTBOT_MCP_CERT_FILE", "").strip()   # PEM: private key + cert

# --- certbot back end ------------------------------------------------------------
CERTBOT_API   = os.environ.get("CERTBOT_API_BASE", "").rstrip("/")
CERTBOT_RES   = os.environ.get("CERTBOT_RESOURCE", "").strip()        # certbot App ID URI: api://<certbot-app-id>
TIMEOUT       = int(os.environ.get("CERTBOT_TIMEOUT", "45"))          # certbot reads can be slow
MAX_OUT       = int(os.environ.get("CERTBOT_MAX_OUTPUT_CHARS", "60000"))
AUDIT         = os.environ.get("CERTBOT_AUDIT_LOG", "/opt/php7certbot-mcp/logs/audit.log")

# --- front door (Entra bearer) — validation approach mirrors cloudflare-dns-mcp ---
# By design the front-door audience app and the back-end OBO client are the SAME app
# registration (a token audienced to THIS app is exactly what we OBO). So there is no
# separate front-door identity to configure — TENANT/CLIENT ARE the MCP identity. This
# removes the possibility of the two boundaries silently diverging.
PUBLIC_HOST     = os.environ.get("CERTBOT_PUBLIC_HOST", "localhost")
PORT            = int(os.environ.get("CERTBOT_PORT", "8785"))
TENANT          = MCP_TENANT
CLIENT          = MCP_CLIENT   # our app id == token audience
AUDIENCE        = [x for x in (CLIENT, f"api://{CLIENT}", os.environ.get("CERTBOT_AUDIENCE", "").strip()) if x]
REQUIRED_SCOPE  = os.environ.get("CERTBOT_REQUIRED_SCOPE", "").strip()
ALLOWED_CLIENTS = [x.strip() for x in os.environ.get("CERTBOT_ALLOWED_CLIENTS", "").split(",") if x.strip()]
# Optional per-user app-role gate on THIS mcp app. Empty => any validated caller may read
# (certbot still enforces its own per-account Bouncer authz on the app-user downstream).
READ_ROLES      = {r.strip().lower() for r in os.environ.get("CERTBOT_READ_ROLES", "").split(",") if r.strip()}

_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_lock = threading.Lock()


def _validate_config():
    """Fail-closed config gate — runs at IMPORT, so no launch path can serve with auth
    disabled or with unfilled sample placeholders still in place."""
    def _ph(v):
        v = str(v).strip()
        return (not v) or ("<" in v) or (">" in v) or ("REPLACE" in v.upper())
    if _ph(TENANT) or _ph(CLIENT):
        raise SystemExit("CERTBOT_MCP_TENANT_ID / CERTBOT_MCP_CLIENT_ID must be real (every bearer is validated).")
    if not (_GUID.match(TENANT) and _GUID.match(CLIENT)):
        raise SystemExit("tenant/client must be specific GUIDs — multi-tenant aliases refused.")
    if _ph(REQUIRED_SCOPE):
        raise SystemExit("CERTBOT_REQUIRED_SCOPE is required — pin the coarse 'valid caller' scope.")
    if not ALLOWED_CLIENTS or any(_ph(c) for c in ALLOWED_CLIENTS):
        raise SystemExit("CERTBOT_ALLOWED_CLIENTS is required — pin the calling client (turnstone).")
    if _ph(CERTBOT_RES):
        raise SystemExit("CERTBOT_RESOURCE is required — certbot's App ID URI (api://<id>).")
    if _ph(CERTBOT_API):
        raise SystemExit("CERTBOT_API_BASE is required — certbot's API base URL.")
    if urlparse(CERTBOT_API).scheme != "https":
        raise SystemExit("CERTBOT_API_BASE must be https:// — delegated bearer tokens and cert "
                         "bundles must never transit in cleartext.")
    if _ph(MCP_CERT_FILE) or not os.path.isfile(MCP_CERT_FILE):
        raise SystemExit("CERTBOT_MCP_CERT_FILE must point at the client-credentials PEM (key+cert).")
    try:
        os.makedirs(os.path.dirname(AUDIT) or ".", exist_ok=True)
        with open(AUDIT, "a"):
            pass
    except Exception as e:
        raise SystemExit(f"audit log not writable at {AUDIT}: {e}")


_validate_config()


# --- front-door bearer validation (same approach as cloudflare-dns-mcp) -----------
def _bearer(ctx):
    try:
        h = ctx.request_context.request.headers
        auth = h.get("authorization") or h.get("Authorization") or ""
    except Exception:
        return None
    m = re.match(r"bearer\s+(\S+)", auth, re.I)
    return m.group(1) if m else None


_jwks = None
def _jwks_client():
    global _jwks
    if _jwks is None:
        from jwt import PyJWKClient
        _jwks = PyJWKClient(f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys")
    return _jwks


def _identity(bearer):
    """(oid, who, roles) ONLY after the bearer is cryptographically verified for this
    tenant+app (JWKS signature, audience, issuer, expiry, required scope, allowed client)."""
    # Defense-in-depth: never authenticate anyone unless the gates are actually configured,
    # even if _validate_config were somehow bypassed.
    if not (TENANT and CLIENT and REQUIRED_SCOPE and ALLOWED_CLIENTS):
        return None
    if not bearer:
        return None
    try:
        key = _jwks_client().get_signing_key_from_jwt(bearer).key
        claims = jwt.decode(bearer, key, algorithms=["RS256"], audience=AUDIENCE,
                            issuer=f"https://login.microsoftonline.com/{TENANT}/v2.0",
                            options={"require": ["exp"], "verify_aud": True})
        if claims.get("tid") != TENANT:   # pin the exact tenant, not just an iss-shaped string
            return None
    except Exception:
        return None
    if REQUIRED_SCOPE and REQUIRED_SCOPE not in str(claims.get("scp", "")).split():
        return None
    if ALLOWED_CLIENTS and (claims.get("azp") or claims.get("appid")) not in ALLOWED_CLIENTS:
        return None
    oid = claims.get("oid") or claims.get("sub")
    who = claims.get("preferred_username") or claims.get("upn") or claims.get("name") or oid
    roles = [str(r).lower() for r in (claims.get("roles") or [])]
    return (oid, who, roles)


def _auth(ctx):
    return _identity(_bearer(ctx))


def _authz_read(roles):
    if not READ_ROLES:
        return True
    return bool(set(roles or []) & READ_ROLES)


def _err(msg):
    return json.dumps({"error": msg})


def _out(obj):
    s = json.dumps(obj, indent=2, sort_keys=False)
    if len(s) <= MAX_OUT:
        return s
    return s[:MAX_OUT] + f"\n…[TRUNCATED at {MAX_OUT} chars — narrow your query]"


def _audit(ident, tool, detail, ok):
    """Append-only JSONL accounting: immutable oid + human upn + verb + target + result.
    A dropped line ALWAYS goes to stderr/journald (audit is a control)."""
    rec = json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      "oid": ident[0], "who": ident[1], "tool": tool, "detail": detail, "ok": bool(ok)})
    try:
        with _lock, open(AUDIT, "a") as f:
            f.write(rec + "\n")
    except Exception as e:
        import sys
        print(f"AUDIT-WRITE-FAILED {type(e).__name__}: {rec}", file=sys.stderr, flush=True)


# --- back end: OBO token to certbot (client_assertion cert authenticates THIS app as the
#     middle tier; the `assertion` is the CALLER's own bearer, so certbot gets the real user) --
_obo_cache = {}  # oid -> {"v": token, "exp": epoch} — one cached downstream token per real user
_obo_lock = threading.Lock()
CERTBOT_ACCESS_SCOPE = f"{CERTBOT_RES}/access_as_user"


def _load_cert():
    pem = open(MCP_CERT_FILE, "rb").read()
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography import x509
    key = serialization.load_pem_private_key(pem, password=None)
    cert = x509.load_pem_x509_certificate(pem)
    x5t = base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA1())).decode().rstrip("=")
    return key, x5t


_KEY, _X5T = _load_cert()


def _certbot_obo_token(user_bearer, oid):
    """OBO-exchange the CALLER's own front-door-validated bearer (aud=this app) for a new
    token audienced to certbot (CERTBOT_ACCESS_SCOPE), so certbot authenticates the real
    user instead of this app. Cached per-oid until near expiry."""
    now = time.time()
    with _obo_lock:
        cached = _obo_cache.get(oid)
        if cached and now < cached["exp"] - 60:
            return cached["v"]
    token_ep = f"https://login.microsoftonline.com/{MCP_TENANT}/oauth2/v2.0/token"
    n = int(now)
    assertion = jwt.encode(
        {"aud": token_ep, "iss": MCP_CLIENT, "sub": MCP_CLIENT,
         "jti": str(uuid.uuid4()), "nbf": n, "exp": n + 300},
        _KEY, algorithm="RS256", headers={"x5t": _X5T})
    data = {"client_id": MCP_CLIENT,
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": user_bearer,
            "requested_token_use": "on_behalf_of",
            "scope": CERTBOT_ACCESS_SCOPE,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion}
    with httpx.Client(timeout=30) as c:
        r = c.post(token_ep, data=data)
    j = r.json()
    if "access_token" not in j:
        raise RuntimeError(f"certbot OBO token acquisition failed: {j.get('error', '?')}: "
                           f"{str(j.get('error_description', ''))[:300]}")
    with _obo_lock:
        # Opportunistically drop expired entries so the cache can't grow unbounded across users.
        for k in [k for k, v in _obo_cache.items() if v["exp"] <= now]:
            del _obo_cache[k]
        _obo_cache[oid] = {"v": j["access_token"], "exp": now + int(j.get("expires_in", 3600))}
    return j["access_token"]


def _certbot(method, path, user_bearer, oid):
    """One certbot API call ON BEHALF OF the calling user. Returns (ok: bool, payload)."""
    try:
        tok = _certbot_obo_token(user_bearer, oid)
    except Exception as e:
        return False, {"error": f"backend OBO auth failed: {e}"}
    try:
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.request(method, f"{CERTBOT_API}{path}",
                          headers={"Authorization": f"Bearer {tok}", "Accept": "application/json"})
        if r.status_code >= 400:
            # Don't relay certbot's raw error body to the caller/model — it's a decade-old
            # Laravel app and an error page can carry a stack trace / internal paths if debug
            # mode is ever on. Log the detail server-side; return just the status upstream.
            print(f"certbot {method} {path} -> {r.status_code}: {r.text[:500]}", flush=True)
            return False, {"status": r.status_code, "error": "certbot returned an error (see server log for detail)"}
        try:
            return True, r.json()
        except Exception:
            # A 2xx that isn't JSON from a JSON API is anomalous (e.g. a Laravel HTML page) —
            # don't relay the raw body to the model; log it server-side, return a marker.
            print(f"certbot {method} {path} -> {r.status_code} non-JSON body: {r.text[:500]}", flush=True)
            return False, {"status": r.status_code, "error": "certbot returned a non-JSON response (see server log)"}
    except Exception as e:
        return False, {"error": f"certbot request failed: {type(e).__name__}: {e}"}


# --- MCP server + tools ----------------------------------------------------------
mcp = FastMCP(
    "php7certbot",
    instructions=("Read certificate inventory + expiry from the enterprise CertBot, and get the "
                  "URL/command to deliver a cert straight onto the box that needs it. Tools: "
                  "list_accounts (ca|acme), list_certificates, get_certificate, get_pem_link, "
                  "list_expiring, list_expired. Read-only + link-builder; issuance is intentionally "
                  "not exposed here. get_pem_link returns no key bytes — the host pulls the PEM "
                  "directly from certbot (bytes never pass through the model). Calls run ON BEHALF "
                  "OF the calling user (OBO) and are bounded by what certbot's own per-account "
                  "authorization grants that real user."),
    host="127.0.0.1", port=PORT, stateless_http=True, json_response=True, streamable_http_path="/",
    transport_security=TransportSecuritySettings(
        allowed_hosts=[PUBLIC_HOST, f"{PUBLIC_HOST}:443", f"127.0.0.1:{PORT}", f"localhost:{PORT}"],
        allowed_origins=[f"https://{PUBLIC_HOST}", f"http://127.0.0.1:{PORT}"],
    ),
)

# Drop resource/prompt handlers we don't implement (keeps clients from probing them).
from mcp import types as _t
for _rt in (_t.ListResourcesRequest, _t.ReadResourceRequest, _t.ListResourceTemplatesRequest,
            _t.ListPromptsRequest, _t.GetPromptRequest, _t.SubscribeRequest, _t.UnsubscribeRequest):
    mcp._mcp_server.request_handlers.pop(_rt, None)

_KINDS = ("ca", "acme")


def _guard(ctx, tool, detail):
    ident = _auth(ctx)
    if ident is None:
        return None, _err("unauthenticated: bearer failed validation "
                          "(signature/audience/issuer/expiry/scope/client)")
    if not _authz_read(ident[2]):
        _audit(ident, tool, detail, False)
        return None, _err("not authorized: read requires one of the configured Certbot read roles")
    return ident, None


@mcp.tool()
def list_accounts(ctx: Context, kind: str) -> str:
    """List certificate accounts on CertBot. `kind` = 'ca' (enterprise issuing CAs) or 'acme'
    (public ACME / Let's Encrypt accounts). Returns each account the MCP is authorized to see,
    with the zones it may issue for. Take an account id from here into list_certificates."""
    if kind not in _KINDS:
        return _err("kind must be 'ca' or 'acme'")
    ident, e = _guard(ctx, "list_accounts", kind)
    if e:
        return e
    ok, data = _certbot("GET", f"/{kind}/accounts", _bearer(ctx), ident[0])
    _audit(ident, "list_accounts", kind, ok)
    return _out(data)


@mcp.tool()
def list_certificates(ctx: Context, kind: str, account_id: int) -> str:
    """List certificates in a CertBot account. `kind`='ca'|'acme', `account_id` from list_accounts.
    Returns id / subject / SANs / status / expiry per certificate."""
    if kind not in _KINDS:
        return _err("kind must be 'ca' or 'acme'")
    ident, e = _guard(ctx, "list_certificates", f"{kind}/{account_id}")
    if e:
        return e
    ok, data = _certbot("GET", f"/{kind}/accounts/{int(account_id)}/certificates", _bearer(ctx), ident[0])
    _audit(ident, "list_certificates", f"{kind}/{account_id}", ok)
    return _out(data)


@mcp.tool()
def get_certificate(ctx: Context, kind: str, account_id: int, certificate_id: int) -> str:
    """Get one certificate's detail (subject, SANs, issuer, validity window, status). Does NOT
    return private key material — use get_pem_link to obtain a download link for the bundle."""
    if kind not in _KINDS:
        return _err("kind must be 'ca' or 'acme'")
    ident, e = _guard(ctx, "get_certificate", f"{kind}/{account_id}/{certificate_id}")
    if e:
        return e
    ok, data = _certbot("GET", f"/{kind}/accounts/{int(account_id)}/certificates/{int(certificate_id)}",
                        _bearer(ctx), ident[0])
    _audit(ident, "get_certificate", f"{kind}/{account_id}/{certificate_id}", ok)
    return _out(data)


@mcp.tool()
def get_pem_link(ctx: Context, kind: str, account_id: int, certificate_id: int,
                 fmt: str = "pem") -> str:
    """Return a FULLY FUNCTIONAL, ready-to-curl download link for a certificate bundle, so the
    host that needs it can pull it DIRECTLY from certbot — including the very FIRST time on a
    brand-new box (no pre-existing key required). Hand `host_pull` to XConnect's remote_run.

    How it works: the MCP exchanges your own bearer for a token on-behalf-of you and requests
    the bundle (`fmt`='pem'|'pkcs12') with a STREAMING request — it reads only the response
    `Link: <…>; rel="alternate"` header (the UNAUTHENTICATED keyhash refresh URL, keyhash computed
    server-side from the key certbot holds) and closes the stream WITHOUT reading the body, so the
    cert+key bytes are never materialized in this process or returned to the model. The MCP relays
    ONLY that URL; the bytes travel certbot->host when the host curls the URL.

    The returned URL embeds the key's keyhash, so it is a single-cert retrieval capability — treat
    it as sensitive (don't persist in shared logs). `kind`='ca'|'acme'; ids from list_certificates."""
    if kind not in _KINDS:
        return _err("kind must be 'ca' or 'acme'")
    if fmt not in ("pem", "pkcs12"):
        return _err("fmt must be 'pem' or 'pkcs12'")
    ident, e = _guard(ctx, "get_pem_link", f"{kind}/{account_id}/{certificate_id}/{fmt}")
    if e:
        return e
    aid, cid = int(account_id), int(certificate_id)
    path = f"/{kind}/accounts/{aid}/certificates/{cid}/{fmt}"
    try:
        tok = _certbot_obo_token(_bearer(ctx), ident[0])
    except Exception as ex:
        _audit(ident, "get_pem_link", f"{kind}/{account_id}/{certificate_id}", False)
        return _err(f"backend OBO auth failed: {ex}")
    # Fetch the bundle ONLY to read the alternate-link header. STREAM the response so the body
    # (incl. the private key) is never pulled into this process — we read headers, then close.
    try:
        with httpx.Client(timeout=TIMEOUT) as c:
            with c.stream("GET", f"{CERTBOT_API}{path}",
                          headers={"Authorization": f"Bearer {tok}", "Accept": "*/*"}) as r:
                status = r.status_code
                link = r.headers.get("link", "")
                # NB: we deliberately never call r.read()/iterate — the body is not materialized.
    except Exception as ex:
        _audit(ident, "get_pem_link", f"{kind}/{account_id}/{certificate_id}", False)
        return _err(f"certbot request failed: {type(ex).__name__}: {ex}")
    if status >= 400:
        _audit(ident, "get_pem_link", f"{kind}/{account_id}/{certificate_id}", False)
        # This endpoint's success path carries key material, so its error path is redacted too —
        # no raw body back to the caller/model (and we didn't read it anyway).
        print(f"certbot GET {path} -> {status} (body not read)", flush=True)
        return _out({"status": status, "error": "certbot returned an error (see server log for detail)"})
    # Require the explicit rel="alternate" relation — do NOT fall back to an arbitrary first link
    # (a garbled/hostile header must not silently yield the wrong URL).
    m = re.search(r'<([^>]+)>\s*;\s*rel="alternate"', link)
    download_url = m.group(1) if m else None
    _audit(ident, "get_pem_link", f"{kind}/{account_id}/{certificate_id}/{fmt}", bool(download_url))
    if not download_url:
        return _out({"error": "certbot returned no rel=\"alternate\" keyhash link header for this cert"})
    # The URL is emitted into a shell command run on a remote host — do not trust certbot's header
    # blindly. Resolve it against CERTBOT_API (so a relative Link path lands on the known-good
    # origin) then require https + the SAME origin (kills SSRF-to-arbitrary-host and header-injected
    # schemes on an absolute link) before we ever hand it downstream.
    download_url = urljoin(CERTBOT_API + "/", download_url)
    u = urlparse(download_url)
    if u.scheme != "https" or u.netloc != urlparse(CERTBOT_API).netloc:
        print(f"certbot returned an off-origin/insecure alternate link: {download_url[:200]}", flush=True)
        return _out({"error": "certbot returned a download URL that is not https on the expected "
                              "certbot host — refusing to relay it."})
    ext = "pem" if fmt == "pem" else "p12"
    out = {
        "kind": kind, "account_id": aid, "certificate_id": cid, "format": fmt,
        "download_url": download_url,
        # shlex.quote the URL: it's interpolated into a shell command for remote execution, so any
        # shell metacharacters in the (downstream-controlled) URL must be neutralized. DEST is our
        # own static, shell-safe placeholder the operator replaces with a real path.
        "host_pull": f'curl -fsS -o DEST.{ext} {shlex.quote(download_url)}',
        "notes": [
            "Replace DEST.{ext} in host_pull with the real destination path before running.".format(ext=ext),
            "download_url is unauthenticated (keyhash-based) and returns the FULL bundle incl. private key.",
            "Works on a brand-new box — no pre-existing key needed (certbot computed the keyhash).",
            "Bytes go certbot->host directly; only this URL passes through the model.",
            "The URL is a single-cert retrieval capability — treat as sensitive; don't persist in shared logs.",
            "After the pull: install cert+key, reload the consuming service, verify (openssl x509 -noout -dates).",
        ],
    }
    return _out(out)


@mcp.tool()
def list_expiring(ctx: Context) -> str:
    """Certificates expiring within the next month across all accounts — the fleet-wide expiry
    watch. Returns subject/SANs/expiry per cert; feed these into alerting."""
    ident, e = _guard(ctx, "list_expiring", "-")
    if e:
        return e
    ok, data = _certbot("GET", "/monitor/expiring", _bearer(ctx), ident[0])
    _audit(ident, "list_expiring", "-", ok)
    return _out(data)


@mcp.tool()
def list_expired(ctx: Context) -> str:
    """Certificates that have already expired (and were seen recently). Returns subject/SANs/expiry."""
    ident, e = _guard(ctx, "list_expired", "-")
    if e:
        return e
    ok, data = _certbot("GET", "/monitor/expired", _bearer(ctx), ident[0])
    _audit(ident, "list_expired", "-", ok)
    return _out(data)


if __name__ == "__main__":
    # Config was validated at import (_validate_config) — fail-closed on every path.
    mcp.run(transport="streamable-http")
