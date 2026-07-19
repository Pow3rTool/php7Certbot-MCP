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
  - read-first : list accounts / list+get certificates / expiry monitors are always on.
  - issuance   : create + re-sign are OFF unless CERTBOT_ENABLE_ISSUANCE. certbot's sign() is a
                 single blocking call (ACME = minutes of DNS-01), so we run it in a background
                 thread, block briefly for the fast/CA case, and hand the caller check_issuance to
                 poll — which reconciles against certbot's OWN cert record (status/expires), so no
                 in-memory job store is the source of truth and a restart can't blind us. Only
                 SERVER certs are issued (the CA path's type field is forced to 'server', never
                 ca/user). A disk journal records intent + result for the operator.
"""
import os, re, json, time, threading, base64, uuid
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

# --- issuance (create/re-sign) — OFF unless explicitly enabled -------------------
# Read-only by default: request_certificate / update_certificate_hostnames refuse unless set.
ENABLE_ISSUANCE = os.environ.get("CERTBOT_ENABLE_ISSUANCE", "").lower() in ("1", "true", "yes")
# certbot's sign() is a single blocking call; for ACME it runs the DNS-01 dance (minutes).
# This is the httpx timeout for that one call (the sign runs in a background thread).
SIGN_TIMEOUT    = int(os.environ.get("CERTBOT_SIGN_TIMEOUT", "600"))
# How long a request/update tool blocks waiting for the sign before returning "issuing" and
# letting the caller poll. MUST stay under the MCP client's per-call timeout (Turnstone: 120s).
SIGN_INLINE_WAIT = int(os.environ.get("CERTBOT_SIGN_INLINE_WAIT", "90"))
# Durable operator journal of every issuance attempt (intent + result). Separate from the audit
# log so the cert-lifecycle trail is easy to eyeball.
ISSUANCE_JOURNAL = os.environ.get("CERTBOT_ISSUANCE_JOURNAL", "/opt/php7certbot-mcp/logs/issuance.jsonl")

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
    # Only enforce the issuance journal when issuance is actually enabled (accounting is a
    # control for mutations): prove it's writable at startup, not mid-issue.
    if ENABLE_ISSUANCE:
        try:
            os.makedirs(os.path.dirname(ISSUANCE_JOURNAL) or ".", exist_ok=True)
            with open(ISSUANCE_JOURNAL, "a"):
                pass
        except Exception as e:
            raise SystemExit(f"issuance journal not writable at {ISSUANCE_JOURNAL}: {e}")


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


def _certbot(method, path, user_bearer, oid, body=None, timeout=None):
    """One certbot API call ON BEHALF OF the calling user. Returns (ok: bool, payload).
    `body` (dict) is sent as JSON for POST/PUT; `timeout` overrides the default read timeout
    (the sign call needs minutes)."""
    try:
        tok = _certbot_obo_token(user_bearer, oid)
    except Exception as e:
        return False, {"error": f"backend OBO auth failed: {e}"}
    try:
        with httpx.Client(timeout=(timeout or TIMEOUT)) as c:
            r = c.request(method, f"{CERTBOT_API}{path}",
                          headers={"Authorization": f"Bearer {tok}", "Accept": "application/json"},
                          json=body)
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
    instructions=("Read and manage certificates on the enterprise CertBot. Everywhere a trust axis "
                  "is needed, `trust`='public' (ACME / Let's Encrypt, publicly trusted) or 'private' "
                  "(internal enterprise CA, privately trusted). Read tools: list_accounts, "
                  "search_certificates (find a cert by hostname across accounts — use this in a large "
                  "estate), list_certificates (one account), get_certificate, get_pem_link (returns a "
                  "download URL; bytes go certbot->host, never through the model), list_expiring, "
                  "list_expired. Issuance tools (only when enabled): request_server_certificate (new "
                  "server cert — only ever a server cert, never a CA/client cert), "
                  "update_certificate_hostnames (replace the SAN set on an existing server cert, "
                  "keeping its key), check_issuance (poll a sign that returned 'issuing' — public/ACME "
                  "signs take minutes). When multiple certs could match (overlapping SANs) or multiple "
                  "accounts look alike, present the numbered options and ask the user to pick — don't "
                  "guess. All calls run ON BEHALF OF the signed-in user (OBO); certbot enforces its own "
                  "per-account authorization on that real user."),
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

# Public-facing axis: 'public' = ACME / Let's Encrypt (publicly trusted); 'private' = internal
# enterprise CA (privately trusted). This is the ONLY selector the model sees — there is no 'ca'
# token anywhere on the surface, so it can't be misread as "a CA-type certificate".
_TRUST_TO_KIND = {"public": "acme", "private": "ca"}


def _trust_to_kind(trust):
    """Map the public/private trust axis to certbot's ca/acme path segment. Returns (kind, err)."""
    k = _TRUST_TO_KIND.get((trust or "").strip().lower())
    if not k:
        return None, _err("trust must be 'public' (ACME / Let's Encrypt, publicly trusted) or "
                          "'private' (internal enterprise CA, privately trusted)")
    return k, None


def _accounts(kind, bearer, oid):
    """List accounts in one pool -> (ok, [account dicts])."""
    ok, data = _certbot("GET", f"/{kind}/accounts", bearer, oid)
    if not ok:
        return False, data
    return True, (data.get("accounts") or []) if isinstance(data, dict) else []


def _certs(kind, aid, bearer, oid):
    """List certs in one account -> (ok, [cert dicts])."""
    ok, data = _certbot("GET", f"/{kind}/accounts/{int(aid)}/certificates", bearer, oid)
    if not ok:
        return False, data
    return True, (data.get("certificates") or []) if isinstance(data, dict) else []


def _cert_view(trust, kind, aid, aname, c):
    """The disambiguation-ready view of a cert. Includes `type` for the private pool (where CA /
    user / server certs coexist) so nobody re-signs a root by accident; ACME certs have no type."""
    v = {"trust": trust, "account_id": int(aid), "account_name": aname,
         "certificate_id": c.get("id"), "name": c.get("name"), "status": c.get("status"),
         "expires": c.get("expires"), "subjects": c.get("subjects")}
    if kind == "ca":
        v["type"] = c.get("type")
    return v


# We enumerate every cert server-side (the full list is small enough not to paginate), filter
# here, and only ever hand the model the MATCHES — capped so a broad query can't flood context.
MATCH_CAP = int(os.environ.get("CERTBOT_MATCH_CAP", "100"))


def _cert_match(c, q):
    """True if the query substring hits the cert's name, any SAN, or its id. Empty q matches all."""
    if not q:
        return True
    if q in str(c.get("name", "")).lower():
        return True
    if any(q in str(s).lower() for s in (c.get("subjects") or [])):
        return True
    return q == str(c.get("id", "")).lower()


def _bounded(narrow_by, trust, total, views, extra=None):
    """Shape a bounded match list. If more than MATCH_CAP matched, say so and tell the model to
    narrow (rather than silently returning a partial set)."""
    shown = views[:MATCH_CAP]
    out = {"trust": trust, "match_count": total, "shown": len(shown), **(extra or {}),
           "certificates": shown}
    if total > MATCH_CAP:
        out["truncated"] = True
        out["note"] = (f"{total} matches; showing first {MATCH_CAP}. Narrow by {narrow_by} — do not "
                       "assume the target is in the shown subset.")
    return _out(out)


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
def list_accounts(ctx: Context, trust: str = "") -> str:
    """List the certificate-issuing accounts. `trust` optional: 'public' (ACME / Let's Encrypt,
    publicly trusted), 'private' (internal enterprise CA, privately trusted), or omit to list BOTH.
    Returns each account's numeric account_id, name, trust, and permitted zones — this is the menu
    you pick an account_id from. If two accounts look alike (e.g. multiple production CAs), show the
    user the options and let them choose the account_id; don't guess."""
    t = (trust or "").strip().lower()
    if t and t not in _TRUST_TO_KIND:
        return _err("trust must be 'public', 'private', or omitted (for both)")
    ident, e = _guard(ctx, "list_accounts", t or "both")
    if e:
        return e
    pools = [t] if t else ["public", "private"]
    out = []
    for tr in pools:
        kind = _TRUST_TO_KIND[tr]
        ok, accts = _accounts(kind, _bearer(ctx), ident[0])
        if not ok:
            return _out(accts)
        for a in accts:
            out.append({"account_id": a.get("id"), "name": a.get("name"), "trust": tr,
                        "zones": a.get("zones")})
    _audit(ident, "list_accounts", t or "both", True)
    return _out({"count": len(out), "accounts": out})


@mcp.tool()
def list_certificates(ctx: Context, trust: str, account_id: int, query: str = "") -> str:
    """List certificates in ONE account. `trust`='public'|'private', `account_id` from list_accounts.
    Optional `query` = case-insensitive substring filter over cert name / SANs / id. Returns
    id / name / SANs / status / expiry (plus `type` for private-CA accounts). For finding a cert
    across ALL accounts (e.g. by hostname), use search_certificates instead."""
    kind, e = _trust_to_kind(trust)
    if e:
        return e
    ident, e = _guard(ctx, "list_certificates", f"{trust}/{account_id}")
    if e:
        return e
    aid = int(account_id)
    ok, accts = _accounts(kind, _bearer(ctx), ident[0])
    if not ok:
        return _out(accts)
    aname = next((a.get("name") for a in accts if a.get("id") == aid), None)
    ok, certs = _certs(kind, aid, _bearer(ctx), ident[0])
    if not ok:
        _audit(ident, "list_certificates", f"{trust}/{account_id}", False)
        return _out(certs)
    q = (query or "").strip().lower()
    views = [_cert_view(trust, kind, aid, aname, c) for c in certs if _cert_match(c, q)]
    _audit(ident, "list_certificates", f"{trust}/{account_id} q={q!r} n={len(views)}", True)
    return _bounded("account_id / query", trust, len(views), views, extra={"account_id": aid, "query": query})


@mcp.tool()
def search_certificates(ctx: Context, trust: str, query: str, account_id: int = 0) -> str:
    """Find certificates by hostname/name across accounts — the tool for a large, messy estate.
    `trust`='public'|'private'. `query` = case-insensitive substring matched against each cert's
    name, EVERY SAN, and its id. `account_id` optional: 0/omitted searches EVERY account in that
    trust pool (use this when you don't know which account a hostname lives under); or pass one to
    scope the search. Returns matching certs with full context (account_id, certificate_id, status,
    expiry, complete SAN list, and `type` for private-CA certs) so you can disambiguate.

    IMPORTANT: when more than one certificate matches — common with overlapping SANs — DO NOT guess
    which one to act on. Present the numbered candidates to the user and ask them to pick the
    certificate_id. Results are capped; if truncated, narrow the query or pass an account_id."""
    kind, e = _trust_to_kind(trust)
    if e:
        return e
    q = (query or "").strip().lower()
    if not q:
        return _err("query is required (a hostname or name substring to search for)")
    ident, e = _guard(ctx, "search_certificates", f"{trust} q={q!r}")
    if e:
        return e
    bearer = _bearer(ctx)
    ok, accts = _accounts(kind, bearer, ident[0])
    if not ok:
        return _out(accts)
    if int(account_id) > 0:
        accts = [a for a in accts if a.get("id") == int(account_id)]
        if not accts:
            return _err(f"no {trust} account with id {account_id} (see list_accounts)")
    matches = []
    for a in accts:
        aid, aname = a.get("id"), a.get("name")
        cok, certs = _certs(kind, aid, bearer, ident[0])
        if not cok:
            continue  # skip an unreadable account rather than fail the whole search
        for c in certs:
            if _cert_match(c, q):
                matches.append(_cert_view(trust, kind, aid, aname, c))
    _audit(ident, "search_certificates", f"{trust} q={q!r} scanned={len(accts)} hits={len(matches)}", True)
    return _bounded("query / account_id", trust, len(matches), matches,
                    extra={"query": query, "scanned_accounts": len(accts)})


@mcp.tool()
def get_certificate(ctx: Context, trust: str, account_id: int, certificate_id: int) -> str:
    """Get one certificate's detail (subject, SANs, issuer, validity window, status). `trust`=
    'public'|'private'. Does NOT return private key material — use get_pem_link for a download link."""
    kind, e = _trust_to_kind(trust)
    if e:
        return e
    ident, e = _guard(ctx, "get_certificate", f"{trust}/{account_id}/{certificate_id}")
    if e:
        return e
    ok, data = _certbot("GET", f"/{kind}/accounts/{int(account_id)}/certificates/{int(certificate_id)}",
                        _bearer(ctx), ident[0])
    _audit(ident, "get_certificate", f"{trust}/{account_id}/{certificate_id}", ok)
    return _out(data)


@mcp.tool()
def get_pem_link(ctx: Context, trust: str, account_id: int, certificate_id: int,
                 fmt: str = "pem") -> str:
    """Return a FULLY FUNCTIONAL download URL for a certificate bundle, so the host that needs it
    can pull it DIRECTLY from certbot — including the very FIRST time on a brand-new box (no
    pre-existing key required). Run the pull on the target host (e.g. via XConnect's remote_run):
    curl -fsS -o <dest-path> <download_url>.

    How it works: the MCP exchanges your own bearer for a token on-behalf-of you and requests
    the bundle (`fmt`='pem'|'pkcs12') with a STREAMING request — it reads only the response
    `Link: <…>; rel="alternate"` header (the UNAUTHENTICATED keyhash refresh URL, keyhash computed
    server-side from the key certbot holds) and closes the stream WITHOUT reading the body, so the
    cert+key bytes are never materialized in this process or returned to the model. The MCP relays
    ONLY that URL; the bytes travel certbot->host when the host curls the URL.

    The returned URL embeds the key's keyhash, so it is a single-cert retrieval capability — treat
    it as sensitive (don't persist in shared logs). `trust`='public'|'private'; ids from search_certificates."""
    kind, e = _trust_to_kind(trust)
    if e:
        return e
    if fmt not in ("pem", "pkcs12"):
        return _err("fmt must be 'pem' or 'pkcs12'")
    ident, e = _guard(ctx, "get_pem_link", f"{trust}/{account_id}/{certificate_id}/{fmt}")
    if e:
        return e
    aid, cid = int(account_id), int(certificate_id)
    path = f"/{kind}/accounts/{aid}/certificates/{cid}/{fmt}"
    try:
        tok = _certbot_obo_token(_bearer(ctx), ident[0])
    except Exception as ex:
        _audit(ident, "get_pem_link", f"{trust}/{account_id}/{certificate_id}", False)
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
        _audit(ident, "get_pem_link", f"{trust}/{account_id}/{certificate_id}", False)
        return _err(f"certbot request failed: {type(ex).__name__}: {ex}")
    if status >= 400:
        _audit(ident, "get_pem_link", f"{trust}/{account_id}/{certificate_id}", False)
        # This endpoint's success path carries key material, so its error path is redacted too —
        # no raw body back to the caller/model (and we didn't read it anyway).
        print(f"certbot GET {path} -> {status} (body not read)", flush=True)
        return _out({"status": status, "error": "certbot returned an error (see server log for detail)"})
    # Require the explicit rel="alternate" relation — do NOT fall back to an arbitrary first link
    # (a garbled/hostile header must not silently yield the wrong URL).
    m = re.search(r'<([^>]+)>\s*;\s*rel="alternate"', link)
    download_url = m.group(1) if m else None
    _audit(ident, "get_pem_link", f"{trust}/{account_id}/{certificate_id}/{fmt}", bool(download_url))
    if not download_url:
        return _out({"error": "certbot returned no rel=\"alternate\" keyhash link header for this cert"})
    # Don't trust certbot's header blindly — this URL becomes an argument to a command the agent
    # runs on a remote host. Resolve it against CERTBOT_API (so a relative Link path lands on the
    # known-good origin), require https + the SAME origin (kills SSRF-to-arbitrary-host), and reject
    # any shell-dangerous character. A keyhash refresh URL is only host+path+'?keyhash=<hex>', so
    # this never fires on real input — but it makes the URL provably safe to hand out bare, without
    # relying on how the agent later quotes it.
    download_url = urljoin(CERTBOT_API + "/", download_url)
    u = urlparse(download_url)
    if u.scheme != "https" or u.netloc != urlparse(CERTBOT_API).netloc:
        print(f"certbot returned an off-origin/insecure alternate link: {download_url[:200]}", flush=True)
        return _out({"error": "certbot returned a download URL that is not https on the expected "
                              "certbot host — refusing to relay it."})
    if re.search(r"""[`$;&|<>()'"\\\s]""", download_url):
        print(f"certbot returned a download URL with unsafe characters: {download_url[:200]}", flush=True)
        return _out({"error": "certbot returned a download URL containing unexpected characters — "
                              "refusing to relay it."})
    out = {
        "trust": trust, "account_id": aid, "certificate_id": cid, "format": fmt,
        "download_url": download_url,
        "notes": [
            "download_url is unauthenticated (keyhash-based) and returns the FULL bundle incl. private key.",
            "Works on a brand-new box — no pre-existing key needed (certbot computed the keyhash).",
            "Pull it on the target host, e.g.: curl -fsS -o <dest-path> <download_url>",
            "The URL is a single-cert retrieval capability — treat as sensitive; don't persist in shared logs.",
            "After the pull: install cert+key, reload the consuming service, verify (openssl x509 -noout -dates).",
        ],
    }
    return _out(out)


# ---------------------------------------------------------------------------------
# Issuance (create + re-sign). OFF unless CERTBOT_ENABLE_ISSUANCE. certbot's sign() is a
# single blocking call (ACME = minutes of DNS-01), so we run it in a background thread,
# block briefly for the fast/CA case, then hand the caller a poll (check_issuance) that
# reconciles against certbot's own cert record — no in-memory job store is the source of
# truth. A disk journal records intent + result for the operator.
# ---------------------------------------------------------------------------------
_signs = {}          # (kind, aid, cid) -> {"thread","started","who","op","prev_expires","done","ok","detail"}
_signs_lock = threading.Lock()
# certbot's create-path zone check (AcmeController) is NOT mirrored by its update path — so we
# enforce the same rule HERE for BOTH create and update, closing that backend gap.
_DNS_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _journal(rec):
    """Append-only issuance journal (JSONL). A failed write goes to stderr — accounting is a control."""
    line = json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **rec})
    try:
        with _lock, open(ISSUANCE_JOURNAL, "a") as f:
            f.write(line + "\n")
    except Exception as e:
        import sys
        print(f"ISSUANCE-JOURNAL-WRITE-FAILED {type(e).__name__}: {line}", file=sys.stderr, flush=True)


def _parse_subjects(subjects):
    """Accept a list or a whitespace/comma-delimited string (mirrors certbot's own parsing)."""
    if isinstance(subjects, str):
        subjects = re.split(r"[\s,]+", subjects)
    return [s.strip().lower() for s in (subjects or []) if s and s.strip()]


def _validate_subjects(subjects, zones):
    """Mirror certbot's createCertificate validation (which its update path skips): every SAN must
    be a valid lowercase DNS name, no wildcards, and fall within one of the account's permitted
    zones. Returns (ok, error). `zones` is the account's whitespace-list of registrable domains."""
    if not subjects:
        return False, "no subjects provided"
    zoneset = {z.strip().lower() for z in re.split(r"[\s,]+", zones or "") if z.strip()}
    if not zoneset:
        return False, "this account has no permitted zones configured — cannot validate subjects"
    for s in subjects:
        if s != s.lower() or " " in s or "," in s:
            return False, f"subject {s!r} must be a lowercase DNS name with no spaces/commas"
        if s.startswith("*"):
            return False, f"subject {s!r} is a wildcard — not allowed"
        if not all(_DNS_LABEL.match(lbl) for lbl in s.split(".")):
            return False, f"subject {s!r} is not a valid DNS name"
        # containment: subject must equal, or be under, a permitted zone (== certbot's TLD rule
        # when zones are registrable domains, and stricter for anything crafted to look otherwise).
        if not any(s == z or s.endswith("." + z) for z in zoneset):
            return False, (f"subject {s!r} is not within this account's permitted zones "
                           f"({sorted(zoneset)}) — refusing (mirrors certbot's create-path check).")
    return True, None


def _get_cert(kind, aid, cid, bearer, oid):
    """Fetch one cert record; return (ok, dict)."""
    return _certbot("GET", f"/{kind}/accounts/{int(aid)}/certificates/{int(cid)}", bearer, oid)


def _cert_snapshot(cert):
    """The fields we reconcile a sign against."""
    c = cert.get("certificate", cert) if isinstance(cert, dict) else {}
    return {"status": c.get("status"), "expires": c.get("expires"), "subjects": c.get("subjects")}


def _sign_worker(key, bearer, oid, ident, op):
    """Background: run the (blocking, possibly minutes-long) sign, then reconcile + journal."""
    kind, aid, cid = key
    ok, data = _certbot("POST", f"/{kind}/accounts/{aid}/certificates/{cid}/sign", bearer, oid,
                        timeout=SIGN_TIMEOUT)
    after_ok, after = _get_cert(kind, aid, cid, bearer, oid)
    snap = _cert_snapshot(after) if after_ok else {}
    detail = {"kind": kind, "account_id": aid, "certificate_id": cid, "op": op,
              "sign_ok": bool(ok), "result_status": snap.get("status"), "result_expires": snap.get("expires")}
    if not ok:
        detail["error"] = data.get("error") or data.get("status")
    _journal({"phase": "result", "oid": ident[0], "who": ident[1], **detail})
    with _signs_lock:
        ent = _signs.get(key)
        if ent is not None:
            ent.update(done=True, ok=bool(ok), detail=snap.get("status"))


def _kick_sign(key, bearer, oid, ident, op, prev_expires):
    """Start the sign in the background, block up to SIGN_INLINE_WAIT for the fast/CA case."""
    with _signs_lock:
        t = threading.Thread(target=_sign_worker, args=(key, bearer, oid, ident, op), daemon=True)
        _signs[key] = {"thread": t, "started": time.time(), "who": ident[1], "op": op,
                       "prev_expires": prev_expires, "done": False, "ok": None, "detail": None}
        t.start()
    t.join(timeout=SIGN_INLINE_WAIT)
    with _signs_lock:
        ent = _signs.get(key, {})
        return ent.get("done", False), ent.get("ok"), ent.get("detail")


def _issue_guard(ctx, tool, detail):
    """Auth + issuance-enabled gate. certbot enforces the actual 'sign' authorization per-user."""
    if not ENABLE_ISSUANCE:
        return None, _err("issuance is disabled on this server (set CERTBOT_ENABLE_ISSUANCE=true "
                          "to allow create/re-sign). This deployment is read-only.")
    return _guard(ctx, tool, detail)


@mcp.tool()
def request_server_certificate(ctx: Context, trust: str, account_id: int, name: str, subjects: str) -> str:
    """Create a NEW TLS SERVER certificate and sign it. This tool ONLY ever issues a standard server
    certificate — it cannot create a CA/intermediate or a client/user certificate, regardless of
    account. `trust`='private' (internal enterprise CA, near-instant) or 'public' (ACME / Let's
    Encrypt — runs DNS-01, can take minutes). `account_id` from list_accounts. `name` = a unique
    label for the cert in that account. `subjects` = the DNS name(s), a list or space/comma string;
    the FIRST is the common name. All subjects must fall within the account's permitted zones or the
    request is refused.

    Returns the signed cert inline if it completes quickly (always for a private/CA sign); otherwise
    returns status 'issuing' with a certificate_id — call check_issuance to poll for completion."""
    kind, e = _trust_to_kind(trust)
    if e:
        return e
    ident, e = _issue_guard(ctx, "request_server_certificate", f"{trust}/{account_id}")
    if e:
        return e
    bearer = _bearer(ctx)
    subs = _parse_subjects(subjects)
    if not name.strip():
        return _err("name is required (a unique label for the cert within the account)")
    # Fetch the account to get its permitted zones, then validate subjects (mirrors + extends
    # certbot's create-path check; also the gate certbot's update path lacks).
    aok, acct = _certbot("GET", f"/{kind}/accounts/{int(account_id)}", bearer, ident[0])
    if not aok:
        _audit(ident, "request_server_certificate", f"{trust}/{account_id}", False)
        return _out(acct)
    zones = (acct.get("account", acct) if isinstance(acct, dict) else {}).get("zones", "")
    vok, verr = _validate_subjects(subs, zones)
    if not vok:
        _audit(ident, "request_server_certificate", {"trust": trust, "account_id": account_id, "denied": verr}, False)
        return _err(verr)
    # Create the record. For a private/CA account we FORCE type=server so the CA can never be steered
    # into minting a CA/intermediate or a client/user cert (certbot's CA path branches on this field).
    # ACME is inherently server-only.
    body = {"name": name.strip(), "subjects": subs}
    if kind == "ca":
        body["type"] = "server"
    _journal({"phase": "intent", "op": "create", "oid": ident[0], "who": ident[1],
              "trust": trust, "account_id": int(account_id), "name": name.strip(), "subjects": subs})
    cok, cdata = _certbot("POST", f"/{kind}/accounts/{int(account_id)}/certificates", bearer, ident[0], body=body)
    if not cok:
        _audit(ident, "request_server_certificate", f"{trust}/{account_id}", False)
        return _out(cdata)
    cid = ((cdata.get("certificate") or {}) if isinstance(cdata, dict) else {}).get("id")
    if not cid:
        return _err("certbot created the record but returned no certificate id — check the journal")
    # Prep: generate keys, then CSR. Both fast; a failure here returns immediately.
    for step in ("generatekeys", "generaterequest"):
        sok, sdata = _certbot("POST", f"/{kind}/accounts/{int(account_id)}/certificates/{cid}/{step}",
                              bearer, ident[0])
        if not sok:
            _audit(ident, "request_server_certificate", f"{trust}/{account_id}/{cid}:{step}", False)
            return _out(sdata)
    # Sign (slow for ACME) in the background; block briefly for the fast/CA path.
    done, ok, status = _kick_sign((kind, int(account_id), int(cid)), bearer, ident[0], ident, "create", None)
    _audit(ident, "request_server_certificate", f"{trust}/{account_id}/{cid}", True)
    return _out(_issue_result(trust, int(account_id), int(cid), name.strip(), subs, done, ok, status))


@mcp.tool()
def update_certificate_hostnames(ctx: Context, trust: str, account_id: int, certificate_id: int,
                                 subjects: str) -> str:
    """Replace the hostname (SAN) set on an EXISTING server certificate and re-sign it, KEEPING the
    current private key. `subjects` = the COMPLETE new DNS name list (this REPLACES the existing set
    — pass every name you want on the cert, not just additions; the first is the common name).
    `trust`='public'|'private', `account_id`/`certificate_id` identify the cert (use
    search_certificates to find it — if multiple certs share a hostname, ask the user which
    certificate_id to modify; never guess).

    Only operates on SERVER certs (refuses CA/user certs). All new subjects must fall within the
    account's permitted zones. NOTE: re-signing puts the cert into 'unsigned' state until it
    completes, during which the old bundle is not downloadable; if the sign fails the cert is left
    unsigned. The key is preserved, so existing automation that pulls this cert keeps working.

    Returns the re-signed cert inline if quick (private/CA); otherwise status 'issuing' — poll check_issuance."""
    kind, e = _trust_to_kind(trust)
    if e:
        return e
    ident, e = _issue_guard(ctx, "update_certificate_hostnames", f"{trust}/{account_id}/{certificate_id}")
    if e:
        return e
    bearer = _bearer(ctx)
    subs = _parse_subjects(subjects)
    aid, cid = int(account_id), int(certificate_id)
    # Snapshot the existing cert: confirm it's a server cert (never re-sign a CA/user cert) and
    # capture prior state for the poll reconcile.
    gok, cur = _get_cert(kind, aid, cid, bearer, ident[0])
    if not gok:
        _audit(ident, "update_certificate_hostnames", f"{trust}/{aid}/{cid}", False)
        return _out(cur)
    curc = (cur.get("certificate", cur) if isinstance(cur, dict) else {})
    if kind == "ca" and str(curc.get("type", "")).strip().lower() not in ("server", "serverexception"):
        return _err(f"refusing to modify certificate id {cid} — its type is {curc.get('type')!r}, not a "
                    "server cert. This tool only re-signs server certs; a blank/unknown type is "
                    "refused too (a CA-pool server cert always carries type='server').")
    prev_expires = curc.get("expires")
    # Validate the NEW subjects against the account's zones — THIS is the check certbot's update
    # path omits, so we must do it or a swap could cross the account's zone boundary.
    aok, acct = _certbot("GET", f"/{kind}/accounts/{aid}", bearer, ident[0])
    if not aok:
        return _out(acct)
    zones = (acct.get("account", acct) if isinstance(acct, dict) else {}).get("zones", "")
    vok, verr = _validate_subjects(subs, zones)
    if not vok:
        _audit(ident, "update_certificate_hostnames", {"trust": trust, "cid": cid, "denied": verr}, False)
        return _err(verr)
    _journal({"phase": "intent", "op": "update", "oid": ident[0], "who": ident[1],
              "trust": trust, "account_id": aid, "certificate_id": cid,
              "prev_subjects": curc.get("subjects"), "prev_expires": prev_expires, "new_subjects": subs})
    # Replace SANs, regenerate the CSR (reuses the existing key), then sign. NB: generaterequest
    # flips status to 'unsigned' here.
    uok, udata = _certbot("PUT", f"/{kind}/accounts/{aid}/certificates/{cid}", bearer, ident[0],
                          body={"subjects": subs})
    if not uok:
        _audit(ident, "update_certificate_hostnames", f"{trust}/{aid}/{cid}", False)
        return _out(udata)
    rok, rdata = _certbot("POST", f"/{kind}/accounts/{aid}/certificates/{cid}/generaterequest", bearer, ident[0])
    if not rok:
        _audit(ident, "update_certificate_hostnames", f"{trust}/{aid}/{cid}:generaterequest", False)
        return _out(rdata)
    done, ok, status = _kick_sign((kind, aid, cid), bearer, ident[0], ident, "update", prev_expires)
    _audit(ident, "update_certificate_hostnames", f"{trust}/{aid}/{cid}", True)
    return _out(_issue_result(trust, aid, cid, curc.get("name"), subs, done, ok, status))


def _issue_result(trust, aid, cid, name, subs, done, ok, status):
    """Shape the create/update return: inline result if the sign finished in the inline window,
    else an 'issuing' handle for check_issuance."""
    base = {"trust": trust, "account_id": aid, "certificate_id": cid, "name": name, "subjects": subs}
    if not done:
        return {**base, "status": "issuing",
                "message": "Signing started (ACME can take a few minutes). Poll check_issuance with "
                           "this trust/account_id/certificate_id — expect completion within ~3 minutes.",
                "poll_with": {"tool": "check_issuance", "trust": trust, "account_id": aid, "certificate_id": cid}}
    if ok and status == "signed":
        return {**base, "status": "signed", "message": "Certificate signed."}
    return {**base, "status": status or "failed",
            "message": "Signing did not complete successfully — see the issuance journal / audit log. "
                       "The certificate may be left unsigned."}


@mcp.tool()
def check_issuance(ctx: Context, trust: str, account_id: int, certificate_id: int) -> str:
    """Poll the outcome of a request_server_certificate / update_certificate_hostnames that returned
    'issuing'. Reconciles against certbot's OWN cert record (the source of truth), so it works even
    across an MCP restart. `trust`='public'|'private'. Returns 'signed' (done), 'issuing' (still
    working), or 'unsigned' (not complete — still in progress or the sign failed; check again or
    inspect the journal)."""
    kind, e = _trust_to_kind(trust)
    if e:
        return e
    ident, e = _guard(ctx, "check_issuance", f"{trust}/{account_id}/{certificate_id}")
    if e:
        return e
    aid, cid = int(account_id), int(certificate_id)
    gok, cur = _get_cert(kind, aid, cid, _bearer(ctx), ident[0])
    if not gok:
        return _out(cur)
    snap = _cert_snapshot(cur)
    key = (kind, aid, cid)
    with _signs_lock:
        ent = dict(_signs.get(key, {}))
    running = bool(ent) and not ent.get("done", True) and ent.get("thread") and ent["thread"].is_alive()
    out = {"trust": trust, "account_id": aid, "certificate_id": cid,
           "status": snap.get("status"), "expires": snap.get("expires"), "subjects": snap.get("subjects")}
    if snap.get("status") == "signed":
        # If we have the pre-sign expiry (same process), confirm it actually advanced.
        prev = ent.get("prev_expires")
        if prev and snap.get("expires") == prev:
            out["result"] = "issuing"
            out["message"] = "Still signing — cert not yet updated (expiry unchanged)."
        else:
            out["result"] = "signed"
            out["message"] = "Signing complete."
    elif running:
        out["result"] = "issuing"
        out["message"] = f"Signing in progress ({int(time.time() - ent['started'])}s elapsed)."
    else:
        out["result"] = "unsigned"
        out["message"] = ("Certificate is not signed and no sign is running here. It is either still "
                          "in progress from another worker, or the sign failed — inspect the issuance "
                          "journal / audit log, and re-run if needed.")
    _audit(ident, "check_issuance", f"{trust}/{aid}/{cid}:{out['result']}", True)
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
    import logging as _lg
    _acc = os.environ.get("CERTBOT_ACCESS_LOG", "false").strip().lower() in ("1", "true", "yes")
    if not _acc:
        class _DropAccess(_lg.Filter):          # suppress uvicorn HTTP access lines (noise → Ringdown)
            def filter(self, record):
                return False
        _lg.getLogger("uvicorn.access").addFilter(_DropAccess())
    mcp.run(transport="streamable-http")
