"""
Authorization variable dictionary for Arbiter-403.

Categorizes bypass-candidate variables into four groups — headers,
params, paths, and methods — each with concrete test values ready
for mutation injection.  Also provides ``enumerate_transport_variables``
for connection-context variables (protocol, User-Agent, Referer).
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from bypasser.db import get_connection

# ═══════════════════════════════════════════════════════════════════════
#  Authorization Variables
# ═══════════════════════════════════════════════════════════════════════
#
#  Each category maps a variable *name* to a dict containing at
#  minimum a ``test_value``.  Additional metadata (``category``,
#  ``description``) is included for reporting and triage.
#
#  Structure
#  ---------
#  AUTHORIZATION_VARIABLES = {
#      "<category>": {
#          "<variable_name>": {
#              "test_value":  <str>,
#              "category":    <str>,   # e.g. 'Internal-Only', 'Proxy'
#              "description": <str>,
#          },
#          ...
#      },
#      ...
#  }
# ═══════════════════════════════════════════════════════════════════════

AUTHORIZATION_VARIABLES: dict[str, dict[str, dict]] = {
    # ── Headers ─────────────────────────────────────────────────────
    "headers": {
        # ── Internal-Only headers ───────────────────────────────────
        "X-Original-URL": {
            "test_value": "/",
            "category": "Internal-Only",
            "description": (
                "Used by reverse proxies (IIS/ARR, Nginx) to pass the "
                "original request URI to the backend.  Injecting a "
                "permitted path may bypass path-based ACLs."
            ),
        },
        "X-Rewrite-URL": {
            "test_value": "/",
            "category": "Internal-Only",
            "description": (
                "Alternate rewrite header honoured by IIS URL Rewrite "
                "module.  Similar bypass vector to X-Original-URL."
            ),
        },
        "X-Custom-IP-Authorization": {
            "test_value": "127.0.0.1",
            "category": "Internal-Only",
            "description": (
                "Non-standard header sometimes trusted by custom "
                "middleware to whitelist internal IPs."
            ),
        },

        # ── Proxy / IP-spoofing headers ─────────────────────────────
        "X-Forwarded-For": {
            "test_value": "127.0.0.1",
            "category": "Proxy",
            "description": (
                "De-facto standard for client-IP forwarding.  When the "
                "app trusts this header without validation, spoofing "
                "127.0.0.1 may bypass IP-based restrictions."
            ),
        },
        "X-Remote-IP": {
            "test_value": "127.0.0.1",
            "category": "Proxy",
            "description": (
                "Alternative IP header used by some load balancers "
                "and cloud proxies."
            ),
        },
        "X-Remote-Addr": {
            "test_value": "127.0.0.1",
            "category": "Proxy",
            "description": (
                "Mirrors REMOTE_ADDR; trusted by some Java / .NET "
                "middleware for IP allow-listing."
            ),
        },
        "X-Host": {
            "test_value": "localhost",
            "category": "Proxy",
            "description": (
                "Override header for the Host value.  May trick "
                "virtual-host routing or host-based ACLs."
            ),
        },
        "X-Forwarded-Host": {
            "test_value": "localhost",
            "category": "Proxy",
            "description": (
                "Standard proxy header for the original Host.  Can "
                "bypass host-header validation on the backend."
            ),
        },
        "X-Real-IP": {
            "test_value": "127.0.0.1",
            "category": "Proxy",
            "description": (
                "Nginx-native header carrying the true client IP.  "
                "Spoofing it may bypass IP-based ACLs when the app "
                "reads this header directly."
            ),
        },
        "X-Client-IP": {
            "test_value": "127.0.0.1",
            "category": "Proxy",
            "description": (
                "Used by some CDNs and proxies.  Applications that "
                "trust it for geo or auth decisions are vulnerable."
            ),
        },
        "X-Forwarded-Proto": {
            "test_value": "https",
            "category": "Proxy",
            "description": (
                "Indicates the originating protocol.  Forcing 'https' "
                "can bypass HTTPS-only access controls."
            ),
        },
        "X-ProxyUser-IP": {
            "test_value": "127.0.0.1",
            "category": "Proxy",
            "description": (
                "Google-internal proxy header.  Occasionally surfaces "
                "in GCP-hosted apps and may be implicitly trusted."
            ),
        },
    },

    # ── Query / body parameters ─────────────────────────────────────
    "params": {
        # Populated by downstream mutation generators.
    },

    # ── Path mutations ──────────────────────────────────────────────
    "paths": {
        # Populated by downstream mutation generators.
    },

    # ── HTTP method overrides ───────────────────────────────────────
    "methods": {
        # Populated by downstream mutation generators.
    },
}


# ═══════════════════════════════════════════════════════════════════════
#  Transport / Connection-Context Variables
# ═══════════════════════════════════════════════════════════════════════

TRANSPORT_VARIABLES: list[dict[str, str]] = [
    # ── Protocol ────────────────────────────────────────────────────
    {
        "name": "Protocol-HTTP",
        "category": "Protocol",
        "test_value": "http",
        "description": "Force the request over plain HTTP to test HTTPS-only ACLs.",
    },
    {
        "name": "Protocol-HTTPS",
        "category": "Protocol",
        "test_value": "https",
        "description": "Explicitly use HTTPS; baseline comparison for protocol toggling.",
    },

    # ── User-Agent types ────────────────────────────────────────────
    {
        "name": "UA-Desktop",
        "category": "User-Agent",
        "test_value": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "description": "Standard desktop Chrome User-Agent.",
    },
    {
        "name": "UA-Mobile",
        "category": "User-Agent",
        "test_value": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.0 Mobile/15E148 Safari/604.1"
        ),
        "description": "Mobile Safari UA; some ACLs treat mobile traffic differently.",
    },
    {
        "name": "UA-Bot-Google",
        "category": "User-Agent",
        "test_value": (
            "Mozilla/5.0 (compatible; Googlebot/2.1; "
            "+http://www.google.com/bot.html)"
        ),
        "description": "Googlebot UA; sites may whitelist crawlers by User-Agent.",
    },
    {
        "name": "UA-Bot-Curl",
        "category": "User-Agent",
        "test_value": "curl/8.4.0",
        "description": "Minimal curl UA; tests whether non-browser agents are blocked.",
    },

    # ── Referer ─────────────────────────────────────────────────────
    {
        "name": "Referer-Internal",
        "category": "Referer",
        "test_value": "{origin}/",
        "description": (
            "Referer set to the target's own origin.  Some apps only "
            "allow requests referred from their own domain."
        ),
    },
    {
        "name": "Referer-Google",
        "category": "Referer",
        "test_value": "https://www.google.com/",
        "description": (
            "Referer set to Google search; tests whether external "
            "referrals are blocked or allowed."
        ),
    },
]


def enumerate_transport_variables() -> list[dict[str, str]]:
    """
    Generate transport / connection-context variables and persist
    them to the ``policy_variables`` table.

    Variables cover three categories:

    * **Protocol** — HTTP vs HTTPS switching.
    * **User-Agent** — Desktop, Mobile, Googlebot, curl.
    * **Referer** — internal origin vs external (Google).

    Each variable is inserted with ``is_active = 1``.  Existing rows
    (matched on ``name``) are updated in place so the function is
    idempotent.

    Returns
    -------
    list[dict[str, str]]
        The full list of transport variable dicts.
    """
    conn = get_connection()
    try:
        for var in TRANSPORT_VARIABLES:
            conn.execute(
                """
                INSERT INTO policy_variables
                    (name, category, test_value, description, is_active)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(name) DO UPDATE SET
                    category    = excluded.category,
                    test_value  = excluded.test_value,
                    description = excluded.description,
                    is_active   = 1
                """,
                (
                    var["name"],
                    var["category"],
                    var["test_value"],
                    var["description"],
                ),
            )
        conn.commit()
    finally:
        conn.close()

    return TRANSPORT_VARIABLES


# ═══════════════════════════════════════════════════════════════════════
#  Identity Stubs — fake credential headers
# ═══════════════════════════════════════════════════════════════════════
#
#  These headers mimic an authenticated state with deliberately
#  invalid credentials.  The goal is to detect whether the server's
#  403 behaviour changes (different body, headers, status code, or
#  timing) when it *thinks* it sees an identity credential — even
#  though the credential itself is junk.
# ═══════════════════════════════════════════════════════════════════════

IDENTITY_STUBS: list[dict[str, str]] = [
    # ── Bearer / JWT tokens ─────────────────────────────────────────
    {
        "name": "Identity-Bearer-Junk",
        "header": "Authorization",
        "category": "Identity",
        "test_value": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.junk",
        "description": (
            "Malformed JWT Bearer token.  If the server returns a "
            "401 instead of 403, the authorization layer is identity-"
            "aware and may be bypassable with a valid token."
        ),
    },
    {
        "name": "Identity-Bearer-Empty",
        "header": "Authorization",
        "category": "Identity",
        "test_value": "Bearer ",
        "description": (
            "Empty Bearer token.  Some frameworks fall through to "
            "a permissive default when the token is blank."
        ),
    },
    {
        "name": "Identity-Basic-Admin",
        "header": "Authorization",
        "category": "Identity",
        "test_value": "Basic YWRtaW46YWRtaW4=",       # admin:admin
        "description": (
            "HTTP Basic auth with admin:admin.  Tests for default "
            "credential acceptance and auth-layer detection."
        ),
    },

    # ── Cookie-based identity ───────────────────────────────────────
    {
        "name": "Identity-Cookie-UserID",
        "header": "Cookie",
        "category": "Identity",
        "test_value": "user_id=1",
        "description": (
            "Numeric user_id cookie.  Apps that trust unsigned "
            "cookies may escalate to the first user's session."
        ),
    },
    {
        "name": "Identity-Cookie-Session",
        "header": "Cookie",
        "category": "Identity",
        "test_value": "session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "description": (
            "Junk session cookie.  Detects whether the server "
            "differentiates between no cookie and an invalid one."
        ),
    },
    {
        "name": "Identity-Cookie-IsAdmin",
        "header": "Cookie",
        "category": "Identity",
        "test_value": "is_admin=true; role=admin",
        "description": (
            "Admin flag cookies.  Poorly-written middleware may "
            "trust client-side role indicators directly."
        ),
    },

    # ── Custom identity headers ─────────────────────────────────────
    {
        "name": "Identity-X-Authenticated-User",
        "header": "X-Authenticated-User",
        "category": "Identity",
        "test_value": "admin",
        "description": (
            "Some reverse-proxy auth setups pass the verified "
            "username in this header.  If the backend trusts "
            "it without re-validation, access is granted."
        ),
    },
    {
        "name": "Identity-X-Auth-Token",
        "header": "X-Auth-Token",
        "category": "Identity",
        "test_value": "00000000-0000-0000-0000-000000000001",
        "description": (
            "Generic internal auth token header.  Tests whether "
            "the app checks token validity or just presence."
        ),
    },
    {
        "name": "Identity-X-API-Key",
        "header": "X-API-Key",
        "category": "Identity",
        "test_value": "test-key-000",
        "description": (
            "Fake API key.  Some endpoints only check that the "
            "header exists, not that the key is valid."
        ),
    },
    {
        "name": "Identity-X-SAML-Token",
        "header": "X-SAML-Token",
        "category": "Identity",
        "test_value": "PHNhbWw+dGVzdDwvc2FtbD4=",     # <saml>test</saml>
        "description": (
            "Base64-encoded junk SAML assertion.  Enterprise apps "
            "relying on SSO may react differently to SAML presence."
        ),
    },
]


def enumerate_identity_stubs() -> list[dict[str, str]]:
    """
    Generate identity-stub variables and persist them to the
    ``policy_variables`` table.

    Each stub injects a fake credential header to test whether the
    server's 403 response changes when it detects an identity signal.
    All entries are created with ``is_active = 1`` and are idempotent
    (upserted on ``name``).

    Returns
    -------
    list[dict[str, str]]
        The full list of identity-stub dicts.
    """
    conn = get_connection()
    try:
        for stub in IDENTITY_STUBS:
            conn.execute(
                """
                INSERT INTO policy_variables
                    (name, category, test_value, description, is_active)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(name) DO UPDATE SET
                    category    = excluded.category,
                    test_value  = excluded.test_value,
                    description = excluded.description,
                    is_active   = 1
                """,
                (
                    stub["name"],
                    stub["category"],
                    stub["test_value"],
                    stub["description"],
                ),
            )
        conn.commit()
    finally:
        conn.close()

    return IDENTITY_STUBS


# ═══════════════════════════════════════════════════════════════════════
#  Object Binding — numeric ID extraction from URLs
# ═══════════════════════════════════════════════════════════════════════
#
#  If a target URL contains a path segment that is a bare numeric ID
#  (e.g. /api/v1/user/100), the segment is extracted and stored as
#  an 'Object ID' variable.  IDOR testing can then substitute
#  neighbouring IDs (id-1, id+1) to probe access boundaries.
# ═══════════════════════════════════════════════════════════════════════

# Matches path segments that are purely numeric (1+ digits).
_NUMERIC_ID_RE = re.compile(r"(?:^|/)(?P<id>\d+)(?=/|$)")


def extract_object_ids(
    urls: list[str] | str,
) -> list[dict[str, str]]:
    """
    Scan one or more URLs for numeric path-segment IDs and persist
    each unique ID as an 'Object ID' variable in ``policy_variables``.

    For every numeric segment found the function also creates
    ``id ± 1`` adjacency probes so downstream mutations can test
    for IDOR boundaries.

    Parameters
    ----------
    urls : list[str] | str
        A single URL string or a list of URLs to inspect.

    Returns
    -------
    list[dict[str, str]]
        A list of dicts (one per extracted variable) with keys
        ``name``, ``category``, ``test_value``, ``description``,
        and ``source_url``.
    """
    if isinstance(urls, str):
        urls = [urls]

    extracted: list[dict[str, str]] = []
    seen_ids: set[str] = set()              # de-duplicate across URLs

    for url in urls:
        path = urlparse(url).path
        for match in _NUMERIC_ID_RE.finditer(path):
            raw_id = match.group("id")
            if raw_id in seen_ids:
                continue
            seen_ids.add(raw_id)

            int_id = int(raw_id)

            # The original ID value.
            extracted.append({
                "name": f"ObjectID-{raw_id}",
                "category": "Object ID",
                "test_value": raw_id,
                "description": (
                    f"Numeric ID '{raw_id}' extracted from path "
                    f"'{path}'.  Direct replay of the original value."
                ),
                "source_url": url,
            })

            # Adjacency probe: id - 1  (skip if it would go negative)
            if int_id > 0:
                adj_lo = str(int_id - 1)
                extracted.append({
                    "name": f"ObjectID-{raw_id}-minus1",
                    "category": "Object ID",
                    "test_value": adj_lo,
                    "description": (
                        f"Adjacency probe: original ID {raw_id} → "
                        f"{adj_lo}.  Tests horizontal IDOR boundary."
                    ),
                    "source_url": url,
                })

            # Adjacency probe: id + 1
            adj_hi = str(int_id + 1)
            extracted.append({
                "name": f"ObjectID-{raw_id}-plus1",
                "category": "Object ID",
                "test_value": adj_hi,
                "description": (
                    f"Adjacency probe: original ID {raw_id} → "
                    f"{adj_hi}.  Tests horizontal IDOR boundary."
                ),
                "source_url": url,
            })

    # ── Persist to policy_variables ─────────────────────────────────
    if extracted:
        conn = get_connection()
        try:
            for var in extracted:
                conn.execute(
                    """
                    INSERT INTO policy_variables
                        (name, category, test_value, description, is_active)
                    VALUES (?, ?, ?, ?, 1)
                    ON CONFLICT(name) DO UPDATE SET
                        category    = excluded.category,
                        test_value  = excluded.test_value,
                        description = excluded.description,
                        is_active   = 1
                    """,
                    (
                        var["name"],
                        var["category"],
                        var["test_value"],
                        var["description"],
                    ),
                )
            conn.commit()
        finally:
            conn.close()

    return extracted


# ═══════════════════════════════════════════════════════════════════════
#  Method Sequence — POST-then-GET probing
# ═══════════════════════════════════════════════════════════════════════
#
#  Some servers enforce 403 only on GET but forget to guard the same
#  resource after a state-changing POST (or vice-versa).  These stubs
#  define method sequences that the mutation engine should replay
#  within a single session.
# ═══════════════════════════════════════════════════════════════════════

METHOD_SEQUENCE_STUBS: list[dict[str, str]] = [
    {
        "name": "MethodSeq-POST-then-GET",
        "category": "Method Sequence",
        "test_value": "POST,GET",
        "description": (
            "Issue a POST with an empty body, then a GET on the same "
            "session.  If the POST primes server-side state (CSRF "
            "token, session flag) the follow-up GET may succeed."
        ),
    },
    {
        "name": "MethodSeq-OPTIONS-then-GET",
        "category": "Method Sequence",
        "test_value": "OPTIONS,GET",
        "description": (
            "Send an OPTIONS pre-flight, then a GET.  CORS-aware "
            "servers may relax enforcement after a valid pre-flight."
        ),
    },
    {
        "name": "MethodSeq-PUT-then-GET",
        "category": "Method Sequence",
        "test_value": "PUT,GET",
        "description": (
            "PUT followed by GET.  Tests whether a write-method "
            "request toggles access for subsequent reads."
        ),
    },
    {
        "name": "MethodSeq-PATCH-then-GET",
        "category": "Method Sequence",
        "test_value": "PATCH,GET",
        "description": (
            "PATCH followed by GET.  Some REST frameworks treat "
            "partial-update verbs with different ACL rules."
        ),
    },
]


def enumerate_method_sequences() -> list[dict[str, str]]:
    """
    Persist method-sequence stubs to the ``policy_variables`` table.

    Each sequence describes an ordered pair of HTTP methods that
    should be replayed within a single keep-alive session to test
    whether the 403 response changes after a state-priming request.

    Returns
    -------
    list[dict[str, str]]
        The full list of method-sequence dicts.
    """
    conn = get_connection()
    try:
        for seq in METHOD_SEQUENCE_STUBS:
            conn.execute(
                """
                INSERT INTO policy_variables
                    (name, category, test_value, description, is_active)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(name) DO UPDATE SET
                    category    = excluded.category,
                    test_value  = excluded.test_value,
                    description = excluded.description,
                    is_active   = 1
                """,
                (
                    seq["name"],
                    seq["category"],
                    seq["test_value"],
                    seq["description"],
                ),
            )
        conn.commit()
    finally:
        conn.close()

    return METHOD_SEQUENCE_STUBS


# ═══════════════════════════════════════════════════════════════════════
#  WAF-Aware Variable Selection
# ═══════════════════════════════════════════════════════════════════════
#
#  Different enforcers are vulnerable to different variable classes.
#  Rather than testing every variable against every target, we query
#  the endpoints table for the WAF type and denial layer, then return
#  the active policy_variables **sorted by priority** so the most
#  promising mutations run first.
# ═══════════════════════════════════════════════════════════════════════

# Priority ordering per WAF / layer profile.
# Lower number = higher priority.  Categories not listed default to 50.
_WAF_PRIORITY: dict[str, dict[str, int]] = {
    # ── Cloudflare ──────────────────────────────────────────────────
    #    Edge WAF that inspects headers aggressively.
    "Cloudflare": {
        "Internal-Only":   1,
        "Proxy":           2,
        "Identity":        3,
        "Protocol":        5,
        "User-Agent":      6,
        "Object ID":      10,
        "Method Sequence": 12,
        "Referer":        15,
    },
    # ── Akamai ──────────────────────────────────────────────────────
    "Akamai": {
        "Internal-Only":   1,
        "Proxy":           2,
        "Identity":        4,
        "Protocol":        5,
        "User-Agent":      8,
        "Method Sequence": 10,
        "Object ID":      12,
        "Referer":        15,
    },
    # ── AWS CloudFront ──────────────────────────────────────────────
    "AWS CloudFront": {
        "Proxy":           1,
        "Internal-Only":   2,
        "Protocol":        3,
        "Identity":        5,
        "User-Agent":      8,
        "Method Sequence": 10,
        "Object ID":      12,
        "Referer":        15,
    },
}

_LAYER_PRIORITY: dict[str, dict[str, int]] = {
    # ── Application-Layer ───────────────────────────────────────────
    #    The origin is making the decision → object / param / path
    #    mutations are most likely to succeed.
    "Application-Layer": {
        "Object ID":       1,
        "Method Sequence": 2,
        "Identity":        3,
        "Referer":         5,
        "User-Agent":      8,
        "Internal-Only":  10,
        "Proxy":          12,
        "Protocol":       15,
    },
    # ── Edge-Layer ──────────────────────────────────────────────────
    #    The CDN / WAF is making the decision → header and proxy
    #    spoofing is the primary attack surface.
    "Edge-Layer": {
        "Internal-Only":   1,
        "Proxy":           2,
        "Protocol":        3,
        "Identity":        5,
        "User-Agent":      8,
        "Method Sequence": 10,
        "Object ID":      12,
        "Referer":        15,
    },
}

_DEFAULT_PRIORITY = 50


def get_active_variables(fingerprint_group_id: str) -> list[dict]:
    """
    Return all active policy variables, **sorted by relevance** to
    the enforcer profile associated with *fingerprint_group_id*.

    Resolution order
    ----------------
    1. Look up every endpoint in the ``endpoints`` table that shares
       the given ``fingerprint_group_id``.
    2. Extract the most common ``waf_type`` and ``denial_layer``.
    3. Merge WAF-specific and layer-specific priority maps.  When
       both maps assign a priority to the same category, the
       **lower (= more urgent)** value wins.
    4. Fetch all rows from ``policy_variables`` where
       ``is_active = 1``, sort them by the merged priority, and
       return them as a list of dicts.

    Parameters
    ----------
    fingerprint_group_id : str
        The UUID fingerprint group to resolve the enforcer profile
        for.  Obtained from ``endpoints.fingerprint_group_id``.

    Returns
    -------
    list[dict]
        Each dict contains: ``name``, ``category``, ``test_value``,
        ``description``, ``is_active``, and an added ``priority``
        key (int, lower = more relevant).
    """
    conn = get_connection()
    try:
        # ── 1. Resolve WAF type and denial layer ───────────────────
        rows = conn.execute(
            """
            SELECT waf_type, denial_layer
              FROM endpoints
             WHERE fingerprint_group_id = ?
               AND is_stable = 1
            """,
            (fingerprint_group_id,),
        ).fetchall()

        waf_type = _majority_value([r["waf_type"] for r in rows]) if rows else "Unknown"
        denial_layer = _majority_value([r["denial_layer"] for r in rows]) if rows else None

        # ── 2. Build merged priority map ───────────────────────────
        waf_prio = _WAF_PRIORITY.get(waf_type, {})
        layer_prio = _LAYER_PRIORITY.get(denial_layer, {}) if denial_layer else {}

        # Merge: take the minimum (= most urgent) of the two maps
        all_categories = set(waf_prio) | set(layer_prio)
        merged: dict[str, int] = {}
        for cat in all_categories:
            merged[cat] = min(
                waf_prio.get(cat, _DEFAULT_PRIORITY),
                layer_prio.get(cat, _DEFAULT_PRIORITY),
            )

        # ── 3. Fetch active variables ──────────────────────────────
        var_rows = conn.execute(
            """
            SELECT name, category, test_value, description, is_active
              FROM policy_variables
             WHERE is_active = 1
            """
        ).fetchall()

        variables = []
        for r in var_rows:
            priority = merged.get(r["category"], _DEFAULT_PRIORITY)
            variables.append({
                "name":        r["name"],
                "category":    r["category"],
                "test_value":  r["test_value"],
                "description": r["description"],
                "is_active":   r["is_active"],
                "priority":    priority,
                "waf_type":    waf_type,
                "denial_layer": denial_layer,
            })

        variables.sort(key=lambda v: v["priority"])
        return variables

    finally:
        conn.close()


def _majority_value(values: list[str | None]) -> str:
    """Return the most common non-None value, or 'Unknown'."""
    filtered = [v for v in values if v]
    if not filtered:
        return "Unknown"
    from collections import Counter
    return Counter(filtered).most_common(1)[0][0]
