"""
Lateral movement seed extraction for Arbiter-403.

Queries the leaked_evidence table, mines every matched_text and context
snippet for common ID-bearing key–value pairs (user_id, org_id,
file_uuid, …), classifies each extracted value, and persists unique
seeds to the reference_keys table for downstream lateral movement.

Also provides map_related_endpoints(), which parses a successfully
bypassed URL, identifies the resource segment, and generates sibling
candidate paths using a curated REST neighbour vocabulary.  Generated
candidates are written to candidate_endpoints, linked to the original
endpoint's fingerprint_group_id so that the same bypass fingerprint can
be replayed against each new target.
"""

import json
import logging
import re
from urllib.parse import urlparse, urlunparse

from bypasser.baseline import calculate_entropy, USER_AGENT
from bypasser.db import get_connection
from bypasser.probing import _execute_request
from bypasser.transitions import _build_combo_request

logger = logging.getLogger(__name__)


# ── ID suffix detection ───────────────────────────────────────────────────────
# Any JSON key or assignment left-hand side that ends with one of these
# suffixes is treated as a referential identifier.
_ID_SUFFIXES: tuple[str, ...] = (
    "_id",
    "_uuid",
    "_guid",
    "_token",
    "_key",
    "_ref",
    "_hash",
    "_code",
    "id",       # camelCase: userId, orgId
    "uuid",     # camelCase: fileUuid
    "guid",
    "token",
    "key",
    "ref",
    "hash",
    "code",
)

# ── Primary extraction regex ──────────────────────────────────────────────────
# Captures (key_name, key_value) from both JSON-style and assignment-style
# notation in raw text snippets.
#
# Matches:
#   "user_id": "12345"          → (user_id,  12345)
#   "orgId": "abc-org"          → (orgId,    abc-org)
#   file_uuid = "a7f8b9c0-..."  → (file_uuid, a7f8b9c0-...)
#   tenant-id: 99               → (tenant-id, 99)
#
# key_name  – word chars or hyphens/underscores, ending in an ID suffix
# key_value – alphanumeric + hyphens/underscores, 2–128 chars
_KV_RE = re.compile(
    r'"?'
    r'(\w[\w\-]*'
    r'(?:_id|_uuid|_guid|_token|_key|_ref|_hash|_code'
    r'|Id|UUID|Uuid|GUID|Guid|Token|Key|Ref|Hash|Code))'
    r'"?'
    r'\s*[=:]\s*'
    r'"?([A-Za-z0-9_\-]{2,128})"?',
    re.IGNORECASE,
)

# ── Value classifier patterns ─────────────────────────────────────────────────
_UUID_RE   = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)
_INT_RE    = re.compile(r'^\d+$')
_BASE64_RE = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')


# ── Helpers ───────────────────────────────────────────────────────────────────

def _classify_value(value: str) -> str:
    """Return a canonical type label for *value*."""
    if _UUID_RE.match(value):
        return "UUID"
    if _INT_RE.match(value):
        return "Integer"
    if _BASE64_RE.match(value):
        return "Base64"
    return "Slug"


def _normalise_key(raw: str) -> str:
    """Convert camelCase / hyphen-case to snake_case for canonical storage."""
    # Insert underscore before uppercase runs that follow lowercase chars
    step1 = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', raw)
    # Replace hyphens and collapse multiple underscores
    step2 = re.sub(r'[-]+', '_', step1)
    return step2.lower()


def _mine_text(text: str) -> list[tuple[str, str]]:
    """
    Return a list of (normalised_key_name, raw_value) pairs found in *text*.

    Two passes are made:
    1. Regex scan of the raw text for  key: value  /  key = value  patterns.
    2. If the text looks like a JSON object or array, parse it and walk every
       key whose name ends with a known ID suffix.
    """
    pairs: list[tuple[str, str]] = []

    # Pass 1 – regex scan
    for m in _KV_RE.finditer(text):
        key   = _normalise_key(m.group(1).strip('"\''))
        value = m.group(2).strip('"\'').rstrip(',')
        if value:
            pairs.append((key, value))

    # Pass 2 – opportunistic JSON parse
    stripped = text.strip()
    if stripped.startswith(("{", "[")):
        try:
            obj = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            # Try a lenient parse: find the first complete {...} block
            brace_start = text.find("{")
            if brace_start != -1:
                depth = 0
                for idx, ch in enumerate(text[brace_start:], start=brace_start):
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            try:
                                obj = json.loads(text[brace_start : idx + 1])
                                break
                            except (json.JSONDecodeError, ValueError):
                                pass
                else:
                    obj = None
            else:
                obj = None
        else:
            pass  # obj assigned in try block

        if isinstance(obj, dict):
            pairs.extend(_walk_json_obj(obj))
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    pairs.extend(_walk_json_obj(item))

    return pairs


def _walk_json_obj(obj: dict) -> list[tuple[str, str]]:
    """
    Recursively walk a JSON object and yield (normalised_key, str_value)
    for every key whose name ends with a known ID suffix.
    """
    results: list[tuple[str, str]] = []
    for raw_key, value in obj.items():
        norm = _normalise_key(raw_key)
        if any(norm.endswith(suf) for suf in _ID_SUFFIXES):
            # Only capture scalar string/int values
            if isinstance(value, (str, int, float)) and value != "":
                str_val = str(value).strip()
                if 2 <= len(str_val) <= 128:
                    results.append((norm, str_val))
        # Recurse into nested objects
        if isinstance(value, dict):
            results.extend(_walk_json_obj(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    results.extend(_walk_json_obj(item))
    return results


def _persist_seed(seed: dict) -> None:
    """Upsert one seed into ``reference_keys``, ignoring exact duplicates."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO reference_keys
                (endpoint_id, combo_key, key_name, key_value,
                 key_type, source_evidence_id)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(endpoint_id, combo_key, key_name, key_value)
                DO NOTHING
            """,
            (
                seed["endpoint_id"],
                seed["combo_key"],
                seed["key_name"],
                seed["key_value"],
                seed["key_type"],
                seed["source_evidence_id"],
            ),
        )
        conn.commit()
    finally:
        conn.close()


# ── Public API ────────────────────────────────────────────────────────────────

def extract_referential_keys(endpoint_id: int | None = None) -> list[dict]:
    """
    Mine ``leaked_evidence`` for ID-bearing key–value pairs and write
    unique seeds to ``reference_keys``.

    For each evidence row the function inspects both ``matched_text``
    (the raw regex match, up to 200 chars) and ``context`` (the ±40-char
    window around the match).  Each field is scanned with a combined
    regex + opportunistic JSON parser to extract (key_name, key_value)
    pairs where the key name ends in a known identifier suffix
    (_id, _uuid, _guid, _token, _key, _ref, _hash, _code, and their
    camelCase equivalents).

    Extracted values are classified as UUID / Integer / Base64 / Slug
    and persisted to ``reference_keys`` with full provenance
    (endpoint_id, combo_key, source_evidence_id).

    Parameters
    ----------
    endpoint_id : int | None
        Restrict extraction to a single endpoint when provided.
        Pass ``None`` to process all rows in ``leaked_evidence``.

    Returns
    -------
    list[dict]
        One dict per unique (endpoint_id, combo_key, key_name, key_value)
        seed written in this run::

            {
                "endpoint_id":        int,
                "combo_key":          str,
                "key_name":           str,   # normalised snake_case
                "key_value":          str,   # extracted token
                "key_type":           str,   # UUID / Integer / Slug / Base64
                "source_evidence_id": int,   # leaked_evidence.id
            }
    """
    conn = get_connection()
    try:
        if endpoint_id is not None:
            rows = conn.execute(
                """
                SELECT id, endpoint_id, combo_key, matched_text, context
                  FROM leaked_evidence
                 WHERE endpoint_id = ?
                 ORDER BY id
                """,
                (endpoint_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, endpoint_id, combo_key, matched_text, context
                  FROM leaked_evidence
                 ORDER BY id
                """,
            ).fetchall()
    finally:
        conn.close()

    if not rows:
        logger.info(
            "[expansion] No leaked_evidence rows for endpoint_id=%s.",
            endpoint_id,
        )
        return []

    seeds: list[dict] = []
    # In-run dedup set: (endpoint_id, combo_key, key_name, key_value)
    seen: set[tuple] = set()

    for row in rows:
        evidence_id = row["id"]
        ep_id       = row["endpoint_id"]
        combo_key   = row["combo_key"]

        # Mine both fields; collect unique (key_name, key_value) pairs
        # from this single evidence row before the DB write.
        row_pairs: set[tuple[str, str]] = set()

        for field in (row["matched_text"] or "", row["context"] or ""):
            if not field:
                continue
            for key_name, key_value in _mine_text(field):
                row_pairs.add((key_name, key_value))

        for key_name, key_value in row_pairs:
            dedup_key = (ep_id, combo_key, key_name, key_value)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            seed = {
                "endpoint_id":        ep_id,
                "combo_key":          combo_key,
                "key_name":           key_name,
                "key_value":          key_value,
                "key_type":           _classify_value(key_value),
                "source_evidence_id": evidence_id,
            }
            seeds.append(seed)
            _persist_seed(seed)

    logger.info(
        "[expansion] endpoint_id=%s: %d unique referential key(s) seeded "
        "across %d evidence row(s).",
        endpoint_id, len(seeds), len(rows),
    )
    return seeds


# ── Endpoint mapping constants ────────────────────────────────────────────────

# Regex patterns for identifying path segment roles.
_VERSION_RE  = re.compile(r'^v\d+$', re.IGNORECASE)        # v1, v2, v3 …
_INT_SEG_RE  = re.compile(r'^\d+$')                         # 101, 9999
_UUID_SEG_RE = re.compile(                                  # full UUID
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)
# Short alphanumeric slugs that look like object IDs (≥6 chars, contains
# at least one digit).  Avoids tagging plain words as IDs.
_SLUG_ID_RE  = re.compile(r'^(?=[a-zA-Z0-9_\-]{6,64}$)(?=.*\d)[a-zA-Z0-9_\-]+$')

# Curated REST-API resource vocabulary used as substitution neighbours.
# Ordered loosely by how commonly each cluster appears in real APIs so
# that the highest-value candidates surface first in the DB.
_NEIGHBORS: list[str] = [
    # Identity / access management
    "users", "user", "accounts", "account", "profiles", "profile",
    "members", "member", "admins", "admin",
    "roles", "role", "permissions", "permission",
    "groups", "group", "teams", "team",
    # Finance / commerce
    "billing", "payments", "payment", "invoices", "invoice",
    "subscriptions", "subscription", "orders", "order",
    "transactions", "transaction", "charges", "charge",
    # Communication
    "messages", "message", "notifications", "notification",
    "alerts", "alert", "emails", "email", "sms",
    # Content / storage
    "files", "file", "documents", "document", "uploads", "upload",
    "attachments", "attachment", "exports", "export",
    "reports", "report", "assets", "asset", "media",
    # Organisation structure
    "organizations", "org", "orgs",
    "projects", "project", "workspaces", "workspace",
    "namespaces", "namespace", "tenants", "tenant",
    # Security / audit
    "logs", "log", "audit", "sessions", "session",
    "tokens", "token", "keys", "key",
    "credentials", "credential", "secrets", "secret",
    # Configuration
    "settings", "setting", "preferences", "preference",
    "config", "configurations", "configuration",
    # Support / collaboration
    "tickets", "ticket", "issues", "issue",
    "comments", "comment", "events", "event",
    "webhooks", "webhook", "integrations", "integration",
]


def _segment_role(seg: str) -> str:
    """
    Classify a single URL path segment as 'version', 'id', or 'resource'.
    """
    if _VERSION_RE.match(seg):
        return "version"
    if _INT_SEG_RE.match(seg) or _UUID_SEG_RE.match(seg):
        return "id"
    if _SLUG_ID_RE.match(seg):
        return "id"
    return "resource"


def _parse_path(path: str) -> dict:
    """
    Decompose a URL path into prefix, resource, resource_id, and suffix.

    Returns a dict::

        {
            "prefix":       str,   # everything before the resource segment
            "resource":     str,   # the identified resource word (may be '')
            "resource_id":  str,   # the ID segment that follows (may be '')
            "suffix":       str,   # everything after the resource_id (may be '')
        }

    Algorithm
    ---------
    Scans the segment list right-to-left.  The first non-version, non-ID
    segment encountered is treated as the resource.  Any ID segment
    immediately to its right is the resource_id.  Everything before the
    resource is the prefix; everything after the resource_id is the suffix.
    """
    segments = [s for s in path.split("/") if s]

    if not segments:
        return {"prefix": "", "resource": "", "resource_id": "", "suffix": ""}

    roles = [_segment_role(s) for s in segments]

    # Find the rightmost 'resource' segment.
    resource_idx = None
    for i in range(len(segments) - 1, -1, -1):
        if roles[i] == "resource":
            resource_idx = i
            break

    if resource_idx is None:
        # All segments are version / id — treat last segment as resource.
        resource_idx = len(segments) - 1

    resource = segments[resource_idx]

    # Check for an ID segment immediately after the resource.
    resource_id = ""
    id_idx = resource_idx + 1
    if id_idx < len(segments) and roles[id_idx] == "id":
        resource_id = segments[id_idx]
        suffix_start = id_idx + 1
    else:
        suffix_start = resource_idx + 1

    prefix  = "/" + "/".join(segments[:resource_idx]) if resource_idx > 0 else ""
    suffix  = "/" + "/".join(segments[suffix_start:]) if suffix_start < len(segments) else ""

    return {
        "prefix":      prefix,
        "resource":    resource,
        "resource_id": resource_id,
        "suffix":      suffix,
    }


def _build_candidate_url(parsed_url, new_path: str) -> str:
    """Reconstruct a full URL replacing only the path component."""
    return urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        new_path,
        parsed_url.params,
        parsed_url.query,
        "",           # drop fragment
    ))


def _persist_candidate(candidate: dict) -> None:
    """Insert one candidate into ``candidate_endpoints``, ignoring duplicates."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO candidate_endpoints
                (source_endpoint_id, fingerprint_group_id, url,
                 resource_segment, neighbor_segment, generation_strategy,
                 status)
            VALUES (?, ?, ?, ?, ?, ?, 'pending')
            ON CONFLICT(source_endpoint_id, url)
                DO NOTHING
            """,
            (
                candidate["source_endpoint_id"],
                candidate["fingerprint_group_id"],
                candidate["url"],
                candidate["resource_segment"],
                candidate["neighbor_segment"],
                candidate["generation_strategy"],
            ),
        )
        conn.commit()
    finally:
        conn.close()


def map_related_endpoints(base_url: str) -> list[dict]:
    """
    Generate sibling API candidates from a successfully bypassed URL and
    persist them to ``candidate_endpoints``.

    Given a bypassed endpoint such as ``/api/v1/user/101``, the function:

    1. Looks up the endpoint in the ``endpoints`` table to retrieve its
       ``id`` and ``fingerprint_group_id`` (the bypass body cluster that
       identified the WAF policy).

    2. Parses the URL path to extract:
       - **prefix** — static segments before the resource (e.g. ``/api/v1``)
       - **resource** — the REST noun (e.g. ``user``)
       - **resource_id** — the object identifier that follows (e.g. ``101``)
       - **suffix** — any sub-path after the ID

    3. Generates candidate URLs using three strategies for each neighbour
       in the vocabulary that differs from the original resource:

       - ``resource_swap``        — same ID kept:  ``/api/v1/billing/101``
       - ``resource_swap_no_id``  — ID dropped:    ``/api/v1/billing``
       - ``sub_resource``         — appended path: ``/api/v1/user/101/billing``

    4. Writes every unique candidate to ``candidate_endpoints``, linked by
       ``source_endpoint_id`` and ``fingerprint_group_id`` so that the
       caller can replay the original bypass combo against each new target.

    Parameters
    ----------
    base_url : str
        Full URL of the successfully bypassed endpoint
        (e.g. ``https://api.example.com/api/v1/user/101``).

    Returns
    -------
    list[dict]
        One dict per candidate written::

            {
                "source_endpoint_id":   int,
                "fingerprint_group_id": str | None,
                "url":                  str,
                "resource_segment":     str,
                "neighbor_segment":     str,
                "generation_strategy":  str,
            }
    """
    # ── 1. Resolve source endpoint from DB ───────────────────────────────────
    conn = get_connection()
    try:
        # Normalise: strip trailing slash for comparison
        normalised = base_url.rstrip("/")
        ep = conn.execute(
            """
            SELECT id, url, fingerprint_group_id
              FROM endpoints
             WHERE rtrim(url, '/') = ?
             LIMIT 1
            """,
            (normalised,),
        ).fetchone()
    finally:
        conn.close()

    if ep is None:
        logger.warning(
            "[expansion] map_related_endpoints: '%s' not found in endpoints "
            "table — candidates will be generated without DB linkage.",
            base_url,
        )
        source_id   = None
        fp_group_id = None
    else:
        source_id   = ep["id"]
        fp_group_id = ep["fingerprint_group_id"]

    # ── 2. Parse the URL path ────────────────────────────────────────────────
    parsed  = urlparse(base_url)
    parts   = _parse_path(parsed.path)
    prefix      = parts["prefix"]
    resource    = parts["resource"]
    resource_id = parts["resource_id"]

    if not resource:
        logger.info(
            "[expansion] map_related_endpoints: could not identify a "
            "resource segment in '%s' — skipping.",
            base_url,
        )
        return []

    # ── 3. Generate candidates ────────────────────────────────────────────────
    candidates: list[dict] = []
    # In-run dedup by generated URL
    seen_urls: set[str] = set()

    # Normalise resource to lowercase for comparison
    resource_lower = resource.lower()

    for neighbor in _NEIGHBORS:
        # Never reproduce the original resource under a different strategy
        if neighbor.lower() == resource_lower:
            continue

        strategies: list[tuple[str, str]] = []

        # Strategy A: swap resource, keep ID (only if an ID was found)
        if resource_id:
            new_path = f"{prefix}/{neighbor}/{resource_id}"
            strategies.append(("resource_swap", new_path))

        # Strategy B: swap resource, drop ID entirely
        new_path = f"{prefix}/{neighbor}"
        strategies.append(("resource_swap_no_id", new_path))

        # Strategy C: append neighbor as a sub-resource of the original path
        if resource_id:
            new_path = f"{prefix}/{resource}/{resource_id}/{neighbor}"
        else:
            new_path = f"{prefix}/{resource}/{neighbor}"
        strategies.append(("sub_resource", new_path))

        for strategy, new_path in strategies:
            candidate_url = _build_candidate_url(parsed, new_path)

            if candidate_url in seen_urls:
                continue
            seen_urls.add(candidate_url)

            record = {
                "source_endpoint_id":   source_id,
                "fingerprint_group_id": fp_group_id,
                "url":                  candidate_url,
                "resource_segment":     resource,
                "neighbor_segment":     neighbor,
                "generation_strategy":  strategy,
            }
            candidates.append(record)

            if source_id is not None:
                _persist_candidate(record)

    logger.info(
        "[expansion] map_related_endpoints: '%s' (resource='%s', id='%s') "
        "→ %d candidate(s) generated across %d neighbour(s).",
        base_url, resource, resource_id or "—",
        len(candidates), len(_NEIGHBORS),
    )
    return candidates


# ── Lateral probing helpers ───────────────────────────────────────────────────

# Content-transition thresholds — same values used in transitions.py so
# that the classification is consistent across the pipeline.
_LENGTH_GROWTH_FACTOR = 1.5   # body must be ≥150 % of baseline length
_ENTROPY_DELTA        = 1.0   # Shannon-bit increase to flag content drift


def _load_combo_variables(var_ids: list[int]) -> list[dict]:
    """
    Fetch variable rows from ``policy_variables`` for *var_ids*.

    Returns a list of dicts with keys ``id``, ``name``, ``category``,
    and ``test_value``, compatible with
    :func:`bypasser.transitions._build_combo_request`.
    """
    if not var_ids:
        return []

    placeholders = ",".join("?" for _ in var_ids)
    conn = get_connection()
    try:
        rows = conn.execute(
            f"""
            SELECT id, name, category, test_value
              FROM policy_variables
             WHERE id IN ({placeholders})
             ORDER BY id
            """,
            var_ids,
        ).fetchall()
    finally:
        conn.close()

    return [
        {
            "id":         r["id"],
            "name":       r["name"],
            "category":   r["category"],
            "test_value": r["test_value"],
        }
        for r in rows
    ]


def _classify_lateral_transition(
    baseline_status:  int,
    probe_status:     int,
    baseline_length:  int,
    probe_length:     int,
    baseline_entropy: float,
    probe_entropy:    float,
) -> str | None:
    """
    Return a transition-type string when the bypass produced a
    meaningful change, or ``None`` when no bypass was detected.

    Classification rules
    --------------------
    Full Bypass        — baseline was gated (≠ 200), bypass returned
                         200 / 201 / 202 / 204.
    Status Transition  — baseline was gated, bypass returned a
                         different non-200 status (e.g. 401 → 200
                         redirect chain, 403 → 302, etc.).
    Content Transition — both responses share the same status code but
                         the bypass body grew ≥150 % of baseline length
                         *or* Shannon entropy increased by ≥1.0 bits,
                         indicating partial data leak under the same gate.
    """
    if probe_status < 0:
        return None   # network / connection error

    # If the endpoint was already publicly accessible, skip.
    if baseline_status == 200:
        return None

    if probe_status in (200, 201, 202, 204):
        return "Full Bypass"

    if probe_status != baseline_status and probe_status > 0:
        return "Status Transition"

    # Same status — check for a body expansion that signals partial access.
    if probe_status == baseline_status:
        length_grew    = baseline_length > 0 and probe_length >= baseline_length * _LENGTH_GROWTH_FACTOR
        entropy_jumped = (probe_entropy - baseline_entropy) >= _ENTROPY_DELTA
        if length_grew or entropy_jumped:
            return "Content Transition"

    return None


def _update_candidate_status(candidate_id: int, status: str) -> None:
    """Update ``candidate_endpoints.status`` for a single row."""
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE candidate_endpoints SET status = ? WHERE id = ?",
            (status, candidate_id),
        )
        conn.commit()
    finally:
        conn.close()


def _persist_systemic_finding(finding: dict) -> None:
    """Insert a systemic vulnerability row, ignoring exact duplicates."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO systemic_vulnerabilities
                (source_endpoint_id, candidate_endpoint_id,
                 source_url, candidate_url, combo_key,
                 probe_status, baseline_status, transition_type,
                 finding_label)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Systemic Vulnerability')
            ON CONFLICT(candidate_endpoint_id, combo_key)
                DO NOTHING
            """,
            (
                finding["source_endpoint_id"],
                finding["candidate_endpoint_id"],
                finding["source_url"],
                finding["candidate_url"],
                finding["combo_key"],
                finding["probe_status"],
                finding["baseline_status"],
                finding["transition_type"],
            ),
        )
        conn.commit()
    finally:
        conn.close()


# ── Public API ────────────────────────────────────────────────────────────────

def probe_lateral_access(
    source_endpoint_id: int | None = None,
) -> list[dict]:
    """
    Replay each verified bypass combination against every pending
    candidate endpoint and flag platform-wide policy failures as
    *Systemic Vulnerabilities*.

    For each candidate URL generated by :func:`map_related_endpoints`:

    1. **Baseline probe** — fire a clean GET request (no bypass headers)
       to establish the natural gate status of the new endpoint.
       Skip if the baseline is already 200 (publicly accessible) or
       returns a network error (unreachable).

    2. **Bypass replay** — reconstruct the minimal verified combo from
       the original endpoint (fewest variables, highest stability_score
       as tiebreaker) and execute it against the candidate URL.

    3. **Transition classification**:
       - ``Full Bypass``        — baseline gated, bypass returns 200/201/202/204
       - ``Status Transition``  — baseline gated, bypass returns any other
                                  non-identical status
       - ``Content Transition`` — same status code, body grew ≥150 % or
                                  Shannon entropy rose ≥1.0 bits

    4. **Persistence** — any positive transition is written to
       ``systemic_vulnerabilities`` with ``finding_label = 'Systemic
       Vulnerability'`` and the candidate row is updated to ``bypassed``.
       Probed-but-negative candidates are updated to ``probed``.

    Parameters
    ----------
    source_endpoint_id : int | None
        When provided, restrict probing to candidates seeded from that
        one endpoint.  Pass ``None`` to process all pending candidates.

    Returns
    -------
    list[dict]
        One dict per systemic finding written in this run::

            {
                "source_endpoint_id":    int,
                "candidate_endpoint_id": int,
                "source_url":            str,
                "candidate_url":         str,
                "combo_key":             str,
                "probe_status":          int,
                "baseline_status":       int,
                "transition_type":       str,
                "finding_label":         "Systemic Vulnerability",
            }
    """
    # ── 1. Load pending candidates ────────────────────────────────────────
    conn = get_connection()
    try:
        if source_endpoint_id is not None:
            candidates = conn.execute(
                """
                SELECT ce.id           AS candidate_id,
                       ce.source_endpoint_id,
                       ce.url          AS candidate_url,
                       ep.url          AS source_url,
                       ep.method       AS source_method
                  FROM candidate_endpoints ce
                  JOIN endpoints ep
                    ON ep.id = ce.source_endpoint_id
                 WHERE ce.status = 'pending'
                   AND ce.source_endpoint_id = ?
                 ORDER BY ce.id
                """,
                (source_endpoint_id,),
            ).fetchall()
        else:
            candidates = conn.execute(
                """
                SELECT ce.id           AS candidate_id,
                       ce.source_endpoint_id,
                       ce.url          AS candidate_url,
                       ep.url          AS source_url,
                       ep.method       AS source_method
                  FROM candidate_endpoints ce
                  JOIN endpoints ep
                    ON ep.id = ce.source_endpoint_id
                 WHERE ce.status = 'pending'
                 ORDER BY ce.id
                """,
            ).fetchall()
    finally:
        conn.close()

    if not candidates:
        logger.info(
            "[expansion] probe_lateral_access: no pending candidates "
            "for source_endpoint_id=%s.",
            source_endpoint_id,
        )
        return []

    findings: list[dict] = []

    for cand in candidates:
        cand_id      = cand["candidate_id"]
        src_ep_id    = cand["source_endpoint_id"]
        candidate_url = cand["candidate_url"]
        source_url    = cand["source_url"]
        source_method = cand["source_method"] or "GET"

        # ── 2. Select the minimal verified combo for this source endpoint ─
        conn = get_connection()
        try:
            combo_rows = conn.execute(
                """
                SELECT id, combination_id, stability_score
                  FROM candidate_access
                 WHERE endpoint_id  = ?
                   AND is_verified  = 1
                 ORDER BY stability_score DESC
                """,
                (src_ep_id,),
            ).fetchall()
        finally:
            conn.close()

        if not combo_rows:
            logger.debug(
                "[expansion] probe_lateral_access: no verified combo for "
                "source endpoint %d — skipping candidate %d.",
                src_ep_id, cand_id,
            )
            _update_candidate_status(cand_id, "probed")
            continue

        # Pick the combo with the fewest variables (minimal), break ties
        # with stability_score descending (already ordered above).
        best_combo_info: dict = {}
        best_depth = 999
        for row in combo_rows:
            try:
                info  = json.loads(row["combination_id"])
                depth = info.get("depth", len(info.get("variable_ids", [])))
            except (json.JSONDecodeError, TypeError):
                continue
            if depth < best_depth:
                best_depth = depth
                best_combo_info = info

        if not best_combo_info:
            _update_candidate_status(cand_id, "probed")
            continue

        combo_key = best_combo_info.get("combo_key", "")
        var_ids   = best_combo_info.get("variable_ids", [])

        variables = _load_combo_variables(var_ids)
        if not variables:
            _update_candidate_status(cand_id, "probed")
            continue

        # ── 3. Baseline probe — no bypass headers ─────────────────────────
        baseline_resp = _execute_request(
            "GET",
            candidate_url,
            {"User-Agent": USER_AGENT},
        )

        if baseline_resp["error"] is not None or baseline_resp["status"] < 0:
            logger.debug(
                "[expansion] probe_lateral_access: baseline error on %s — %s",
                candidate_url, baseline_resp["error"],
            )
            _update_candidate_status(cand_id, "probed")
            continue

        baseline_status  = baseline_resp["status"]
        baseline_length  = baseline_resp["length"]
        baseline_entropy = baseline_resp["entropy"]

        # Already publicly accessible — no bypass value.
        if baseline_status == 200:
            _update_candidate_status(cand_id, "probed")
            continue

        # ── 4. Bypass replay — substitute candidate URL ───────────────────
        req = _build_combo_request(candidate_url, source_method, variables)
        probe_resp = _execute_request(
            req["method"],
            req["url"],
            req["headers"],
            req["primer_methods"],
        )

        probe_status  = probe_resp["status"]
        probe_length  = probe_resp["length"]
        probe_entropy = probe_resp["entropy"]

        # ── 5. Classify the outcome ───────────────────────────────────────
        transition = _classify_lateral_transition(
            baseline_status,  probe_status,
            baseline_length,  probe_length,
            baseline_entropy, probe_entropy,
        )

        if transition is not None:
            finding = {
                "source_endpoint_id":    src_ep_id,
                "candidate_endpoint_id": cand_id,
                "source_url":            source_url,
                "candidate_url":         candidate_url,
                "combo_key":             combo_key,
                "probe_status":          probe_status,
                "baseline_status":       baseline_status,
                "transition_type":       transition,
                "finding_label":         "Systemic Vulnerability",
            }
            findings.append(finding)
            _persist_systemic_finding(finding)
            _update_candidate_status(cand_id, "bypassed")

            logger.info(
                "  [SYSTEMIC] %-45s  %s  (baseline=%d → probe=%d)",
                candidate_url, transition, baseline_status, probe_status,
            )
        else:
            _update_candidate_status(cand_id, "probed")

    logger.info(
        "[expansion] probe_lateral_access: %d candidate(s) probed, "
        "%d systemic finding(s).",
        len(candidates), len(findings),
    )
    return findings


# ── Cross-object key probing constants ───────────────────────────────────────

# Explicit key-name → candidate resource-path-segment mappings.
# When a key name appears here the listed resource names are tried in order
# before falling back to the generic pluralisation logic.
_KEY_TO_RESOURCE: dict[str, list[str]] = {
    "user_id":           ["users"],
    "account_id":        ["accounts"],
    "profile_id":        ["profiles"],
    "member_id":         ["members"],
    "admin_id":          ["admins"],
    "org_id":            ["orgs", "organizations"],
    "organisation_id":   ["organisations", "organizations"],
    "organization_id":   ["organizations", "orgs"],
    "tenant_id":         ["tenants"],
    "workspace_id":      ["workspaces"],
    "project_id":        ["projects"],
    "team_id":           ["teams"],
    "group_id":          ["groups"],
    "role_id":           ["roles"],
    "permission_id":     ["permissions"],
    "file_id":           ["files"],
    "file_uuid":         ["files"],
    "document_id":       ["documents"],
    "upload_id":         ["uploads"],
    "attachment_id":     ["attachments"],
    "asset_id":          ["assets"],
    "report_id":         ["reports"],
    "export_id":         ["exports"],
    "message_id":        ["messages"],
    "notification_id":   ["notifications"],
    "order_id":          ["orders"],
    "invoice_id":        ["invoices"],
    "subscription_id":   ["subscriptions"],
    "payment_id":        ["payments"],
    "transaction_id":    ["transactions"],
    "charge_id":         ["charges"],
    "session_id":        ["sessions"],
    "token_id":          ["tokens"],
    "key_id":            ["keys"],
    "credential_id":     ["credentials"],
    "secret_id":         ["secrets"],
    "ticket_id":         ["tickets"],
    "issue_id":          ["issues"],
    "comment_id":        ["comments"],
    "event_id":          ["events"],
    "webhook_id":        ["webhooks"],
    "integration_id":    ["integrations"],
}

# Regex that strips the ID suffix from a snake_case key name.
_ID_SUFFIX_STRIP_RE = re.compile(
    r'_(id|uuid|guid|token|key|ref|hash|code)$',
    re.IGNORECASE,
)


# ── Cross-object helpers ──────────────────────────────────────────────────────

def _derive_resource_names(key_name: str) -> list[str]:
    """
    Convert a key name like ``group_id`` to candidate REST resource
    path segments like ``['groups', 'group']``.

    Checks the explicit ``_KEY_TO_RESOURCE`` mapping first; falls back
    to stripping the ID suffix and applying simple English pluralisation.
    """
    if key_name in _KEY_TO_RESOURCE:
        return _KEY_TO_RESOURCE[key_name]

    base = _ID_SUFFIX_STRIP_RE.sub("", key_name).strip("_")
    if not base:
        return []

    # Simple pluralisation — covers the vast majority of REST resource names.
    # Use removesuffix() and single-char indexing to avoid slice false
    # positives from the linter's internal slice[int,int,int] representation.
    penultimate = base[-2] if len(base) >= 2 else ""
    if base.endswith("y") and penultimate not in "aeiou":
        plural = base.removesuffix("y") + "ies"   # company → companies
    elif base.endswith(("s", "sh", "ch", "x", "z")):
        plural = base + "es"                       # process → processes
    else:
        plural = base + "s"                        # user → users

    return [plural, base]


def _get_best_verified_combo(endpoint_id: int) -> dict:
    """
    Return the minimal verified combo info dict for *endpoint_id*, or
    an empty dict if no verified combo exists.

    Selects the combo with the fewest variables (``depth`` field in the
    stored JSON), using ``stability_score DESC`` as a tiebreaker.
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT combination_id, stability_score
              FROM candidate_access
             WHERE endpoint_id = ?
               AND is_verified  = 1
             ORDER BY stability_score DESC
            """,
            (endpoint_id,),
        ).fetchall()
    finally:
        conn.close()

    best_info: dict = {}
    best_depth = 999
    for row in rows:
        try:
            info  = json.loads(row["combination_id"])
            depth = info.get("depth", len(info.get("variable_ids", [])))
        except (json.JSONDecodeError, TypeError):
            continue
        if depth < best_depth:
            best_depth = depth
            best_info  = info

    return best_info


def _persist_graph_edge(edge: dict) -> None:
    """Upsert one edge into ``vulnerability_graph``, ignoring duplicates."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO vulnerability_graph
                (source_endpoint_id, source_key_id,
                 source_key_name, source_key_value,
                 target_url, target_status, baseline_status,
                 combo_key, relationship_type,
                 transition_type, finding_label)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_key_id, target_url, combo_key)
                DO NOTHING
            """,
            (
                edge["source_endpoint_id"],
                edge["source_key_id"],
                edge["source_key_name"],
                edge["source_key_value"],
                edge["target_url"],
                edge["target_status"],
                edge["baseline_status"],
                edge["combo_key"],
                edge["relationship_type"],
                edge["transition_type"],
                edge["finding_label"],
            ),
        )
        conn.commit()
    finally:
        conn.close()


def probe_cross_object_keys(
    endpoint_id: int | None = None,
) -> list[dict]:
    """
    Use referential keys extracted from one object to probe related
    objects, and flag successful cross-object bypasses as
    *High-Velocity Lateral Movement*.

    For every row in ``reference_keys`` (optionally scoped to one
    endpoint), the function:

    1. **Derives target resource names** from the key name using the
       explicit ``_KEY_TO_RESOURCE`` vocabulary plus generic English
       pluralisation (e.g. ``group_id`` → ``['groups', 'group']``).

    2. **Constructs target URLs** by combining the API prefix of the
       source endpoint with each derived resource name and the key value
       (e.g. ``https://api.example.com/api/v1/groups/abc123``).

    3. **Baseline probe** — clean GET with no bypass headers to
       establish whether the target is naturally gated.

    4. **Bypass replay** — applies the minimal verified combo from the
       source endpoint (fewest variables, best stability) to the target
       URL via :func:`bypasser.transitions._build_combo_request`.

    5. **Classifies the outcome** using the same thresholds as
       :func:`probe_lateral_access`; any positive transition is labelled
       ``'High-Velocity Lateral Movement'``.

    6. **Records every probe** (successful or not) in
       ``vulnerability_graph`` with the relationship type
       (e.g. ``'group_id → groups'``), status codes, and finding label.

    Parameters
    ----------
    endpoint_id : int | None
        Restrict probing to keys seeded from one endpoint.
        Pass ``None`` to process all rows in ``reference_keys``.

    Returns
    -------
    list[dict]
        One dict per High-Velocity Lateral Movement finding::

            {
                "source_endpoint_id": int,
                "source_key_id":      int,
                "source_key_name":    str,
                "source_key_value":   str,
                "target_url":         str,
                "target_status":      int,
                "baseline_status":    int,
                "combo_key":          str,
                "relationship_type":  str,   # e.g. 'group_id → groups'
                "transition_type":    str,
                "finding_label":      'High-Velocity Lateral Movement',
            }
    """
    # ── 1. Load reference keys ────────────────────────────────────────────
    conn = get_connection()
    try:
        if endpoint_id is not None:
            key_rows = conn.execute(
                """
                SELECT rk.id           AS key_id,
                       rk.endpoint_id  AS src_ep_id,
                       rk.key_name,
                       rk.key_value,
                       ep.url          AS source_url,
                       ep.method       AS source_method
                  FROM reference_keys rk
                  JOIN endpoints ep ON ep.id = rk.endpoint_id
                 WHERE rk.endpoint_id = ?
                 ORDER BY rk.endpoint_id, rk.id
                """,
                (endpoint_id,),
            ).fetchall()
        else:
            key_rows = conn.execute(
                """
                SELECT rk.id           AS key_id,
                       rk.endpoint_id  AS src_ep_id,
                       rk.key_name,
                       rk.key_value,
                       ep.url          AS source_url,
                       ep.method       AS source_method
                  FROM reference_keys rk
                  JOIN endpoints ep ON ep.id = rk.endpoint_id
                 ORDER BY rk.endpoint_id, rk.id
                """,
            ).fetchall()
    finally:
        conn.close()

    if not key_rows:
        logger.info(
            "[expansion] probe_cross_object_keys: no reference keys "
            "for endpoint_id=%s.",
            endpoint_id,
        )
        return []

    # Cache verified combos per source endpoint to avoid repeated DB queries.
    combo_cache: dict[int, dict] = {}

    findings:    list[dict]      = []
    # Dedup set: (source_key_id, target_url, combo_key)
    seen_probes: set[tuple]      = set()

    for key_row in key_rows:
        key_id        = key_row["key_id"]
        src_ep_id     = key_row["src_ep_id"]
        key_name      = key_row["key_name"]
        key_value     = key_row["key_value"]
        source_url    = key_row["source_url"]
        source_method = key_row["source_method"] or "GET"

        # ── 2. Resolve verified combo (cached per endpoint) ───────────────
        if src_ep_id not in combo_cache:
            combo_cache[src_ep_id] = _get_best_verified_combo(src_ep_id)

        combo_info = combo_cache[src_ep_id]
        if not combo_info:
            logger.debug(
                "[expansion] probe_cross_object_keys: no verified combo "
                "for endpoint %d — skipping key '%s'.",
                src_ep_id, key_name,
            )
            continue

        combo_key = combo_info.get("combo_key", "")
        var_ids   = combo_info.get("variable_ids", [])
        variables = _load_combo_variables(var_ids)
        if not variables:
            continue

        # ── 3. Derive target resources and construct URLs ─────────────────
        resource_names = _derive_resource_names(key_name)
        if not resource_names:
            continue

        # Extract API prefix from source URL (e.g. /api/v1)
        parsed_source = urlparse(source_url)
        src_parts     = _parse_path(parsed_source.path)
        api_prefix    = src_parts["prefix"]   # may be '' or '/api/v1'
        base_origin   = f"{parsed_source.scheme}://{parsed_source.netloc}"

        for resource_name in resource_names:
            # Build path: /api/v1/groups/abc123
            path_parts = [
                p for p in [api_prefix.strip("/"), resource_name, key_value]
                if p
            ]
            target_path = "/" + "/".join(path_parts)
            target_url  = base_origin + target_path
            relationship_type = f"{key_name} → {resource_name}"

            probe_key = (key_id, target_url, combo_key)
            if probe_key in seen_probes:
                continue
            seen_probes.add(probe_key)

            # ── 4. Baseline probe ─────────────────────────────────────────
            baseline_resp = _execute_request(
                "GET",
                target_url,
                {"User-Agent": USER_AGENT},
            )

            baseline_status  = baseline_resp["status"]
            baseline_length  = baseline_resp["length"]
            baseline_entropy = baseline_resp["entropy"]

            # Unreachable — record with empty labels and move on.
            if baseline_resp["error"] is not None or baseline_status < 0:
                _persist_graph_edge({
                    "source_endpoint_id": src_ep_id,
                    "source_key_id":      key_id,
                    "source_key_name":    key_name,
                    "source_key_value":   key_value,
                    "target_url":         target_url,
                    "target_status":      baseline_status,
                    "baseline_status":    baseline_status,
                    "combo_key":          combo_key,
                    "relationship_type":  relationship_type,
                    "transition_type":    "",
                    "finding_label":      "",
                })
                continue

            # Already publicly accessible — record relationship, skip bypass.
            if baseline_status == 200:
                _persist_graph_edge({
                    "source_endpoint_id": src_ep_id,
                    "source_key_id":      key_id,
                    "source_key_name":    key_name,
                    "source_key_value":   key_value,
                    "target_url":         target_url,
                    "target_status":      200,
                    "baseline_status":    200,
                    "combo_key":          combo_key,
                    "relationship_type":  relationship_type,
                    "transition_type":    "",
                    "finding_label":      "",
                })
                continue

            # ── 5. Bypass replay ──────────────────────────────────────────
            req = _build_combo_request(target_url, source_method, variables)
            probe_resp = _execute_request(
                req["method"],
                req["url"],
                req["headers"],
                req["primer_methods"],
            )

            probe_status  = probe_resp["status"]
            probe_length  = probe_resp["length"]
            probe_entropy = probe_resp["entropy"]

            # ── 6. Classify and persist ───────────────────────────────────
            transition = _classify_lateral_transition(
                baseline_status,  probe_status,
                baseline_length,  probe_length,
                baseline_entropy, probe_entropy,
            )

            finding_label = (
                "High-Velocity Lateral Movement" if transition else ""
            )

            edge = {
                "source_endpoint_id": src_ep_id,
                "source_key_id":      key_id,
                "source_key_name":    key_name,
                "source_key_value":   key_value,
                "target_url":         target_url,
                "target_status":      probe_status,
                "baseline_status":    baseline_status,
                "combo_key":          combo_key,
                "relationship_type":  relationship_type,
                "transition_type":    transition or "",
                "finding_label":      finding_label,
            }
            _persist_graph_edge(edge)

            if transition:
                findings.append(edge)
                logger.info(
                    "  [HVLM] %-45s  %s  (%s=%s)",
                    target_url, transition, key_name, key_value,
                )

    logger.info(
        "[expansion] probe_cross_object_keys: %d key(s) evaluated, "
        "%d High-Velocity Lateral Movement finding(s).",
        len(key_rows), len(findings),
    )
    return findings


# ── Systemic impact helpers ───────────────────────────────────────────────────

def _classify_severity(
    bypass_rate:         float,
    candidates_bypassed: int,
    hvlm_findings:       int,
) -> tuple[str, int]:
    """
    Return *(severity_label, collapse_flag)* for an endpoint's probe results.

    Tiers
    -----
    Critical: Global Authorization Collapse
        bypass_rate = 100 % AND ≥ 5 endpoints bypassed  — the '5/5' case
        OR bypass_rate ≥ 90 % AND total exposure ≥ 5    — near-perfect + HVLM
    High: Widespread Authorization Failure
        bypass_rate ≥ 70 %  OR  (bypassed ≥ 3 AND HVLM ≥ 1)
    Medium: Partial Authorization Weakness
        bypass_rate ≥ 40 %  OR  bypassed ≥ 2
    Low: Isolated Authorization Gap
        any single bypass or HVLM finding
    Informational: No Bypass Detected
        no evidence of unauthorized access
    """
    total_exposure = candidates_bypassed + hvlm_findings

    # Critical path — exact 5/5 (or more) scenario
    if bypass_rate >= 1.0 and candidates_bypassed >= 5:
        return "Critical: Global Authorization Collapse", 1

    # Critical path — near-perfect bypass reinforced by cross-object HVLM
    if bypass_rate >= 0.9 and total_exposure >= 5:
        return "Critical: Global Authorization Collapse", 1

    if bypass_rate >= 0.7 or (candidates_bypassed >= 3 and hvlm_findings >= 1):
        return "High: Widespread Authorization Failure", 0

    if bypass_rate >= 0.4 or candidates_bypassed >= 2:
        return "Medium: Partial Authorization Weakness", 0

    if candidates_bypassed >= 1 or hvlm_findings >= 1:
        return "Low: Isolated Authorization Gap", 0

    return "Informational: No Bypass Detected", 0


def _persist_impact_report(report: dict) -> None:
    """Upsert one systemic impact report row."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO systemic_impact_report
                (source_endpoint_id, source_url,
                 candidates_generated, candidates_probed,
                 candidates_bypassed, bypass_rate,
                 hvlm_findings, unique_resources_exposed,
                 total_systemic_exposure, severity_label,
                 collapse_flag)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_endpoint_id) DO UPDATE SET
                candidates_generated     = excluded.candidates_generated,
                candidates_probed        = excluded.candidates_probed,
                candidates_bypassed      = excluded.candidates_bypassed,
                bypass_rate              = excluded.bypass_rate,
                hvlm_findings            = excluded.hvlm_findings,
                unique_resources_exposed = excluded.unique_resources_exposed,
                total_systemic_exposure  = excluded.total_systemic_exposure,
                severity_label           = excluded.severity_label,
                collapse_flag            = excluded.collapse_flag
            """,
            (
                report["source_endpoint_id"],
                report["source_url"],
                report["candidates_generated"],
                report["candidates_probed"],
                report["candidates_bypassed"],
                report["bypass_rate"],
                report["hvlm_findings"],
                report["unique_resources_exposed"],
                report["total_systemic_exposure"],
                report["severity_label"],
                report["collapse_flag"],
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _print_impact_report(reports: list[dict]) -> None:
    """Render a formatted Systemic Impact Assessment to stdout."""
    W = 72
    SEP  = "=" * W
    DASH = "─" * W

    print(f"\n{SEP}")
    print("  SYSTEMIC IMPACT ASSESSMENT")
    print(SEP)

    if not reports:
        print("  No impact data — run probe_lateral_access() first.")
        print(SEP)
        return

    # Pre-compute totals with sum() — avoids augmented-assignment type
    # inference issues in linters that cannot track dict-value types.
    total_collapse: int = sum(1 for r in reports if r["collapse_flag"])
    total_exposure: int = sum(r["total_systemic_exposure"] for r in reports)

    for r in reports:
        rate_pct = r["bypass_rate"] * 100
        bypassed = r["candidates_bypassed"]
        probed   = r["candidates_probed"]
        exposure = r["total_systemic_exposure"]
        severity = r["severity_label"]
        collapse = r["collapse_flag"]

        flag = "  *** GLOBAL AUTHORIZATION COLLAPSE ***" if collapse else ""

        print(f"  Endpoint  : {r['source_url']}")
        print(
            f"  J2→J3     : {bypassed}/{probed} candidates bypassed"
            f"  ({rate_pct:.0f}% success rate)"
        )
        print(f"  HVLM      : {r['hvlm_findings']} cross-object key finding(s)")
        print(
            f"  Resources : {r['unique_resources_exposed']}"
            f" unique resource type(s) exposed"
        )
        print(
            f"  Exposure  : {exposure} total unauthorized"
            f" path(s) reachable"
        )
        print(f"  Severity  : {severity}{flag}")
        print(DASH)

    print(
        f"  Total Systemic Exposure : {total_exposure} path(s)"
        f" across {len(reports)} endpoint(s)"
    )
    if total_collapse:
        print(
            f"\n  !!! {total_collapse} endpoint(s) — "
            f"CRITICAL: GLOBAL AUTHORIZATION COLLAPSE !!!"
        )
    print(f"{SEP}\n")


def calculate_systemic_impact(
    source_endpoint_id: int | None = None,
) -> list[dict]:
    """
    Aggregate J2 (candidate generation) and J3 (bypass probe) statistics
    for each source endpoint and compute the *Total Systemic Exposure*.

    Metrics collected per source endpoint
    --------------------------------------
    candidates_generated     — rows in ``candidate_endpoints``
    candidates_probed        — candidates with status ``'probed'``
                               or ``'bypassed'``
    candidates_bypassed      — candidates with status ``'bypassed'``
    bypass_rate              — bypassed / probed  (0.0 – 1.0)
    hvlm_findings            — rows in ``vulnerability_graph`` labelled
                               ``'High-Velocity Lateral Movement'``
    unique_resources_exposed — distinct ``neighbor_segment`` values in
                               bypassed ``candidate_endpoints``
    total_systemic_exposure  — candidates_bypassed + hvlm_findings

    Severity tiers
    --------------
    Critical: Global Authorization Collapse
        100 % bypass rate AND ≥ 5 endpoints bypassed  (the '5/5' case),
        OR ≥ 90 % bypass rate AND total exposure ≥ 5.
    High: Widespread Authorization Failure
        bypass_rate ≥ 70 % OR (bypassed ≥ 3 AND HVLM ≥ 1).
    Medium: Partial Authorization Weakness
        bypass_rate ≥ 40 % OR bypassed ≥ 2.
    Low: Isolated Authorization Gap
        any single bypass or HVLM finding.
    Informational: No Bypass Detected

    Results are persisted to ``systemic_impact_report`` (upserted on
    ``source_endpoint_id``) and printed as a formatted console report.

    Parameters
    ----------
    source_endpoint_id : int | None
        Scope the calculation to one source endpoint.  Pass ``None``
        to evaluate every endpoint that has generated candidates.

    Returns
    -------
    list[dict]
        One dict per source endpoint::

            {
                "source_endpoint_id":       int,
                "source_url":               str,
                "candidates_generated":     int,
                "candidates_probed":        int,
                "candidates_bypassed":      int,
                "bypass_rate":              float,
                "hvlm_findings":            int,
                "unique_resources_exposed": int,
                "total_systemic_exposure":  int,
                "severity_label":           str,
                "collapse_flag":            int,  # 1 = Global Auth Collapse
            }
    """
    # ── 1. Resolve which source endpoints to evaluate ─────────────────────
    conn = get_connection()
    try:
        if source_endpoint_id is not None:
            ep_rows = conn.execute(
                """
                SELECT DISTINCT ep.id, ep.url
                  FROM endpoints ep
                  JOIN candidate_endpoints ce
                    ON ce.source_endpoint_id = ep.id
                 WHERE ep.id = ?
                """,
                (source_endpoint_id,),
            ).fetchall()
        else:
            ep_rows = conn.execute(
                """
                SELECT DISTINCT ep.id, ep.url
                  FROM endpoints ep
                  JOIN candidate_endpoints ce
                    ON ce.source_endpoint_id = ep.id
                 ORDER BY ep.id
                """,
            ).fetchall()
    finally:
        conn.close()

    if not ep_rows:
        logger.info(
            "[expansion] calculate_systemic_impact: no candidate data "
            "for source_endpoint_id=%s — run map_related_endpoints first.",
            source_endpoint_id,
        )
        _print_impact_report([])
        return []

    reports: list[dict] = []

    for ep_row in ep_rows:
        ep_id  = ep_row["id"]
        ep_url = ep_row["url"]

        # ── 2. Gather candidate_endpoints stats ───────────────────────────
        conn = get_connection()
        try:
            stats = conn.execute(
                """
                SELECT
                    COUNT(*)                                          AS generated,
                    SUM(CASE WHEN status IN ('probed','bypassed')
                             THEN 1 ELSE 0 END)                      AS probed,
                    SUM(CASE WHEN status = 'bypassed'
                             THEN 1 ELSE 0 END)                      AS bypassed,
                    COUNT(DISTINCT CASE WHEN status = 'bypassed'
                             THEN neighbor_segment END)               AS unique_res
                  FROM candidate_endpoints
                 WHERE source_endpoint_id = ?
                """,
                (ep_id,),
            ).fetchone()

            # HVLM findings from probe_cross_object_keys
            hvlm_row = conn.execute(
                """
                SELECT COUNT(*) AS count
                  FROM vulnerability_graph
                 WHERE source_endpoint_id = ?
                   AND finding_label = 'High-Velocity Lateral Movement'
                """,
                (ep_id,),
            ).fetchone()
        finally:
            conn.close()

        candidates_generated     = stats["generated"]     or 0
        candidates_probed        = stats["probed"]        or 0
        candidates_bypassed      = stats["bypassed"]      or 0
        unique_resources_exposed = stats["unique_res"]    or 0
        hvlm_findings            = hvlm_row["count"]      or 0

        bypass_rate = (
            candidates_bypassed / candidates_probed
            if candidates_probed > 0 else 0.0
        )
        total_systemic_exposure = candidates_bypassed + hvlm_findings

        # ── 3. Classify severity ──────────────────────────────────────────
        severity_label, collapse_flag = _classify_severity(
            bypass_rate,
            candidates_bypassed,
            hvlm_findings,
        )

        report: dict = {
            "source_endpoint_id":       ep_id,
            "source_url":               ep_url,
            "candidates_generated":     candidates_generated,
            "candidates_probed":        candidates_probed,
            "candidates_bypassed":      candidates_bypassed,
            "bypass_rate":              round(bypass_rate, 4),
            "hvlm_findings":            hvlm_findings,
            "unique_resources_exposed": unique_resources_exposed,
            "total_systemic_exposure":  total_systemic_exposure,
            "severity_label":           severity_label,
            "collapse_flag":            collapse_flag,
        }
        reports.append(report)
        _persist_impact_report(report)

        logger.info(
            "[expansion] impact: ep=%d  %d/%d bypassed (%.0f%%)  "
            "exposure=%d  %s",
            ep_id,
            candidates_bypassed, candidates_probed,
            bypass_rate * 100,
            total_systemic_exposure,
            severity_label,
        )

    # ── 4. Print formatted console report ────────────────────────────────
    _print_impact_report(reports)
    return reports
