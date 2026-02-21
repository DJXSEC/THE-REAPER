"""
Single-variable probing engine for Arbiter-403.

Compares a **mutated** request (with exactly one policy variable
changed) against the stored baseline fingerprint for an endpoint.
Returns a structured *Diff Object* that downstream analysis can use
to decide whether the mutation altered the server's 403 behaviour.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from collections import Counter
from urllib.parse import urlparse, urlunparse

import requests

from bypasser.baseline import calculate_entropy, USER_AGENT
from bypasser.db import get_connection

logger = logging.getLogger(__name__)


# ── Category → mutation strategy ────────────────────────────────────
#
#  Each variable category is applied differently:
#
#    Header-based   →  inject an extra HTTP header.
#    Protocol       →  flip the URL scheme (http ↔ https).
#    User-Agent     →  replace the User-Agent header.
#    Referer        →  add a Referer header.
#    Object ID      →  substitute the numeric path segment.
#    Method Seq     →  send a primer request first, then the real one.
#
# Categories whose name starts with these prefixes are header-based:
_HEADER_CATEGORIES = {"Internal-Only", "Proxy", "Identity"}

# Variable names that carry an explicit target header (e.g. Identity
# stubs have a separate "header" column in the in-memory dict, but in
# the DB we only store name/category/test_value).  We infer the
# header from the variable name when needed.
_IDENTITY_HEADER_MAP: dict[str, str] = {
    "Identity-Bearer-Junk":          "Authorization",
    "Identity-Bearer-Empty":         "Authorization",
    "Identity-Basic-Admin":          "Authorization",
    "Identity-Cookie-UserID":        "Cookie",
    "Identity-Cookie-Session":       "Cookie",
    "Identity-Cookie-IsAdmin":       "Cookie",
    "Identity-X-Authenticated-User": "X-Authenticated-User",
    "Identity-X-Auth-Token":         "X-Auth-Token",
    "Identity-X-API-Key":            "X-API-Key",
    "Identity-X-SAML-Token":         "X-SAML-Token",
}

# Regex to locate a numeric path segment for Object ID substitution.
_NUMERIC_SEG_RE = re.compile(r"(?<=/)\d+(?=/|$)")

# Regex to extract HTML / XML tag names from a response body.
_TAG_RE = re.compile(r"</?([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>")

# Structural divergence threshold — if the tag-count difference
# exceeds this fraction, the body is considered structurally changed.
_STRUCTURE_THRESHOLD = 0.10   # 10 %


# ═══════════════════════════════════════════════════════════════════════
#  Public API
# ═══════════════════════════════════════════════════════════════════════

def probe_variable(endpoint_id: int, variable_id: int) -> dict:
    """
    Apply **exactly one** policy-variable mutation to a request and
    return a diff against the stored baseline.

    Parameters
    ----------
    endpoint_id : int
        Row id in the ``endpoints`` table.  The row supplies the
        target URL, HTTP method, and the three baseline truth values
        (``status_code``, ``body_length``, ``header_hash``).
    variable_id : int
        Row id in the ``policy_variables`` table.  The row supplies
        the mutation name, category, and test value.

    Returns
    -------
    dict
        A *Diff Object* with the following keys::

            {
                "endpoint_id":          int,
                "variable_id":          int,
                "variable_name":        str,
                "variable_category":    str,
                "test_value":           str,

                # ── Baseline truth ──────────────────────────────────
                "baseline_status":      int,
                "baseline_body_length": int,
                "baseline_header_hash": str,

                # ── Mutated response ────────────────────────────────
                "mutated_status":       int,
                "mutated_body_length":  int,
                "mutated_header_hash":  str,
                "mutated_entropy":      float,
                "response_time_ms":     float,

                # ── Diff flags ──────────────────────────────────────
                "status_changed":       bool,
                "length_changed":       bool,
                "headers_changed":      bool,
                "is_interesting":       bool,   # any flag True
                "length_delta":         int,    # signed byte difference

                # ── Metadata ────────────────────────────────────────
                "error":                str | None,
            }

    Raises
    ------
    ValueError
        If either *endpoint_id* or *variable_id* does not exist in
        the database.
    """
    conn = get_connection()
    try:
        # ── 1.  Fetch baseline truth ───────────────────────────────
        ep = conn.execute(
            """
            SELECT id, url, method, status_code, body_length,
                   header_hash, fingerprint_group_id
              FROM endpoints
             WHERE id = ?
            """,
            (endpoint_id,),
        ).fetchone()

        if ep is None:
            raise ValueError(
                f"endpoint_id {endpoint_id} not found in the endpoints table."
            )

        # ── 1b. Fetch the baseline body for structural comparison ──
        baseline_body: str = ""
        fp_group_id = ep["fingerprint_group_id"]
        if fp_group_id:
            body_row = conn.execute(
                "SELECT canonical_body FROM fingerprint_groups WHERE group_id = ?",
                (fp_group_id,),
            ).fetchone()
            if body_row:
                baseline_body = body_row["canonical_body"]

        # ── 2.  Fetch the variable ─────────────────────────────────
        var = conn.execute(
            """
            SELECT id, name, category, test_value
              FROM policy_variables
             WHERE id = ?
            """,
            (variable_id,),
        ).fetchone()

        if var is None:
            raise ValueError(
                f"variable_id {variable_id} not found in the "
                f"policy_variables table."
            )
    finally:
        conn.close()

    url: str        = ep["url"]
    method: str     = ep["method"]
    var_name: str   = var["name"]
    category: str   = var["category"]
    test_value: str = var["test_value"]

    baseline_status: int = ep["status_code"]
    baseline_length: int = ep["body_length"]
    baseline_hash: str   = ep["header_hash"]

    # ── 3.  Build the mutated request spec ──────────────────────────
    mutated_url    = url
    mutated_method = method
    mutated_headers: dict[str, str] = {"User-Agent": USER_AGENT}
    primer_methods: list[str] | None = None

    if category in _HEADER_CATEGORIES:
        header_name = _resolve_header_name(var_name, category)
        mutated_headers[header_name] = test_value

    elif category == "Protocol":
        mutated_url = _apply_protocol(url, test_value)

    elif category == "User-Agent":
        mutated_headers["User-Agent"] = test_value   # overwrite default

    elif category == "Referer":
        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        mutated_headers["Referer"] = test_value.replace("{origin}", origin)

    elif category == "Object ID":
        mutated_url = _substitute_object_id(url, test_value)

    elif category == "Method Sequence":
        # test_value is e.g. "POST,GET" — the first element is the
        # primer, the last element is the actual request method.
        parts = [m.strip() for m in test_value.split(",")]
        primer_methods = parts[:-1]
        mutated_method = parts[-1]

    else:
        logger.warning(
            "[probe] Unknown category '%s' for variable '%s'; "
            "sending request unmodified.",
            category, var_name,
        )

    # ── 4.  Initial mutated request ────────────────────────────────
    m1 = _execute_request(
        mutated_method, mutated_url, mutated_headers, primer_methods,
    )

    # ── 5.  Structural comparison ──────────────────────────────────
    baseline_tags = _tag_fingerprint(baseline_body)
    mutated_tags  = _tag_fingerprint(m1["body"])
    structure_pct = _structural_diff(baseline_tags, mutated_tags)
    structure_changed = structure_pct > _STRUCTURE_THRESHOLD

    # ── 6.  Compute diff flags ─────────────────────────────────────
    status_changed  = m1["status"] != baseline_status
    length_changed  = m1["length"] != baseline_length
    headers_changed = m1["hash"]   != baseline_hash
    length_delta    = m1["length"]  - baseline_length

    initial_change = (
        status_changed or length_changed
        or headers_changed or structure_changed
    )

    # ── 7.  Re-verification gate ───────────────────────────────────
    #
    #    If any change was detected, do NOT record it yet.  Instead:
    #      a)  Re-send the **baseline** request (clean, no mutation)
    #          to confirm the server hasn't started rate-limiting or
    #          shifted state.
    #      b)  Re-send the **mutated** request to confirm the
    #          variable is genuinely responsible for the difference.
    #
    #    Only if both re-checks are consistent is the finding marked
    #    reproducible.  Otherwise it is logged as *Transient Noise*.
    #
    reproducible = False
    is_policy_relevant = False

    if initial_change and m1["error"] is None:
        # (a) Baseline re-check ──────────────────────────────────
        b_recheck = _execute_request(method, url, {"User-Agent": USER_AGENT})

        baseline_stable = (
            b_recheck["status"] == baseline_status
            and b_recheck["length"] == baseline_length
        )

        # (b) Mutated re-check ───────────────────────────────────
        m2 = _execute_request(
            mutated_method, mutated_url, mutated_headers, primer_methods,
        )

        mutated_consistent = (
            m2["status"] == m1["status"]
            and m2["length"] == m1["length"]
            and m2["hash"]   == m1["hash"]
        )

        if baseline_stable and mutated_consistent:
            reproducible = True
            is_policy_relevant = True
            logger.info(
                "  [VERIFIED] %-30s  Δstatus=%s→%s  Δlen=%+d  "
                "struct=%.1f%%  reproducible=True",
                var_name, baseline_status, m1["status"],
                length_delta, structure_pct * 100,
            )
        else:
            # Transient Noise — server state drifted or result
            # was not repeatable.
            reproducible = False
            is_policy_relevant = False
            logger.info(
                "  [TRANSIENT NOISE] %-22s  baseline_stable=%s  "
                "mutated_consistent=%s  — discarded",
                var_name, baseline_stable, mutated_consistent,
            )

    elif m1["error"] is not None:
        # Network error on the initial request — can't verify.
        is_policy_relevant = False
        reproducible = False

    # ── 8.  Persist to sensitivity_results ─────────────────────────
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO sensitivity_results
                (endpoint_id, variable_id, is_policy_relevant,
                 status_diff, length_delta, headers_diff,
                 structure_diff, reproducible)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(endpoint_id, variable_id) DO UPDATE SET
                is_policy_relevant = excluded.is_policy_relevant,
                status_diff        = excluded.status_diff,
                length_delta       = excluded.length_delta,
                headers_diff       = excluded.headers_diff,
                structure_diff     = excluded.structure_diff,
                reproducible       = excluded.reproducible
            """,
            (
                endpoint_id,
                variable_id,
                int(is_policy_relevant),
                int(status_changed),
                length_delta,
                int(headers_changed),
                round(structure_pct, 4),
                int(reproducible),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    # ── 9.  Return the diff object ─────────────────────────────────
    return {
        # Identifiers
        "endpoint_id":          endpoint_id,
        "variable_id":          variable_id,
        "variable_name":        var_name,
        "variable_category":    category,
        "test_value":           test_value,

        # Baseline truth
        "baseline_status":      baseline_status,
        "baseline_body_length": baseline_length,
        "baseline_header_hash": baseline_hash,

        # Mutated response
        "mutated_status":       m1["status"],
        "mutated_body_length":  m1["length"],
        "mutated_header_hash":  m1["hash"],
        "mutated_entropy":      m1["entropy"],
        "response_time_ms":     m1["time_ms"],

        # Diff flags
        "status_changed":       status_changed,
        "length_changed":       length_changed,
        "headers_changed":      headers_changed,
        "structure_changed":    structure_changed,
        "structure_pct":        round(structure_pct, 4),
        "is_interesting":       is_policy_relevant,
        "reproducible":         reproducible,
        "length_delta":         length_delta,

        # Metadata
        "error":                m1["error"],
    }


# ═══════════════════════════════════════════════════════════════════════
#  Collapsing loop — single-variable sweep
# ═══════════════════════════════════════════════════════════════════════

def collapse_variables(endpoint_id: int) -> dict:
    """
    Probe **every** active policy variable for a single endpoint,
    freezing any variable that produces no observable change.

    Algorithm
    ---------
    1. Fetch all ``is_active = 1`` rows from ``policy_variables``.
    2. Skip any that have already been tested for this endpoint
       (i.e. a row exists in ``sensitivity_results``).
    3. For each untested variable, call :func:`probe_variable`.
    4. Variables where ``is_policy_relevant = 0`` are automatically
       recorded as frozen in ``sensitivity_results`` by
       :func:`probe_variable`.
    5. Return a summary dict with the live/frozen counts and the
       full list of live diff objects.

    Parameters
    ----------
    endpoint_id : int
        Row id in the ``endpoints`` table.

    Returns
    -------
    dict
        ::

            {
                "endpoint_id":    int,
                "total_tested":   int,   # variables probed this run
                "total_skipped":  int,   # already tested previously
                "live_count":     int,   # variables that caused a diff
                "frozen_count":   int,   # variables with no change
                "live_diffs":     list[dict],   # diff objects for live vars
                "frozen_names":   list[str],    # names of frozen vars
            }
    """
    conn = get_connection()
    try:
        # All active variables
        all_vars = conn.execute(
            """
            SELECT id, name
              FROM policy_variables
             WHERE is_active = 1
             ORDER BY id
            """
        ).fetchall()

        # Already-tested variable IDs for this endpoint
        already_tested = {
            row["variable_id"]
            for row in conn.execute(
                """
                SELECT variable_id
                  FROM sensitivity_results
                 WHERE endpoint_id = ?
                """,
                (endpoint_id,),
            ).fetchall()
        }
    finally:
        conn.close()

    # ── Probe untested variables ───────────────────────────────────
    live_diffs: list[dict]  = []
    frozen_names: list[str] = []
    skipped = 0
    tested  = 0

    for var_row in all_vars:
        var_id   = var_row["id"]
        var_name = var_row["name"]

        if var_id in already_tested:
            skipped += 1
            continue

        # Single-variable probe (auto-logged to sensitivity_results)
        diff = probe_variable(endpoint_id, var_id)
        tested += 1

        if diff["is_interesting"]:
            live_diffs.append(diff)
            logger.info(
                "  [LIVE]   %-35s  status=%s→%s  Δlen=%+d",
                var_name,
                diff["baseline_status"],
                diff["mutated_status"],
                diff["length_delta"],
            )
        else:
            frozen_names.append(var_name)
            logger.info("  [FROZEN] %-35s  no change", var_name)

    return {
        "endpoint_id":   endpoint_id,
        "total_tested":  tested,
        "total_skipped": skipped,
        "live_count":    len(live_diffs),
        "frozen_count":  len(frozen_names),
        "live_diffs":    live_diffs,
        "frozen_names":  frozen_names,
    }


def get_live_variables(endpoint_id: int) -> list[dict]:
    """
    Return the policy variables that are still **live** for
    *endpoint_id* — i.e. those that caused an observable diff and
    have not been frozen by :func:`collapse_variables`.

    A variable is live when its ``sensitivity_results`` row has
    ``is_policy_relevant = 1``.  Variables with no row at all
    (not yet tested) are also included so they can be tested in a
    later pass.

    Returns
    -------
    list[dict]
        Each dict has keys ``id``, ``name``, ``category``,
        ``test_value``, and ``status`` (``'live'`` or ``'untested'``).
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT pv.id,
                   pv.name,
                   pv.category,
                   pv.test_value,
                   sr.is_policy_relevant
              FROM policy_variables pv
              LEFT JOIN sensitivity_results sr
                ON sr.variable_id = pv.id
               AND sr.endpoint_id = ?
             WHERE pv.is_active = 1
               AND (sr.is_policy_relevant IS NULL      -- untested
                    OR sr.is_policy_relevant = 1)       -- live
             ORDER BY pv.id
            """,
            (endpoint_id,),
        ).fetchall()

        return [
            {
                "id":         r["id"],
                "name":       r["name"],
                "category":   r["category"],
                "test_value": r["test_value"],
                "status":     "live" if r["is_policy_relevant"] == 1 else "untested",
            }
            for r in rows
        ]
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════
#  Internal helpers
# ═══════════════════════════════════════════════════════════════════════

def _execute_request(
    method: str,
    url: str,
    headers: dict[str, str],
    primer_methods: list[str] | None = None,
) -> dict:
    """
    Send an HTTP request and return a standardised response dict.

    Parameters
    ----------
    method : str
        HTTP method for the main request.
    url : str
        Target URL.
    headers : dict
        HTTP headers to send.
    primer_methods : list[str] | None
        Optional list of HTTP methods to send *before* the main
        request (used by Method Sequence variables).

    Returns
    -------
    dict
        ``{"status", "length", "hash", "entropy", "body",
          "time_ms", "error"}``
    """
    try:
        session = requests.Session()

        # Primer requests (Method Sequence only)
        if primer_methods:
            for pm in primer_methods:
                session.request(
                    pm, url,
                    headers=headers,
                    allow_redirects=False,
                )

        t0 = time.perf_counter()
        response = session.request(
            method, url,
            headers=headers,
            allow_redirects=False,
        )
        elapsed = round((time.perf_counter() - t0) * 1000, 2)

        # Deterministic header hash (same algorithm as baseline)
        sorted_hdrs = sorted(
            response.headers.items(), key=lambda h: h[0].lower()
        )
        hdr_string = "\n".join(f"{n}: {v}" for n, v in sorted_hdrs)
        hdr_hash = hashlib.sha256(hdr_string.encode("utf-8")).hexdigest()

        return {
            "status":  response.status_code,
            "length":  len(response.content),
            "hash":    hdr_hash,
            "entropy": calculate_entropy(response.text),
            "body":    response.text,
            "time_ms": elapsed,
            "error":   None,
        }

    except requests.RequestException as exc:
        return {
            "status":  -1,
            "length":  0,
            "hash":    "",
            "entropy": 0.0,
            "body":    "",
            "time_ms": 0.0,
            "error":   str(exc),
        }

def _tag_fingerprint(html: str) -> Counter:
    """
    Build a :class:`Counter` of HTML/XML tag names in *html*.

    Only tag names are counted (e.g. ``div``, ``p``, ``input``);
    attributes and content are ignored.  This gives a lightweight
    structural fingerprint that is resilient to whitespace / text
    changes but sensitive to layout shifts (different error pages,
    CAPTCHA injection, hidden fields).
    """
    return Counter(tag.lower() for tag in _TAG_RE.findall(html))


def _structural_diff(
    baseline: Counter, mutated: Counter
) -> float:
    """
    Compute the structural divergence between two tag fingerprints
    as a fraction in ``[0.0, 1.0]``.

    The metric is the **symmetric difference** of tag counts divided
    by the **total** tag count across both fingerprints::

        diff = Σ |baseline[t] - mutated[t]|  /  (Σ baseline + Σ mutated)

    Returns ``0.0`` when both fingerprints are identical or both are
    empty.  Returns ``1.0`` when they share no tags at all.
    """
    all_tags = set(baseline) | set(mutated)
    if not all_tags:
        return 0.0

    total = sum(baseline.values()) + sum(mutated.values())
    if total == 0:
        return 0.0

    delta = sum(abs(baseline.get(t, 0) - mutated.get(t, 0)) for t in all_tags)
    return delta / total

def _resolve_header_name(var_name: str, category: str) -> str:
    """
    Determine which HTTP header to inject for a given variable.

    * **Identity** variables use a lookup table keyed on the
      variable name.
    * **Internal-Only** and **Proxy** variables use the variable
      name directly as the header name (e.g. ``X-Forwarded-For``).
    """
    if category == "Identity":
        return _IDENTITY_HEADER_MAP.get(var_name, var_name)
    return var_name


def _apply_protocol(url: str, scheme: str) -> str:
    """Replace the URL scheme with *scheme* (``http`` or ``https``)."""
    parts = urlparse(url)
    return urlunparse(parts._replace(scheme=scheme))


def _substitute_object_id(url: str, new_id: str) -> str:
    """
    Replace the **first** numeric path segment in *url* with *new_id*.

    If no numeric segment is found the URL is returned unchanged.
    """
    parts = urlparse(url)
    new_path = _NUMERIC_SEG_RE.sub(new_id, parts.path, count=1)
    return urlunparse(parts._replace(path=new_path))
