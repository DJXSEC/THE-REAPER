"""
Variable-combination engine for Arbiter-403  (Section E).

Generates **minimal, bounded** multi-variable test plans from the
reproducible single-variable sensitivities discovered in Section D,
then executes each combination and classifies the observed transitions.

Design constraints
------------------
* **Max depth = 3** — combinations are limited to pairs and triplets
  to prevent combinatorial explosion and maintain probing stealth.
* **Input** — only variables with ``is_policy_relevant = 1`` *and*
  ``reproducible = 1`` in ``sensitivity_results`` are eligible.
* **Transition types** detected:
  - **Status Transition** — 403 → 401 / 404 / 200 / etc.
  - **Content Transition** — status stays 403 but body entropy or
    length increases significantly ("Partial Data").
"""

from __future__ import annotations

import json
import logging
import re
from itertools import combinations
from urllib.parse import urlparse

from bypasser.baseline import calculate_entropy, USER_AGENT
from bypasser.db import get_connection
from bypasser.probing import (
    _execute_request,
    _resolve_header_name,
    _apply_protocol,
    _substitute_object_id,
    _HEADER_CATEGORIES,
)

logger = logging.getLogger(__name__)

# Upper bound on how many variables may be combined in a single test.
_MAX_COMBO_DEPTH = 3

# Content Transition thresholds — if body length jumps by more than
# this factor OR entropy increases by more than this absolute delta,
# we flag a Content Transition even when the status stays 403.
_LENGTH_GROWTH_FACTOR = 1.5    # 50 % larger
_ENTROPY_DELTA        = 1.0    # Shannon bits

# ── False-Win validation constants ──────────────────────────────────────

# Login/auth paths that indicate a redirect rather than genuine access.
_LOGIN_PATH_RE = re.compile(
    r"/login|/signin|/sign-in|/auth(?:enticate)?|/sso",
    re.IGNORECASE,
)

# HTML meta-refresh: <meta http-equiv="refresh" content="0; url=/login">
_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']refresh["\'][^>]*'
    r'content=["\'][^"\']*url=([^"\'>\s]+)',
    re.IGNORECASE,
)

# JS redirect: window.location = "/login" or window.location.href = "/login"
_JS_REDIRECT_RE = re.compile(
    r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Denial phrases that may appear in a 200-wrapped denial page.
_DENIAL_KEYWORDS: list[str] = [
    "access denied",
    "forbidden",
    "unauthorized",
    "please log in to continue",
    "login required",
    "authentication required",
    "not authorized",
    "permission denied",
]

# Body length must differ from the baseline 403 by more than this fraction
# to be considered genuine content; otherwise it is treated as a false positive.
_LENGTH_SIMILARITY_THRESHOLD = 0.10   # ±10 % of baseline length


# ═══════════════════════════════════════════════════════════════════════
#  E1 — Combination generator
# ═══════════════════════════════════════════════════════════════════════

def generate_minimal_combinations(endpoint_id: int) -> list[dict]:
    """
    Build a de-duplicated list of variable combinations to test for
    *endpoint_id*.

    Algorithm
    ---------
    1. Query ``sensitivity_results`` for all variables where
       ``is_policy_relevant = 1`` AND ``reproducible = 1``.
    2. Join with ``policy_variables`` to get names / categories /
       test values.
    3. Generate all unique **pairs** (C(n,2)), then all unique
       **triplets** (C(n,3)), capped at ``_MAX_COMBO_DEPTH``.
    4. Filter out redundant combos — e.g. two variables that target
       the same header are collapsed into the later-ID variable.
    5. Return an ordered list of combination dicts.

    Parameters
    ----------
    endpoint_id : int
        Row id in the ``endpoints`` table.

    Returns
    -------
    list[dict]
        Each dict has::

            {
                "endpoint_id":   int,
                "combo_depth":   int,          # 2 or 3
                "variable_ids":  tuple[int, ...],
                "variables":     list[dict],    # id/name/category/test_value
                "combo_key":     str,           # stable sort key
            }

        The list is ordered by ``combo_depth`` (pairs first), then
        alphabetically by ``combo_key``.
    """
    # ── 1.  Fetch reproducible, policy-relevant variables ──────────
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT pv.id,
                   pv.name,
                   pv.category,
                   pv.test_value,
                   sr.status_diff,
                   sr.length_delta,
                   sr.headers_diff,
                   sr.structure_diff
              FROM sensitivity_results sr
              JOIN policy_variables pv
                ON pv.id = sr.variable_id
             WHERE sr.endpoint_id     = ?
               AND sr.is_policy_relevant = 1
               AND sr.reproducible       = 1
             ORDER BY pv.id
            """,
            (endpoint_id,),
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        logger.info(
            "[combos] endpoint %d: no reproducible variables — "
            "nothing to combine.", endpoint_id,
        )
        return []

    # Materialise into a list of lightweight dicts.
    live_vars: list[dict] = [
        {
            "id":           r["id"],
            "name":         r["name"],
            "category":     r["category"],
            "test_value":   r["test_value"],
        }
        for r in rows
    ]

    logger.info(
        "[combos] endpoint %d: %d live variable(s) → generating combos "
        "(max depth %d).",
        endpoint_id, len(live_vars), _MAX_COMBO_DEPTH,
    )

    # ── 2.  Generate pair + triplet combinations ───────────────────
    combos: list[dict] = []

    for depth in range(2, _MAX_COMBO_DEPTH + 1):
        if len(live_vars) < depth:
            continue

        for group in combinations(live_vars, depth):
            categories = [v["category"] for v in group]
            if len(categories) != len(set(categories)):
                continue

            var_ids = tuple(v["id"] for v in group)
            combo_key = "+".join(v["name"] for v in group)

            combos.append({
                "endpoint_id":  endpoint_id,
                "combo_depth":  depth,
                "variable_ids": var_ids,
                "variables":    list(group),
                "combo_key":    combo_key,
            })

    # ── 3.  Sort:  pairs first, then alphabetical key ──────────────
    combos.sort(key=lambda c: (c["combo_depth"], c["combo_key"]))

    logger.info(
        "[combos] endpoint %d: %d combination(s) generated "
        "(pairs=%d  triplets=%d).",
        endpoint_id,
        len(combos),
        sum(1 for c in combos if c["combo_depth"] == 2),
        sum(1 for c in combos if c["combo_depth"] == 3),
    )

    return combos


# ═══════════════════════════════════════════════════════════════════════
#  E2 — Combination executor + transition classifier
# ═══════════════════════════════════════════════════════════════════════

def test_combinations(endpoint_id: int) -> list[dict]:
    """
    Execute every combination for *endpoint_id* and classify
    observed transitions.

    For each combo produced by :func:`generate_minimal_combinations`:

    1. **Build** a single request that applies all variables in the
       combo simultaneously.
    2. **Execute** the request via ``_execute_request``.
    3. **Classify** the result:
       - **Status Transition** — the status code moved away from 403.
       - **Content Transition** — status stayed 403 but the response
         body length grew by ≥ 50 % *or* Shannon entropy increased
         by ≥ 1.0 bit (i.e. "Partial Data" leaking through).
    4. **Re-verify** — re-send the baseline and the combo request
       to confirm the transition is reproducible.
    5. **Persist** verified transitions to ``combination_results``.

    Parameters
    ----------
    endpoint_id : int

    Returns
    -------
    list[dict]
        One dict per **verified** transition::

            {
                "endpoint_id":      int,
                "combo_key":        str,
                "combo_depth":      int,
                "variable_ids":     tuple,
                "transition_type":  str,   # "Status" or "Content"
                "baseline_status":  int,
                "combo_status":     int,
                "baseline_length":  int,
                "combo_length":     int,
                "baseline_entropy": float,
                "combo_entropy":    float,
                "detail":           str,
                "reproducible":     bool,
            }
    """
    # ── 0.  Fetch endpoint baseline ────────────────────────────────
    conn = get_connection()
    try:
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
                f"endpoint_id {endpoint_id} not found."
            )

        # Baseline entropy from the canonical body
        baseline_entropy = 0.0
        fp_gid = ep["fingerprint_group_id"]
        if fp_gid:
            body_row = conn.execute(
                "SELECT canonical_body FROM fingerprint_groups "
                "WHERE group_id = ?",
                (fp_gid,),
            ).fetchone()
            if body_row and body_row["canonical_body"]:
                baseline_entropy = calculate_entropy(
                    body_row["canonical_body"]
                )
    finally:
        conn.close()

    url: str            = ep["url"]
    method: str         = ep["method"]
    baseline_status     = ep["status_code"]
    baseline_length     = ep["body_length"]

    # ── 1.  Generate combos ────────────────────────────────────────
    combos = generate_minimal_combinations(endpoint_id)
    if not combos:
        return []

    logger.info(
        "[E2] Testing %d combination(s) for endpoint %d …",
        len(combos), endpoint_id,
    )

    transitions: list[dict] = []

    for combo in combos:
        # ── 2.  Build the multi-variable mutated request ───────────
        req = _build_combo_request(
            url, method, combo["variables"],
        )

        # ── 3.  Execute ────────────────────────────────────────────
        r1 = _execute_request(
            req["method"], req["url"], req["headers"],
            req["primer_methods"],
        )
        if r1["error"] is not None:
            continue   # skip network failures

        # ── 4.  Classify transition ────────────────────────────────
        transition_type = None
        detail = ""

        # Status Transition: 403 → anything else
        if r1["status"] != baseline_status:
            transition_type = "Status"
            detail = f"{baseline_status}→{r1['status']}"

        # Content Transition: status still 403 but body grew
        elif r1["status"] == 403:
            length_ratio = (
                r1["length"] / baseline_length
                if baseline_length > 0 else 0
            )
            entropy_delta = r1["entropy"] - baseline_entropy

            if length_ratio >= _LENGTH_GROWTH_FACTOR:
                transition_type = "Content"
                detail = (
                    f"Body length {baseline_length}→{r1['length']} "
                    f"({length_ratio:.1f}×)"
                )
            elif entropy_delta >= _ENTROPY_DELTA:
                transition_type = "Content"
                detail = (
                    f"Entropy {baseline_entropy:.2f}→{r1['entropy']:.2f} "
                    f"(+{entropy_delta:.2f} bits)"
                )

        if transition_type is None:
            continue   # no interesting transition

        # ── 5.  Re-verification gate ───────────────────────────────
        #    (a) Baseline re-check
        b_recheck = _execute_request(
            method, url, {"User-Agent": USER_AGENT},
        )
        baseline_stable = (
            b_recheck["status"] == baseline_status
            and b_recheck["length"] == baseline_length
        )

        #    (b) Combo re-check
        r2 = _execute_request(
            req["method"], req["url"], req["headers"],
            req["primer_methods"],
        )
        combo_consistent = (
            r2["status"] == r1["status"]
            and r2["length"] == r1["length"]
        )

        reproducible = baseline_stable and combo_consistent

        if not reproducible:
            logger.info(
                "  [TRANSIENT] %-30s  — discarded  "
                "(baseline_stable=%s  combo_consistent=%s)",
                combo["combo_key"], baseline_stable, combo_consistent,
            )
            continue

        logger.info(
            "  [TRANSITION] %-28s  %s  %s  (verified)",
            combo["combo_key"], transition_type, detail,
        )

        result = {
            "endpoint_id":      endpoint_id,
            "combo_key":        combo["combo_key"],
            "combo_depth":      combo["combo_depth"],
            "variable_ids":     combo["variable_ids"],
            "transition_type":  transition_type,
            "baseline_status":  baseline_status,
            "combo_status":     r1["status"],
            "baseline_length":  baseline_length,
            "combo_length":     r1["length"],
            "baseline_entropy": round(baseline_entropy, 4),
            "combo_entropy":    round(r1["entropy"], 4),
            "detail":           detail,
            "reproducible":     True,
        }
        transitions.append(result)

        # ── 6.  Persist ────────────────────────────────────────────
        _persist_transition(result)

        # ── 7.  Log as candidate in candidate_access ───────────────
        #    For 200 OK responses, run the false-win validation gate
        #    before writing to candidate_access.  Other status codes
        #    (e.g. 401 → 302, 403 → 404) are logged unconditionally.
        if r1["status"] == 200:
            passes, reason = validate_content_payload(
                r1, baseline_length, baseline_entropy,
            )
            if not passes:
                logger.info(
                    "  [FALSE-WIN] %-28s  discarded — %s",
                    combo["combo_key"], reason,
                )
                continue
        _log_candidate(result)

    logger.info(
        "[E2] endpoint %d: %d verified transition(s) from "
        "%d combination(s).",
        endpoint_id, len(transitions), len(combos),
    )

    return transitions


# ═══════════════════════════════════════════════════════════════════════
#  E4 — Reduction Logic
# ═══════════════════════════════════════════════════════════════════════

def reduce_to_minimal_combinations(transitions: list[dict]) -> list[dict]:
    """
    Discard any combination whose variable set is a *strict superset* of
    another verified transition on the same endpoint.

    Algorithm
    ---------
    Build a set of ``(endpoint_id, frozenset(variable_ids))`` for all
    verified transitions, then retain only combinations for which no
    proper sub-combination also appears in that set.

    Example
    -------
    If both ``(A, B)`` and ``(A, B, C)`` triggered a transition on the
    same endpoint, ``(A, B, C)`` is non-minimal — ``(A, B)`` already
    explains the effect.  Only ``(A, B)`` survives.

    Parameters
    ----------
    transitions : list[dict]
        Verified transition dicts as returned by :func:`test_combinations`
        across one or more endpoints.

    Returns
    -------
    list[dict]
        Subset of *transitions* containing only minimal combinations,
        preserving original order.
    """
    if not transitions:
        return []

    # Index: (endpoint_id, frozenset(variable_ids)) → bool  (exists)
    keys: set[tuple[int, frozenset]] = {
        (t["endpoint_id"], frozenset(t["variable_ids"]))
        for t in transitions
    }

    minimal: list[dict] = []
    for t in transitions:
        ep_id   = t["endpoint_id"]
        var_set = frozenset(t["variable_ids"])

        # Non-minimal if any proper subset triggered the same endpoint.
        is_minimal = not any(
            other_ep == ep_id and other_vars < var_set
            for other_ep, other_vars in keys
        )

        if is_minimal:
            minimal.append(t)

    eliminated = len(transitions) - len(minimal)
    if eliminated:
        logger.info(
            "[E4] Reduction: %d non-minimal combination(s) eliminated "
            "— %d minimal combination(s) remain.",
            eliminated, len(minimal),
        )
    else:
        logger.info(
            "[E4] Reduction: all %d combination(s) are already minimal.",
            len(minimal),
        )

    return minimal


# ═══════════════════════════════════════════════════════════════════════
#  Internal helpers
# ═══════════════════════════════════════════════════════════════════════

def validate_content_payload(
    response: dict,
    baseline_length: int,
    baseline_entropy: float,
) -> tuple[bool, str]:
    """
    Guard against 'False Win' candidates by inspecting the body of any
    request that returned ``200 OK``.

    Three checks are applied in order:

    1. **Redirection** — the body contains an HTML ``<meta http-equiv=refresh>``
       or a JavaScript ``window.location`` assignment whose target URL
       matches a login/auth path (``/login``, ``/signin``, ``/sign-in``,
       ``/auth``, ``/sso``).  These responses are soft-redirect disguised
       as 200s and do **not** represent genuine access.

    2. **Denial keywords** — the body (case-insensitive) contains phrases
       such as ``"Access Denied"``, ``"Forbidden"``, ``"Unauthorized"``, or
       ``"Please log in to continue"``.  A 200 wrapper around a denial page
       is still a denial.

    3. **Length similarity** — the response body length is within
       ``_LENGTH_SIMILARITY_THRESHOLD`` (±10 %) of the baseline 403 body
       length.  A body that is nearly the same size as the known denial
       page is most likely the same denial page re-served with a different
       status code.

    Parameters
    ----------
    response : dict
        Return value from ``_execute_request``.  Must contain ``"body"``
        (str) and ``"length"`` (int) fields.
    baseline_length : int
        Body byte-length of the canonical 403 baseline for this endpoint.
    baseline_entropy : float
        Shannon entropy of the canonical 403 baseline body (reserved for
        future entropy-based checks; not currently used as a filter but
        kept in the signature for forward compatibility).

    Returns
    -------
    tuple[bool, str]
        ``(passes, reason)`` — ``True`` (with an empty reason string) when
        the response looks like genuine content.  ``False`` with a
        human-readable *reason* string when the response is discarded as a
        false positive.
    """
    body: str = response.get("body", "")
    resp_length: int = response.get("length", 0)

    # ── 1.  Redirection check ───────────────────────────────────────────
    for pattern in (_META_REFRESH_RE, _JS_REDIRECT_RE):
        for match in pattern.finditer(body):
            target = match.group(1)
            if _LOGIN_PATH_RE.search(target):
                return False, (
                    f"Soft redirect to login path in 200 body: {target!r}"
                )

    # ── 2.  Denial keyword check ────────────────────────────────────────
    body_lower = body.lower()
    for keyword in _DENIAL_KEYWORDS:
        if keyword in body_lower:
            return False, f"Denial keyword found in 200 body: {keyword!r}"

    # ── 3.  Length similarity check ─────────────────────────────────────
    if baseline_length > 0:
        delta_ratio = abs(resp_length - baseline_length) / baseline_length
        if delta_ratio <= _LENGTH_SIMILARITY_THRESHOLD:
            return False, (
                f"200 body length ({resp_length} B) is within "
                f"{_LENGTH_SIMILARITY_THRESHOLD:.0%} of baseline 403 "
                f"length ({baseline_length} B); likely a false positive "
                f"(delta ratio={delta_ratio:.3f})"
            )

    return True, ""


def _build_combo_request(
    url: str,
    method: str,
    variables: list[dict],
) -> dict:
    """
    Apply **all** variable mutations simultaneously to produce a
    single request spec.

    Returns a dict with ``url``, ``method``, ``headers``, and
    ``primer_methods``.
    """
    combo_url    = url
    combo_method = method
    combo_headers: dict[str, str] = {"User-Agent": USER_AGENT}
    primer_methods: list[str] | None = None

    for var in variables:
        cat  = var["category"]
        name = var["name"]
        val  = var["test_value"]

        if cat in _HEADER_CATEGORIES:
            header_name = _resolve_header_name(name, cat)
            combo_headers[header_name] = val

        elif cat == "Protocol":
            combo_url = _apply_protocol(combo_url, val)

        elif cat == "User-Agent":
            combo_headers["User-Agent"] = val

        elif cat == "Referer":
            origin = (
                f"{urlparse(combo_url).scheme}://"
                f"{urlparse(combo_url).netloc}"
            )
            combo_headers["Referer"] = val.replace("{origin}", origin)

        elif cat == "Object ID":
            combo_url = _substitute_object_id(combo_url, val)

        elif cat == "Method Sequence":
            parts = [m.strip() for m in val.split(",")]
            primer_methods = parts[:-1]
            combo_method = parts[-1]

    return {
        "url":            combo_url,
        "method":         combo_method,
        "headers":        combo_headers,
        "primer_methods": primer_methods,
    }


def _persist_transition(result: dict) -> None:
    """Upsert a verified transition into ``combination_results``."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO combination_results
                (endpoint_id, combo_key, combo_depth,
                 transition_type, baseline_status,
                 combo_status, baseline_length, combo_length,
                 baseline_entropy, combo_entropy,
                 detail, reproducible)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(endpoint_id, combo_key) DO UPDATE SET
                transition_type  = excluded.transition_type,
                combo_status     = excluded.combo_status,
                combo_length     = excluded.combo_length,
                combo_entropy    = excluded.combo_entropy,
                detail           = excluded.detail,
                reproducible     = excluded.reproducible
            """,
            (
                result["endpoint_id"],
                result["combo_key"],
                result["combo_depth"],
                result["transition_type"],
                result["baseline_status"],
                result["combo_status"],
                result["baseline_length"],
                result["combo_length"],
                result["baseline_entropy"],
                result["combo_entropy"],
                result["detail"],
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _log_candidate(result: dict) -> None:
    """
    Insert a transition into ``candidate_access`` as an unverified
    candidate.

    The ``combination_id`` column stores a JSON string describing the
    variables that were applied, making it human-readable in raw SQL
    queries and easy to deserialise later.

    ``is_verified`` defaults to ``0`` — a downstream confirmation
    step will promote successful candidates to ``1``.
    """
    # Build a compact JSON descriptor of the variable combo.
    combo_descriptor = json.dumps(
        {
            "combo_key":    result["combo_key"],
            "variable_ids": list(result["variable_ids"]),
            "depth":        result["combo_depth"],
        },
        separators=(",", ":"),
    )

    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO candidate_access
                (endpoint_id, combination_id, transition_type,
                 new_status, new_length, is_verified)
            VALUES (?, ?, ?, ?, ?, 0)
            ON CONFLICT(endpoint_id, combination_id) DO UPDATE SET
                transition_type = excluded.transition_type,
                new_status      = excluded.new_status,
                new_length      = excluded.new_length,
                is_verified     = excluded.is_verified
            """,
            (
                result["endpoint_id"],
                combo_descriptor,
                result["transition_type"],
                result["combo_status"],
                result["combo_length"],
            ),
        )
        conn.commit()
    finally:
        conn.close()

