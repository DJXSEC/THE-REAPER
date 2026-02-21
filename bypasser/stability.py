"""
Endpoint stability verification for the 403 bypass scanner.

Issues three identical baseline requests with a 1-second delay between
each.  If the fingerprint (status_code, body_length, header_hash) is
identical across all three samples, the endpoint is recorded as stable
in the SQLite database.  Otherwise it is marked unstable and further
analysis is skipped.

Phase-F candidate stability scheduling
---------------------------------------
``schedule_stability_tests()`` reads every unverified entry from the
``candidate_access`` table and produces a structured testing schedule
that describes three ordered checks per candidate:

1. **Immediate Retry** — re-execute the combination straight away.
2. **60-Second Delayed Retry** — pause 60 s before re-executing, to
   detect results that are sensitive to rate-limiting or transient CDN
   caching.
3. **Clean Session Retry** — re-execute in a brand-new
   ``requests.Session`` with no cookies, connection pools, or headers
   inherited from previous pipeline phases.

The schedule is returned as a plain list of dicts; a downstream
executor (Phase F) is responsible for actually running the checks and
promoting verified candidates to ``is_verified = 1``.
"""

import json
import logging
import secrets
import time
from urllib.parse import urlparse, urlunparse

from bypasser.baseline import execute_baseline_request, USER_AGENT
from bypasser.db import get_connection, init_db
from bypasser.probing import _execute_request
from bypasser.transitions import _build_combo_request

logger = logging.getLogger(__name__)

# ── Fingerprint keys used for the stability comparison ──────────────
_FINGERPRINT_KEYS = ("status_code", "body_length", "header_hash")

# Number of samples and delay between them
_SAMPLE_COUNT = 3
_DELAY_SECONDS = 1

# Phase-F candidate stability schedule definition.
# Each tuple is (check_id, label, delay_seconds, clean_session, description).
_CANDIDATE_CHECKS: list[tuple[int, str, int, bool, str]] = [
    (
        1,
        "Immediate Retry",
        0,
        False,
        "Re-execute the combination immediately using the same session "
        "state as Section E to confirm the transition is not a one-shot "
        "fluke.",
    ),
    (
        2,
        "60-Second Delayed Retry",
        60,
        False,
        "Pause 60 seconds before re-executing, testing whether the result "
        "is sensitive to rate-limiting, transient CDN caching, or "
        "time-windowed policy enforcement.",
    ),
    (
        3,
        "Clean Session Retry",
        0,
        True,
        "Re-execute in a fresh requests.Session with no cookies, "
        "connection pools, or headers inherited from previous pipeline "
        "phases, confirming the bypass is not dependent on prior "
        "session state.",
    ),
]

# Interference check — a second User-Agent that is deliberately distinct
# from USER_AGENT so the baseline probe looks like a different client
# session.  The source IP will be the same (application-layer constraint),
# but the different UA ensures the baseline request carries none of the
# bypass headers and is treated independently by most WAF/CDN rule sets.
_INTERFERENCE_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Cache-busting — query parameter name appended with a random value to
# force a fresh cache miss.  A bypass that disappears under this param
# is a cached artefact, not a genuine authorisation bypass.
_CACHE_BUST_PARAM = "cb"


def verify_endpoint_stability(url: str, method: str = "GET") -> dict:
    """
    Probe an endpoint three times and decide whether it is stable.

    Parameters
    ----------
    url : str
        Target endpoint URL.
    method : str
        HTTP method (default ``GET``).

    Returns
    -------
    dict
        {
            "url":         str  – the tested URL,
            "method":      str  – the HTTP method used,
            "is_stable":   bool – True when all three samples match,
            "status_code":   int   – canonical status code    (from first sample),
            "body_length":   int   – canonical body length    (from first sample),
            "header_hash":   str   – canonical header hash    (from first sample),
            "entropy_score": float – Shannon entropy of body  (from first sample),
            "waf_type":      str      – detected WAF / infra       (from first sample),
            "denial_source":    str|None – enforcer from 403 body     (from first sample),
            "denial_layer":     str|None – 'Edge-Layer'/'App-Layer'   (from first sample),
            "response_time_ms":      float    – round-trip ms              (from first sample),
            "fingerprint_group_id":  str|None – cluster ID for 403 dedup   (from first sample),
            "samples":               list     – the three raw fingerprint dicts,
        }
    """
    # Ensure the database table exists before we try to write.
    init_db()

    # ── Collect samples ─────────────────────────────────────────────
    samples: list[dict] = []
    for i in range(_SAMPLE_COUNT):
        if i > 0:
            time.sleep(_DELAY_SECONDS)
        samples.append(execute_baseline_request(url, method))

    # ── Compare fingerprints ────────────────────────────────────────
    first = samples[0]
    is_stable = all(
        sample[key] == first[key]
        for sample in samples[1:]
        for key in _FINGERPRINT_KEYS
    )

    # ── Persist to database ─────────────────────────────────────────
    _store_result(url, method, first, is_stable)

    return {
        "url": url,
        "method": method,
        "is_stable": is_stable,
        "status_code": first["status_code"],
        "body_length": first["body_length"],
        "header_hash": first["header_hash"],
        "entropy_score": first["entropy_score"],
        "waf_type": first["waf_type"],
        "denial_source": first["denial_source"],
        "denial_layer": first["denial_layer"],
        "response_time_ms": first["response_time_ms"],
        "fingerprint_group_id": first["fingerprint_group_id"],
        "samples": samples,
    }


def _store_result(
    url: str, method: str, fingerprint: dict, is_stable: bool
) -> None:
    """Insert (or update) the endpoint row in the database."""
    conn = get_connection()
    try:
        # If a row for this url+method already exists, update it;
        # otherwise insert a fresh row.
        existing = conn.execute(
            "SELECT id FROM endpoints WHERE url = ? AND method = ?",
            (url, method),
        ).fetchone()

        if existing:
            conn.execute(
                """
                UPDATE endpoints
                   SET status_code     = ?,
                       body_length     = ?,
                       header_hash     = ?,
                       entropy_score   = ?,
                       waf_type        = ?,
                       denial_source   = ?,
                       denial_layer    = ?,
                       response_time_ms = ?,
                       fingerprint_group_id = ?,
                       is_stable       = ?,
                       created_at      = datetime('now')
                 WHERE id = ?
                """,
                (
                    fingerprint["status_code"],
                    fingerprint["body_length"],
                    fingerprint["header_hash"],
                    fingerprint["entropy_score"],
                    fingerprint["waf_type"],
                    fingerprint["denial_source"],
                    fingerprint["denial_layer"],
                    fingerprint["response_time_ms"],
                    fingerprint["fingerprint_group_id"],
                    int(is_stable),
                    existing["id"],
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO endpoints
                    (url, method, status_code, body_length, header_hash,
                     entropy_score, waf_type, denial_source, denial_layer,
                     response_time_ms, fingerprint_group_id, is_stable)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    url,
                    method,
                    fingerprint["status_code"],
                    fingerprint["body_length"],
                    fingerprint["header_hash"],
                    fingerprint["entropy_score"],
                    fingerprint["waf_type"],
                    fingerprint["denial_source"],
                    fingerprint["denial_layer"],
                    fingerprint["response_time_ms"],
                    fingerprint["fingerprint_group_id"],
                    int(is_stable),
                ),
            )

        conn.commit()
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════
#  Phase-F — Candidate stability scheduling
# ═══════════════════════════════════════════════════════════════════════

def schedule_stability_tests() -> list[dict]:
    """
    Build a Phase-F stability testing schedule for every unverified
    candidate bypass in ``candidate_access``.

    For each row where ``is_verified = 0``, three ordered check
    descriptors are produced (defined in ``_CANDIDATE_CHECKS``):

    1. **Immediate Retry** — no delay, same session context.
    2. **60-Second Delayed Retry** — 60-second pause before execution,
       same session context.
    3. **Clean Session Retry** — no delay, brand-new
       ``requests.Session`` with no inherited cookies or headers.

    The function only *builds* the schedule; it does not execute any
    HTTP requests.  A downstream Phase-F executor is responsible for
    working through the returned plan and promoting passing candidates
    to ``is_verified = 1``.

    Returns
    -------
    list[dict]
        One entry per unverified candidate.  Each entry has the shape::

            {
                "candidate": {
                    "endpoint_id":     int,
                    "url":             str,
                    "method":          str,
                    "combination_id":  dict,   # parsed from JSON
                    "transition_type": str,
                    "new_status":      int,
                    "new_length":      int,
                },
                "checks": [
                    {
                        "check_id":      int,   # 1 / 2 / 3
                        "label":         str,
                        "delay_seconds": int,   # 0 or 60
                        "clean_session": bool,
                        "description":   str,
                    },
                    ...
                ],
            }

        Returns an empty list when there are no unverified candidates.
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT ca.endpoint_id,
                   ca.combination_id,
                   ca.transition_type,
                   ca.new_status,
                   ca.new_length,
                   ep.url,
                   ep.method
              FROM candidate_access ca
              JOIN endpoints ep ON ep.id = ca.endpoint_id
             WHERE ca.is_verified = 0
             ORDER BY ca.endpoint_id, ca.rowid
            """,
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        logger.info(
            "[schedule] No unverified candidates found in candidate_access."
        )
        return []

    logger.info(
        "[schedule] Building stability schedule for %d unverified "
        "candidate(s).",
        len(rows),
    )

    schedule: list[dict] = []

    for row in rows:
        # Parse the JSON combo descriptor stored in combination_id.
        # _log_candidate() always writes valid JSON, but guard against
        # any hand-edited or legacy rows.
        try:
            combo = json.loads(row["combination_id"])
        except (json.JSONDecodeError, TypeError):
            combo = {
                "combo_key":    str(row["combination_id"]),
                "variable_ids": [],
                "depth":        0,
            }

        candidate = {
            "endpoint_id":     row["endpoint_id"],
            "url":             row["url"],
            "method":          row["method"],
            "combination_id":  combo,
            "transition_type": row["transition_type"],
            "new_status":      row["new_status"],
            "new_length":      row["new_length"],
        }

        checks = [
            {
                "check_id":      check_id,
                "label":         label,
                "delay_seconds": delay,
                "clean_session": clean,
                "description":   description,
            }
            for check_id, label, delay, clean, description
            in _CANDIDATE_CHECKS
        ]

        schedule.append({
            "candidate": candidate,
            "checks":    checks,
        })

        logger.info(
            "[schedule]   candidate ep=%d  combo=%s  → 3 checks queued.",
            row["endpoint_id"],
            combo.get("combo_key", "?"),
        )

    return schedule


# ═══════════════════════════════════════════════════════════════════════
#  Phase-F — Candidate verification executor
# ═══════════════════════════════════════════════════════════════════════

def verify_stability(candidate_id: int) -> dict:
    """
    Execute the bypass combination for *candidate_id* three times
    according to the Phase-F schedule and decide whether the result
    is **Stable** or a **Fluke**.

    Execution schedule (matches ``_CANDIDATE_CHECKS``)
    ---------------------------------------------------
    1. **Immediate Retry** — fire right away.
    2. **60-Second Delayed Retry** — sleep 60 s, then fire again.
    3. **Clean Session Retry** — rebuild the request spec from scratch
       (no in-memory state from checks 1 or 2) and fire immediately.

    Stability criteria
    ------------------
    A candidate is **Stable** when all three checks satisfy:

    * No network error.
    * HTTP status matches the expected ``new_status`` recorded during
      Section E (i.e. the bypass status did not revert to 403 or any
      other code).
    * Body length is identical across all three checks (dynamic
      content variations that produce the same status are still
      flagged if the length drifts significantly).

    Outcomes
    --------
    * **Stable** — ``candidate_access.is_verified`` is set to ``1``.
    * **Fluke**  — a row is inserted into ``failed_candidates``
      describing which check(s) diverged and why; ``is_verified``
      remains ``0``.

    Parameters
    ----------
    candidate_id : int
        Primary-key ``id`` of the row in ``candidate_access``.

    Returns
    -------
    dict
        ::

            {
                "candidate_id":    int,
                "endpoint_id":     int,
                "combo_key":       str,
                "expected_status": int,
                "is_stable":       bool,
                "failure_reason":  str,   # empty string when stable
                "check_results":   list[dict],
            }

    Raises
    ------
    ValueError
        If *candidate_id* is not found in ``candidate_access``.
    """
    # ── 1.  Load candidate row ─────────────────────────────────────
    conn = get_connection()
    try:
        row = conn.execute(
            """
            SELECT ca.id,
                   ca.endpoint_id,
                   ca.combination_id,
                   ca.transition_type,
                   ca.new_status,
                   ca.new_length,
                   ep.url,
                   ep.method
              FROM candidate_access ca
              JOIN endpoints ep ON ep.id = ca.endpoint_id
             WHERE ca.id = ?
            """,
            (candidate_id,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        raise ValueError(
            f"candidate_id {candidate_id} not found in candidate_access."
        )

    expected_status: int = row["new_status"]

    # ── 2.  Resolve variable definitions from combination_id ───────
    try:
        combo = json.loads(row["combination_id"])
    except (json.JSONDecodeError, TypeError):
        combo = {
            "combo_key":    str(row["combination_id"]),
            "variable_ids": [],
            "depth":        0,
        }

    variable_ids: list[int] = combo.get("variable_ids", [])
    combo_key: str = combo.get("combo_key", str(combo))

    conn = get_connection()
    try:
        if variable_ids:
            placeholders = ",".join("?" * len(variable_ids))
            var_rows = conn.execute(
                f"SELECT id, name, category, test_value "
                f"  FROM policy_variables "
                f" WHERE id IN ({placeholders})",
                variable_ids,
            ).fetchall()
            variables = [dict(r) for r in var_rows]
        else:
            variables = []
    finally:
        conn.close()

    logger.info(
        "[F1] verify_stability: candidate=%d  combo=%s  "
        "expected_status=%d  variables=%d",
        candidate_id, combo_key, expected_status, len(variables),
    )

    # ── 3.  Execute three checks per _CANDIDATE_CHECKS schedule ───
    check_results: list[dict] = []

    for check_id, label, delay_seconds, clean_session, _ in _CANDIDATE_CHECKS:

        # Delay before this check if required.
        if delay_seconds > 0:
            logger.info(
                "[F1] Check %d (%s): sleeping %ds…",
                check_id, label, delay_seconds,
            )
            time.sleep(delay_seconds)

        # For the clean-session check, rebuild the request spec from
        # scratch so no in-memory state from earlier checks leaks in.
        # For checks 1 & 2, reuse the same spec to be fair.
        req = _build_combo_request(row["url"], row["method"], variables)

        result = _execute_request(
            req["method"],
            req["url"],
            req["headers"],
            req["primer_methods"],
        )

        # Interference check — fire a plain baseline request from a
        # separate session immediately after the combo to confirm the
        # enforcement gap is context-specific and not a race condition.
        interference = _run_interference_check(
            row["url"],
            row["method"],
            expected_status,
            result["status"],
        )

        check_results.append({
            "check_id":     check_id,
            "label":        label,
            "status":       result["status"],
            "length":       result["length"],
            "error":        result["error"],
            "interference": interference,
        })

        logger.info(
            "[F1] Check %d (%s): status=%s  length=%s  error=%s  "
            "baseline=%s  context_specific=%s",
            check_id, label,
            result["status"], result["length"], result["error"],
            interference["baseline_status"],
            interference["is_context_specific"],
        )

    # ── 4.  Evaluate stability and context-specificity ─────────────
    #    Collect results from checks that completed without error.
    errors = [r for r in check_results if r["error"] is not None]
    statuses = [r["status"] for r in check_results if r["error"] is None]
    lengths  = [r["length"]  for r in check_results if r["error"] is None]

    all_completed   = len(errors) == 0
    status_stable   = (
        all_completed
        and len(set(statuses)) == 1
        and statuses[0] == expected_status
    )
    length_stable   = all_completed and len(set(lengths)) == 1

    is_stable = all_completed and status_stable and length_stable

    # Context-specific: every successful check confirmed that the baseline
    # probe returned 403 while the combo returned the expected bypass
    # status.  A single check where both the combo AND baseline returned
    # the same non-403 status (i.e. the endpoint was briefly open to all)
    # invalidates the context-specific label.
    interference_hits = [
        r["interference"]
        for r in check_results
        if r["error"] is None
    ]
    is_context_specific = bool(interference_hits) and all(
        i["is_context_specific"] for i in interference_hits
    )

    # Build a human-readable failure reason.
    if not is_stable:
        if not all_completed:
            failed_ids = [r["check_id"] for r in errors]
            failure_reason = (
                f"Network error on check(s) {failed_ids}: "
                f"{[r['error'] for r in errors]}"
            )
        elif not status_stable:
            bad = [r for r in check_results if r["status"] != expected_status]
            failure_reason = (
                f"Status reverted on check(s) "
                f"{[r['check_id'] for r in bad]}: "
                f"expected {expected_status}, "
                f"got {[r['status'] for r in bad]}"
            )
        else:
            failure_reason = (
                f"Body length inconsistent across checks: {lengths}"
            )
    else:
        failure_reason = ""

    # ── 4b. Cache-busting check ────────────────────────────────────
    #    Only run when the standard checks indicate stability.
    #    A result that collapses under a fresh cache key is a Cache
    #    Artifact and must not be promoted as a real bypass.
    cache_bust_result: dict | None = None
    is_cache_artifact: bool = False

    if is_stable:
        cache_bust_result = _run_cache_bust_check(
            row["url"], row["method"], variables, expected_status,
        )
        if not cache_bust_result["survived"]:
            is_cache_artifact = True
            is_stable = False
            failure_reason = (
                f"Cache artifact: bypass failed with cache-busting param "
                f"(?{_CACHE_BUST_PARAM}=...); "
                f"cache-busted status={cache_bust_result['status']}, "
                f"expected={expected_status}"
            )
            logger.info(
                "[F1] CACHE-ARTIFACT ⚠ — candidate %d: bypass did not "
                "survive cache-busting (busted_status=%s, expected=%s).",
                candidate_id,
                cache_bust_result["status"],
                expected_status,
            )
        else:
            logger.info(
                "[F1] CACHE-BUST PASS ✓ — candidate %d: bypass survived "
                "cache-busting (status=%s).",
                candidate_id, cache_bust_result["status"],
            )

    # ── 5.  Persist outcome ────────────────────────────────────────
    if is_stable:
        _mark_verified(candidate_id)
        logger.info(
            "[F1] STABLE ✓ — candidate %d promoted to is_verified=1.",
            candidate_id,
        )
    else:
        _log_failed_candidate(
            candidate_id=candidate_id,
            endpoint_id=row["endpoint_id"],
            combo_key=combo_key,
            expected_status=expected_status,
            check_results=check_results,
            failure_reason=failure_reason,
        )
        logger.info(
            "[F1] FLUKE ✗ — candidate %d logged to failed_candidates: %s",
            candidate_id, failure_reason,
        )

    return {
        "candidate_id":        candidate_id,
        "endpoint_id":         row["endpoint_id"],
        "combo_key":           combo_key,
        "expected_status":     expected_status,
        "is_stable":           is_stable,
        "is_context_specific": is_context_specific,
        "is_cache_artifact":   is_cache_artifact,
        "cache_bust_result":   cache_bust_result,
        "failure_reason":      failure_reason,
        "check_results":       check_results,
    }


# ═══════════════════════════════════════════════════════════════════════
#  Phase-F — Wait and See
# ═══════════════════════════════════════════════════════════════════════

def wait_and_see(candidate_id: int, interval_seconds: int = 300) -> dict:
    """
    Re-execute a verified bypass after a configurable delay to confirm
    the access gap is not tied to a temporary session window or a
    short-lived backend misconfiguration.

    The function sleeps for *interval_seconds* (default 300 = 5 minutes),
    then replays the bypass combination from scratch.  The outcome is
    quantified as a **stability_score** (1–5) and persisted to
    ``candidate_access.stability_score``.

    Scoring rubric
    --------------
    1 — Re-run failed: status reverted or network error.
    2 — Status matched but body length drifted from the original.
    3 — Status and length stable; bypass not confirmed context-specific.
    4 — Status and length stable; context-specific confirmed.
    5 — Status and length stable; context-specific confirmed; cache-bust
        survived.

    Parameters
    ----------
    candidate_id : int
        Primary-key ``id`` of the row in ``candidate_access``.
        The row must already have ``is_verified = 1``.
    interval_seconds : int
        Seconds to sleep before replaying the bypass (default 300).

    Returns
    -------
    dict
        ::

            {
                "candidate_id":        int,
                "endpoint_id":         int,
                "combo_key":           str,
                "interval_seconds":    int,
                "rerun_status":        int | None,
                "rerun_length":        int | None,
                "rerun_error":         str | None,
                "status_matched":      bool,
                "length_matched":      bool,
                "is_context_specific": bool,
                "cache_bust_survived": bool | None,
                "stability_score":     int,   # 1–5
            }

    Raises
    ------
    ValueError
        If *candidate_id* is not found in ``candidate_access`` or its
        ``is_verified`` flag is still ``0``.
    """
    # ── 1.  Load verified candidate ────────────────────────────────
    conn = get_connection()
    try:
        row = conn.execute(
            """
            SELECT ca.id,
                   ca.endpoint_id,
                   ca.combination_id,
                   ca.new_status,
                   ca.new_length,
                   ep.url,
                   ep.method
              FROM candidate_access ca
              JOIN endpoints ep ON ep.id = ca.endpoint_id
             WHERE ca.id = ?
               AND ca.is_verified = 1
            """,
            (candidate_id,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        raise ValueError(
            f"candidate_id {candidate_id} not found in candidate_access "
            f"or is not yet verified (is_verified must be 1)."
        )

    expected_status: int = row["new_status"]
    original_length: int = row["new_length"]

    try:
        combo = json.loads(row["combination_id"])
    except (json.JSONDecodeError, TypeError):
        combo = {
            "combo_key":    str(row["combination_id"]),
            "variable_ids": [],
            "depth":        0,
        }

    variable_ids: list[int] = combo.get("variable_ids", [])
    combo_key: str = combo.get("combo_key", str(combo))

    conn = get_connection()
    try:
        if variable_ids:
            placeholders = ",".join("?" * len(variable_ids))
            var_rows = conn.execute(
                f"SELECT id, name, category, test_value "
                f"  FROM policy_variables "
                f" WHERE id IN ({placeholders})",
                variable_ids,
            ).fetchall()
            variables = [dict(r) for r in var_rows]
        else:
            variables = []
    finally:
        conn.close()

    logger.info(
        "[F2] wait_and_see: candidate=%d  combo=%s  "
        "expected_status=%d  delay=%ds",
        candidate_id, combo_key, expected_status, interval_seconds,
    )

    # ── 2.  Wait ───────────────────────────────────────────────────
    logger.info("[F2] Sleeping %d seconds before re-run…", interval_seconds)
    time.sleep(interval_seconds)

    # ── 3.  Re-execute the bypass ──────────────────────────────────
    req = _build_combo_request(row["url"], row["method"], variables)
    result = _execute_request(
        req["method"],
        req["url"],
        req["headers"],
        req["primer_methods"],
    )

    rerun_status: int | None = result["status"]
    rerun_length: int | None = result["length"]
    rerun_error:  str | None = result["error"]

    status_matched = (
        rerun_error is None
        and rerun_status == expected_status
    )
    length_matched = (
        status_matched
        and rerun_length == original_length
    )

    logger.info(
        "[F2] Re-run result: status=%s  length=%s  error=%s  "
        "status_matched=%s  length_matched=%s",
        rerun_status, rerun_length, rerun_error,
        status_matched, length_matched,
    )

    # ── 4.  Interference check ─────────────────────────────────────
    is_context_specific = False
    if status_matched:
        interference = _run_interference_check(
            row["url"],
            row["method"],
            expected_status,
            rerun_status,
        )
        is_context_specific = interference["is_context_specific"]

    # ── 5.  Cache-bust check ───────────────────────────────────────
    cache_bust_survived: bool | None = None
    if status_matched:
        cache_bust_result = _run_cache_bust_check(
            row["url"], row["method"], variables, expected_status,
        )
        cache_bust_survived = cache_bust_result["survived"]

    # ── 6.  Compute stability score ────────────────────────────────
    score = _compute_stability_score(
        status_matched, length_matched, is_context_specific, cache_bust_survived,
    )

    logger.info(
        "[F2] stability_score=%d  context_specific=%s  "
        "cache_bust_survived=%s",
        score, is_context_specific, cache_bust_survived,
    )

    # ── 7.  Persist score ──────────────────────────────────────────
    _update_stability_score(candidate_id, score)

    return {
        "candidate_id":        candidate_id,
        "endpoint_id":         row["endpoint_id"],
        "combo_key":           combo_key,
        "interval_seconds":    interval_seconds,
        "rerun_status":        rerun_status,
        "rerun_length":        rerun_length,
        "rerun_error":         rerun_error,
        "status_matched":      status_matched,
        "length_matched":      length_matched,
        "is_context_specific": is_context_specific,
        "cache_bust_survived": cache_bust_survived,
        "stability_score":     score,
    }


# ── Private execution helpers ────────────────────────────────────────

def _append_cache_buster(url: str) -> str:
    """
    Append ``?cb=<random>`` (or ``&cb=<random>`` if a query string
    already exists) to *url*.

    The random token is generated with :func:`secrets.token_urlsafe`
    so it is URL-safe and unpredictable enough to guarantee a cache miss
    on any standards-compliant CDN or proxy.

    Parameters
    ----------
    url : str
        The fully-built combo URL produced by ``_build_combo_request``.

    Returns
    -------
    str
        *url* with the cache-busting parameter appended.
    """
    parsed  = urlparse(url)
    buster  = f"{_CACHE_BUST_PARAM}={secrets.token_urlsafe(8)}"
    new_qs  = f"{parsed.query}&{buster}" if parsed.query else buster
    return urlunparse(parsed._replace(query=new_qs))


def _run_cache_bust_check(
    url: str,
    method: str,
    variables: list[dict],
    expected_status: int,
) -> dict:
    """
    Execute the bypass combination with a cache-busting query parameter
    appended to the final URL.

    The cache buster is applied **after** ``_build_combo_request``
    constructs the full combo URL (including any Object ID or Protocol
    mutations), so it is always the last query parameter and does not
    interfere with variable substitution logic.

    A bypass **survives** cache-busting when:

    * The request completes without a network error.
    * The response status equals *expected_status* (the same status the
      bypass returned during the standard stability checks).

    If the status reverts to 403 (or any other code), the finding is
    classified as a **Cache Artifact** by the caller — the original
    bypass result was served from a cached response and the underlying
    endpoint still enforces access control.

    Parameters
    ----------
    url : str
        Base endpoint URL (without cache-busting param).
    method : str
        HTTP method to use.
    variables : list[dict]
        Resolved variable definitions (id / name / category / test_value).
    expected_status : int
        The status the bypass is expected to return.

    Returns
    -------
    dict
        ::

            {
                "busted_url": str,
                "status":     int,
                "length":     int,
                "error":      str | None,
                "survived":   bool,
            }
    """
    # Build the combo request first so all URL mutations are applied,
    # then append the cache buster to the resulting URL.
    req        = _build_combo_request(url, method, variables)
    busted_url = _append_cache_buster(req["url"])

    result = _execute_request(
        req["method"],
        busted_url,
        req["headers"],
        req["primer_methods"],
    )

    survived = (
        result["error"] is None
        and result["status"] == expected_status
    )

    logger.info(
        "[F1-cachebust]  busted_url=%s  status=%s  survived=%s",
        busted_url, result["status"], survived,
    )

    return {
        "busted_url": busted_url,
        "status":     result["status"],
        "length":     result["length"],
        "error":      result["error"],
        "survived":   survived,
    }


def _run_interference_check(
    url: str,
    method: str,
    expected_bypass_status: int,
    combo_status: int,
) -> dict:
    """
    Send a clean baseline request immediately after the combo request
    to determine whether the bypass is Context-Specific or a race
    condition.

    The baseline probe uses ``_INTERFERENCE_USER_AGENT`` and carries
    **no bypass headers** — it intentionally looks like an ordinary,
    unprivileged client.  Changing the source IP is not possible at the
    application layer, so a distinct User-Agent is used to signal a
    different session context to WAF/CDN rule engines that inspect it.

    A bypass is considered **Context-Specific** when both of the
    following are true simultaneously:

    * The combo request returned the expected bypass status (i.e. the
      bypass worked and did not revert to 403).
    * The baseline probe returned ``403`` (i.e. the endpoint is still
      enforcing access control for non-bypass sessions).

    If both the combo and the baseline return a non-403 status at the
    same moment, the endpoint was transiently open to everyone — a race
    condition, not a genuine bypass.

    Parameters
    ----------
    url : str
        Target endpoint URL.
    method : str
        HTTP method to use for the baseline probe.
    expected_bypass_status : int
        The status code the combo is expected to return (from
        ``candidate_access.new_status``).
    combo_status : int
        Actual status code returned by the combo request that was just
        executed.

    Returns
    -------
    dict
        ::

            {
                "baseline_status":     int,
                "baseline_length":     int,
                "baseline_error":      str | None,
                "is_context_specific": bool,
            }
    """
    baseline = _execute_request(
        method,
        url,
        {"User-Agent": _INTERFERENCE_USER_AGENT},
    )

    # Context-specific: combo hit the expected non-403 status AND the
    # concurrent baseline probe was still blocked with a 403.
    is_context_specific = (
        baseline["error"] is None
        and combo_status == expected_bypass_status
        and combo_status != 403
        and baseline["status"] == 403
    )

    logger.info(
        "[F1-interference]  baseline_status=%s  combo_status=%s  "
        "context_specific=%s",
        baseline["status"], combo_status, is_context_specific,
    )

    return {
        "baseline_status":     baseline["status"],
        "baseline_length":     baseline["length"],
        "baseline_error":      baseline["error"],
        "is_context_specific": is_context_specific,
    }


# ── Private DB helpers ────────────────────────────────────────────────

def _mark_verified(candidate_id: int) -> None:
    """Set ``is_verified = 1`` on a confirmed stable candidate."""
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE candidate_access SET is_verified = 1 WHERE id = ?",
            (candidate_id,),
        )
        conn.commit()
    finally:
        conn.close()


def _log_failed_candidate(
    candidate_id: int,
    endpoint_id: int,
    combo_key: str,
    expected_status: int,
    check_results: list[dict],
    failure_reason: str,
) -> None:
    """Insert a Fluke record into ``failed_candidates``."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO failed_candidates
                (candidate_id, endpoint_id, combo_key,
                 expected_status, check_results, failure_reason)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                candidate_id,
                endpoint_id,
                combo_key,
                expected_status,
                json.dumps(check_results),
                failure_reason,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _compute_stability_score(
    status_matched: bool,
    length_matched: bool,
    is_context_specific: bool,
    cache_bust_survived: bool | None,
) -> int:
    """
    Map wait-and-see outcomes to a 1–5 stability score.

    1 — Re-run failed (status mismatch or network error).
    2 — Status matched but body length drifted from the original.
    3 — Status and length stable; bypass not confirmed context-specific.
    4 — Status and length stable; context-specific confirmed.
    5 — Status and length stable; context-specific confirmed; cache-bust
        survived.
    """
    if not status_matched:
        return 1
    if not length_matched:
        return 2
    if not is_context_specific:
        return 3
    if not cache_bust_survived:
        return 4
    return 5


def _update_stability_score(candidate_id: int, score: int) -> None:
    """Persist *score* to ``candidate_access.stability_score``."""
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE candidate_access SET stability_score = ? WHERE id = ?",
            (score, candidate_id),
        )
        conn.commit()
    finally:
        conn.close()
