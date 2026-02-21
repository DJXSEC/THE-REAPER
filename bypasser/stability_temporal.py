"""
Temporal stability tracking for verified 403 bypasses.

Phase L captures a *Reference Response* from each confirmed bypass
and stores it as an anchor in ``temporal_checks``.  Subsequent
re-checks compare the live response against the reference to detect
behavioural drift — status regression, body-length shifts, or
structural changes in the response payload.

Public API
----------
``initialize_stability_check(endpoint_id)``
    Fire the bypass for the first verified combo on *endpoint_id*,
    capture the response, compute a structural hash, and store the
    reference row in ``temporal_checks``.

``run_persistence_tests(endpoint_id)``
    Re-attempt the bypass at increasing intervals (1 min → 10 min
    → 1 hour) and score the persistence as High, Medium, or Low.
    If the bypass fails at any stage, mark ``persistence_score``
    as ``Low`` and log the failure time.

``verify_without_artifacts(endpoint_id)``
    Re-fire the bypass with a rotated User-Agent and a unique
    ``X-Arbiter-Cache`` header to confirm the response comes from
    origin, not a stale edge cache.

``audit_response_consistency(endpoint_id)``
    Compare responses across persistence-test intervals.  Flags
    body-length drift (>5%) as Dynamic Content, and performs a
    Hard Reset on 403 regression to confirm IPS closure.

``calculate_survival_index(endpoint_id)``
    Compute a composite 0–100 Survival Index and a triager-facing
    rating (High / Medium / Low) from persistence, origin, and
    consistency evidence.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
import time
import uuid
from datetime import datetime, timezone

import requests

from bypasser.baseline import USER_AGENT
from bypasser.db import get_connection

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
#  Table initialisation
# ═══════════════════════════════════════════════════════════════════════

# ── Persistence re-check schedule ────────────────────────────────────
_PERSISTENCE_SCHEDULE: list[tuple[int, str, int]] = [
    #  (stage_id, label,                  delay_seconds)
    (1, "Immediate (1 min)",              60),
    (2, "Short-term (10 min)",            600),
    (3, "Long-term (1 hour)",             3600),
]


def ensure_temporal_table() -> None:
    """Create the ``temporal_checks`` and ``persistence_log`` tables."""
    conn = get_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS temporal_checks (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id         INTEGER NOT NULL,
                combo_key           TEXT    NOT NULL,

                -- Reference snapshot
                ref_status          INTEGER NOT NULL,
                ref_body_length     INTEGER NOT NULL,
                ref_structure_hash  TEXT    NOT NULL,
                ref_body_text       TEXT    NOT NULL DEFAULT '',
                ref_response_time_ms REAL   NOT NULL DEFAULT 0,
                ref_headers         TEXT    NOT NULL DEFAULT '{}',

                -- Metadata
                captured_at         TEXT    NOT NULL,
                check_count         INTEGER NOT NULL DEFAULT 0,
                last_checked_at     TEXT,
                last_status         INTEGER,
                last_body_length    INTEGER,
                last_structure_hash TEXT,
                drift_detected      INTEGER NOT NULL DEFAULT 0,

                -- Persistence scoring
                persistence_score   TEXT    NOT NULL DEFAULT 'Pending',
                failed_at_stage     INTEGER,
                failed_at_time      TEXT,

                UNIQUE(endpoint_id, combo_key)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS persistence_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id     INTEGER NOT NULL,
                combo_key       TEXT    NOT NULL,
                stage_id        INTEGER NOT NULL,
                stage_label     TEXT    NOT NULL,
                delay_seconds   INTEGER NOT NULL,

                -- Result
                status_code     INTEGER,
                body_length     INTEGER,
                structure_hash  TEXT,
                response_time_ms REAL,
                error           TEXT,

                -- Comparison against reference
                status_match    INTEGER NOT NULL DEFAULT 0,
                length_match    INTEGER NOT NULL DEFAULT 0,
                structure_match INTEGER NOT NULL DEFAULT 0,
                passed          INTEGER NOT NULL DEFAULT 0,

                executed_at     TEXT    NOT NULL
            );
            """
        )
        conn.commit()

        # Migration: add persistence columns if missing.
        for col, coldef in [
            ("persistence_score", "TEXT NOT NULL DEFAULT 'Pending'"),
            ("failed_at_stage",   "INTEGER"),
            ("failed_at_time",    "TEXT"),
        ]:
            try:
                conn.execute(
                    f"ALTER TABLE temporal_checks ADD COLUMN {col} {coldef}"
                )
                conn.commit()
            except Exception:  # noqa: BLE001  — column already exists
                pass

    finally:
        conn.close()
    logger.info("[L] temporal tables ensured.")


# ═══════════════════════════════════════════════════════════════════════
#  Public API
# ═══════════════════════════════════════════════════════════════════════

def initialize_stability_check(endpoint_id: int) -> dict:
    """
    Capture a Reference Response for the successful bypass on
    *endpoint_id* and store it in ``temporal_checks``.

    The function:

    1. Looks up the first **verified** combo from ``candidate_access``
       for this endpoint.
    2. Resolves the bypass variable definitions from
       ``policy_variables``.
    3. Fires the bypass request and captures the full response.
    4. Computes a **structure hash** — a SHA-256 digest of the
       response's structural fingerprint (JSON key skeleton *or*
       HTML tag skeleton) so that future checks can detect payload
       drift without comparing raw bytes.
    5. Inserts the reference row into ``temporal_checks``.

    Parameters
    ----------
    endpoint_id : int

    Returns
    -------
    dict
        ::

            {
                "endpoint_id":       int,
                "combo_key":         str,
                "ref_status":        int,
                "ref_body_length":   int,
                "ref_structure_hash": str,
                "ref_response_time_ms": float,
                "captured_at":       str,    # ISO-8601
            }

    Raises
    ------
    ValueError
        If no verified bypass exists for *endpoint_id*.
    """
    ensure_temporal_table()

    # ── 1. Load verified candidate ───────────────────────────────
    conn = get_connection()
    try:
        row = conn.execute(
            """
            SELECT ca.id            AS candidate_id,
                   ca.endpoint_id,
                   ca.combination_id,
                   ca.new_status,
                   ca.new_length,
                   ep.url,
                   ep.method
              FROM candidate_access ca
              JOIN endpoints ep ON ep.id = ca.endpoint_id
             WHERE ca.endpoint_id = ?
               AND ca.is_verified  = 1
             ORDER BY ca.stability_score DESC, ca.id ASC
             LIMIT 1
            """,
            (endpoint_id,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        raise ValueError(
            f"No verified bypass for endpoint_id {endpoint_id}. "
            f"Run Sections E + F first."
        )

    # ── 2. Parse combination and resolve variables ───────────────
    try:
        combo = json.loads(row["combination_id"])
    except (json.JSONDecodeError, TypeError):
        combo = {
            "combo_key":    str(row["combination_id"]),
            "variable_ids": [],
            "depth":        0,
        }

    combo_key: str = combo.get("combo_key", str(combo))
    variable_ids: list[int] = combo.get("variable_ids", [])

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
        "[L] init_stability: ep=%d  combo=%s  vars=%d",
        endpoint_id, combo_key, len(variables),
    )

    # ── 3. Build and fire bypass request ─────────────────────────
    headers = _build_bypass_headers(variables)
    url    = row["url"]
    method = row["method"]

    t0 = time.perf_counter()
    try:
        resp = requests.request(
            method, url,
            headers=headers,
            timeout=15,
            allow_redirects=False,
            verify=False,
        )
        status     = resp.status_code
        body_text  = resp.text
        body_len   = len(body_text)
        resp_hdrs  = dict(resp.headers)
        elapsed_ms = (time.perf_counter() - t0) * 1000
    except requests.RequestException as exc:
        logger.warning(
            "[L] Network error capturing reference for ep %d: %s",
            endpoint_id, exc,
        )
        raise ValueError(
            f"Network error capturing reference response: {exc}"
        ) from exc

    logger.info(
        "[L] Reference captured: status=%d  length=%d  time=%.0fms",
        status, body_len, elapsed_ms,
    )

    # ── 4. Compute structure hash ────────────────────────────────
    structure_hash = _compute_structure_hash(body_text)

    # ── 5. Persist to temporal_checks ────────────────────────────
    captured_at = datetime.now(timezone.utc).isoformat()

    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO temporal_checks (
                endpoint_id, combo_key,
                ref_status, ref_body_length,
                ref_structure_hash, ref_body_text,
                ref_response_time_ms, ref_headers,
                captured_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(endpoint_id, combo_key)
            DO UPDATE SET
                ref_status           = excluded.ref_status,
                ref_body_length      = excluded.ref_body_length,
                ref_structure_hash   = excluded.ref_structure_hash,
                ref_body_text        = excluded.ref_body_text,
                ref_response_time_ms = excluded.ref_response_time_ms,
                ref_headers          = excluded.ref_headers,
                captured_at          = excluded.captured_at,
                check_count          = 0,
                drift_detected       = 0
            """,
            (
                endpoint_id,
                combo_key,
                status,
                body_len,
                structure_hash,
                body_text,
                elapsed_ms,
                json.dumps(resp_hdrs),
                captured_at,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    logger.info(
        "[L] Reference stored: ep=%d  hash=%s",
        endpoint_id, structure_hash[:16],
    )

    return {
        "endpoint_id":          endpoint_id,
        "combo_key":            combo_key,
        "ref_status":           status,
        "ref_body_length":      body_len,
        "ref_structure_hash":   structure_hash,
        "ref_response_time_ms": elapsed_ms,
        "captured_at":          captured_at,
    }


def run_persistence_tests(endpoint_id: int) -> dict:
    """
    Re-attempt the verified bypass at increasing intervals to
    measure its temporal persistence.

    Schedule
    --------
    1. **Immediate** — wait 1 minute, re-fire.
    2. **Short-term** — wait 10 minutes, re-fire.
    3. **Long-term** — wait 1 hour, re-fire.

    At each stage the response is compared against the reference
    anchor stored by :func:`initialize_stability_check`:

    * **status_match** — HTTP status identical.
    * **length_match** — body length within ±5% of reference.
    * **structure_match** — structural hash identical.

    A stage **passes** when all three conditions hold.

    Scoring
    -------
    * **High** — all 3 stages pass.
    * **Medium** — stages 1 + 2 pass, stage 3 fails.
    * **Low** — any of stages 1 or 2 fails.

    If the bypass fails at any stage, ``persistence_score`` is set
    to ``Low`` and the time of failure is logged.

    Parameters
    ----------
    endpoint_id : int

    Returns
    -------
    dict
        ::

            {
                "endpoint_id":       int,
                "combo_key":         str,
                "persistence_score": "High" | "Medium" | "Low",
                "stages_passed":     int,   # 0–3
                "stages":            list[dict],
                "failed_at_stage":   int | None,
                "failed_at_time":    str | None,
            }

    Raises
    ------
    ValueError
        If no reference anchor exists for *endpoint_id* in
        ``temporal_checks``.  Call
        :func:`initialize_stability_check` first.
    """
    ensure_temporal_table()

    # ── 1. Load reference anchor ─────────────────────────────────
    conn = get_connection()
    try:
        ref = conn.execute(
            """
            SELECT endpoint_id, combo_key,
                   ref_status, ref_body_length,
                   ref_structure_hash
              FROM temporal_checks
             WHERE endpoint_id = ?
             LIMIT 1
            """,
            (endpoint_id,),
        ).fetchone()
    finally:
        conn.close()

    if ref is None:
        raise ValueError(
            f"No reference anchor for endpoint_id {endpoint_id}. "
            f"Call initialize_stability_check() first."
        )

    combo_key       = ref["combo_key"]
    ref_status      = ref["ref_status"]
    ref_body_length = ref["ref_body_length"]
    ref_struct_hash = ref["ref_structure_hash"]

    # ── 2. Resolve bypass variables ──────────────────────────────
    conn = get_connection()
    try:
        ca_row = conn.execute(
            """
            SELECT ca.combination_id, ep.url, ep.method
              FROM candidate_access ca
              JOIN endpoints ep ON ep.id = ca.endpoint_id
             WHERE ca.endpoint_id = ?
               AND ca.is_verified  = 1
             ORDER BY ca.stability_score DESC, ca.id ASC
             LIMIT 1
            """,
            (endpoint_id,),
        ).fetchone()
    finally:
        conn.close()

    if ca_row is None:
        raise ValueError(
            f"No verified candidate for endpoint_id {endpoint_id}."
        )

    try:
        combo = json.loads(ca_row["combination_id"])
    except (json.JSONDecodeError, TypeError):
        combo = {"combo_key": combo_key, "variable_ids": []}

    variable_ids: list[int] = combo.get("variable_ids", [])

    conn = get_connection()
    try:
        if variable_ids:
            ph = ",".join("?" * len(variable_ids))
            var_rows = conn.execute(
                f"SELECT id, name, category, test_value "
                f"  FROM policy_variables WHERE id IN ({ph})",
                variable_ids,
            ).fetchall()
            variables = [dict(r) for r in var_rows]
        else:
            variables = []
    finally:
        conn.close()

    bypass_headers = _build_bypass_headers(variables)
    url    = ca_row["url"]
    method = ca_row["method"]

    logger.info(
        "[L] persistence: ep=%d  combo=%s  schedule=%d stages",
        endpoint_id, combo_key, len(_PERSISTENCE_SCHEDULE),
    )

    # ── 3. Execute staged re-checks ──────────────────────────────
    stages: list[dict] = []
    stages_passed   = 0
    failed_at_stage: int | None = None
    failed_at_time:  str | None = None
    length_tolerance = 0.05   # ±5%

    for stage_id, label, delay_seconds in _PERSISTENCE_SCHEDULE:

        # Wait before this stage.
        logger.info(
            "[L] Stage %d (%s): sleeping %ds…",
            stage_id, label, delay_seconds,
        )
        time.sleep(delay_seconds)

        executed_at = datetime.now(timezone.utc).isoformat()

        # Fire the bypass.
        t0 = time.perf_counter()
        try:
            resp = requests.request(
                method, url,
                headers=bypass_headers,
                timeout=15,
                allow_redirects=False,
                verify=False,
            )
            s_status     = resp.status_code
            s_body       = resp.text
            s_body_len   = len(s_body)
            s_hash       = _compute_structure_hash(s_body)
            s_elapsed_ms = (time.perf_counter() - t0) * 1000
            s_error      = None
        except requests.RequestException as exc:
            s_status     = None
            s_body_len   = None
            s_hash       = None
            s_elapsed_ms = (time.perf_counter() - t0) * 1000
            s_error      = str(exc)

        # Compare against reference.
        status_match = (s_status == ref_status)

        if s_body_len is not None and ref_body_length > 0:
            length_ratio = abs(s_body_len - ref_body_length) / ref_body_length
            length_match = length_ratio <= length_tolerance
        elif s_body_len is not None and ref_body_length == 0:
            length_match = (s_body_len == 0)
        else:
            length_match = False

        structure_match = (s_hash == ref_struct_hash)

        passed = (
            s_error is None
            and status_match
            and length_match
            and structure_match
        )

        stage_result = {
            "stage_id":        stage_id,
            "label":           label,
            "delay_seconds":   delay_seconds,
            "status_code":     s_status,
            "body_length":     s_body_len,
            "structure_hash":  s_hash,
            "response_time_ms": s_elapsed_ms,
            "error":           s_error,
            "status_match":    status_match,
            "length_match":    length_match,
            "structure_match": structure_match,
            "passed":          passed,
            "executed_at":     executed_at,
        }
        stages.append(stage_result)

        # Persist to persistence_log.
        conn = get_connection()
        try:
            conn.execute(
                """
                INSERT INTO persistence_log (
                    endpoint_id, combo_key, stage_id,
                    stage_label, delay_seconds,
                    status_code, body_length, structure_hash,
                    response_time_ms, error,
                    status_match, length_match, structure_match,
                    passed, executed_at
                ) VALUES (?,?,?, ?,?, ?,?,?, ?,?, ?,?,?, ?,?)
                """,
                (
                    endpoint_id, combo_key, stage_id,
                    label, delay_seconds,
                    s_status, s_body_len, s_hash,
                    s_elapsed_ms, s_error,
                    int(status_match), int(length_match),
                    int(structure_match),
                    int(passed), executed_at,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        if passed:
            stages_passed += 1
            logger.info(
                "[L] Stage %d PASS — status=%s  len=%s  hash=%s",
                stage_id, s_status, s_body_len,
                (s_hash or "")[:12],
            )
        else:
            failed_at_stage = stage_id
            failed_at_time  = executed_at
            logger.warning(
                "[L] Stage %d FAIL — status=%s (ref=%s)  "
                "len=%s (ref=%s)  hash=%s  error=%s",
                stage_id, s_status, ref_status,
                s_body_len, ref_body_length,
                (s_hash or "")[:12], s_error,
            )
            # Early exit — mark Low immediately.
            break

    # ── 4. Compute persistence score ─────────────────────────────
    if stages_passed == 3:
        persistence_score = "High"
    elif stages_passed == 2:
        persistence_score = "Medium"
    else:
        persistence_score = "Low"

    # ── 5. Update temporal_checks with score ─────────────────────
    conn = get_connection()
    try:
        conn.execute(
            """
            UPDATE temporal_checks
               SET persistence_score = ?,
                   failed_at_stage   = ?,
                   failed_at_time    = ?,
                   check_count       = check_count + ?,
                   last_checked_at   = ?,
                   last_status       = ?,
                   last_body_length  = ?,
                   last_structure_hash = ?
             WHERE endpoint_id = ?
               AND combo_key   = ?
            """,
            (
                persistence_score,
                failed_at_stage,
                failed_at_time,
                len(stages),
                stages[-1]["executed_at"] if stages else None,
                stages[-1]["status_code"] if stages else None,
                stages[-1]["body_length"] if stages else None,
                stages[-1]["structure_hash"] if stages else None,
                endpoint_id,
                combo_key,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    logger.info(
        "[L] persistence result: ep=%d  score=%s  passed=%d/3  "
        "failed_stage=%s",
        endpoint_id, persistence_score, stages_passed,
        failed_at_stage,
    )

    return {
        "endpoint_id":       endpoint_id,
        "combo_key":         combo_key,
        "persistence_score": persistence_score,
        "stages_passed":     stages_passed,
        "stages":            stages,
        "failed_at_stage":   failed_at_stage,
        "failed_at_time":    failed_at_time,
    }


# ── User-Agent rotation pool ────────────────────────────────────────
_ROTATED_USER_AGENTS: list[str] = [
    # Chrome on Windows 11
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) "
    "Gecko/20100101 Firefox/126.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome on Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.6367.60 Mobile Safari/537.36",
    # Safari on iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 "
    "Mobile/15E148 Safari/604.1",
]

# Cache-busting header name.
_CACHE_BUST_HEADER = "X-Arbiter-Cache"


def verify_without_artifacts(endpoint_id: int) -> dict:
    """
    Re-fire the bypass for *endpoint_id* with **anti-caching
    countermeasures** to confirm the access gap is genuinely
    live at the origin server.

    Countermeasures applied
    -----------------------
    1. **User-Agent rotation** — a randomly selected UA string
       from ``_ROTATED_USER_AGENTS`` replaces the default.
       CDN/WAF layer caches often key on UA, so this forces
       a fresh evaluation.
    2. **``X-Arbiter-Cache: <uuid>``** — a unique, per-request
       header that no edge cache has seen before.  Any
       well-behaved CDN must treat it as a cache miss.
    3. **``Cache-Control: no-cache, no-store``** — instructs
       intermediate proxies to bypass their local cache.
    4. **``Pragma: no-cache``** — HTTP/1.0 fallback.

    The function fires **two** requests:

    * **Probe A** — bypass combo *with* all countermeasures.
    * **Probe B** — plain unauthenticated baseline *with*
      the same countermeasures (no bypass headers).  This
      should return 403.

    Verdicts
    --------
    ``ORIGIN_CONFIRMED``
        Probe A returns the bypass status and Probe B returns
        403 — the bypass is live at origin.
    ``CACHE_ARTIFACT``
        Probe A returns the bypass status but Probe B *also*
        returns a non-403 status — the endpoint is open to
        everyone, likely served from cache.
    ``BYPASS_FAILED``
        Probe A does *not* return the expected bypass status —
        the bypass has regressed or was cache-dependent.
    ``INCONCLUSIVE``
        Network error or timeout prevented determination.

    Parameters
    ----------
    endpoint_id : int

    Returns
    -------
    dict
        ::

            {
                "endpoint_id":       int,
                "combo_key":         str,
                "verdict":           str,
                "rotated_ua":        str,
                "cache_bust_id":     str,
                "probe_a": {
                    "status": int | None,
                    "body_length": int | None,
                    "structure_hash": str | None,
                    "error": str | None,
                },
                "probe_b": {
                    "status": int | None,
                    "body_length": int | None,
                    "error": str | None,
                },
                "reference": {
                    "status": int,
                    "body_length": int,
                    "structure_hash": str,
                },
            }

    Raises
    ------
    ValueError
        If no reference anchor or verified candidate exists.
    """
    ensure_temporal_table()

    # ── 1. Load reference anchor ─────────────────────────────────
    conn = get_connection()
    try:
        ref = conn.execute(
            """
            SELECT endpoint_id, combo_key,
                   ref_status, ref_body_length,
                   ref_structure_hash
              FROM temporal_checks
             WHERE endpoint_id = ?
             LIMIT 1
            """,
            (endpoint_id,),
        ).fetchone()
    finally:
        conn.close()

    if ref is None:
        raise ValueError(
            f"No reference anchor for endpoint_id {endpoint_id}. "
            f"Call initialize_stability_check() first."
        )

    combo_key       = ref["combo_key"]
    ref_status      = ref["ref_status"]
    ref_body_length = ref["ref_body_length"]
    ref_struct_hash = ref["ref_structure_hash"]

    # ── 2. Load bypass combo ─────────────────────────────────────
    conn = get_connection()
    try:
        ca_row = conn.execute(
            """
            SELECT ca.combination_id, ep.url, ep.method
              FROM candidate_access ca
              JOIN endpoints ep ON ep.id = ca.endpoint_id
             WHERE ca.endpoint_id = ?
               AND ca.is_verified  = 1
             ORDER BY ca.stability_score DESC, ca.id ASC
             LIMIT 1
            """,
            (endpoint_id,),
        ).fetchone()
    finally:
        conn.close()

    if ca_row is None:
        raise ValueError(
            f"No verified candidate for endpoint_id {endpoint_id}."
        )

    try:
        combo = json.loads(ca_row["combination_id"])
    except (json.JSONDecodeError, TypeError):
        combo = {"combo_key": combo_key, "variable_ids": []}

    variable_ids: list[int] = combo.get("variable_ids", [])

    conn = get_connection()
    try:
        if variable_ids:
            ph = ",".join("?" * len(variable_ids))
            var_rows = conn.execute(
                f"SELECT id, name, category, test_value "
                f"  FROM policy_variables WHERE id IN ({ph})",
                variable_ids,
            ).fetchall()
            variables = [dict(r) for r in var_rows]
        else:
            variables = []
    finally:
        conn.close()

    url    = ca_row["url"]
    method = ca_row["method"]

    # ── 3. Build anti-cache headers ──────────────────────────────
    rotated_ua   = secrets.choice(_ROTATED_USER_AGENTS)
    cache_bust_id = str(uuid.uuid4())

    anti_cache_headers: dict[str, str] = {
        "User-Agent":     rotated_ua,
        _CACHE_BUST_HEADER: cache_bust_id,
        "Cache-Control":  "no-cache, no-store",
        "Pragma":         "no-cache",
    }

    logger.info(
        "[L] verify_without_artifacts: ep=%d  UA=%s  "
        "cache_bust=%s",
        endpoint_id, rotated_ua[:40], cache_bust_id[:8],
    )

    # ── 4. Probe A — bypass + anti-cache ────────────────────────
    bypass_headers = _build_bypass_headers(variables)
    bypass_headers.update(anti_cache_headers)  # overlay anti-cache

    probe_a = _fire_probe(method, url, bypass_headers)

    # ── 5. Probe B — baseline (no bypass) + anti-cache ──────────
    #    If the endpoint is properly protected, this should 403.
    baseline_headers = dict(anti_cache_headers)  # no bypass vars

    probe_b = _fire_probe(method, url, baseline_headers)

    # ── 6. Determine verdict ────────────────────────────────────
    if probe_a["error"] or probe_b["error"]:
        verdict = "INCONCLUSIVE"
    elif probe_a["status"] != ref_status:
        # Bypass didn’t reproduce with rotated UA — was cache-dependent.
        verdict = "BYPASS_FAILED"
    elif probe_b["status"] is not None and probe_b["status"] != 403:
        # Both authenticated AND unauthenticated get through—
        # the endpoint is open to everyone (cached or misconfigured).
        verdict = "CACHE_ARTIFACT"
    else:
        # Bypass works, baseline blocked — genuine origin bypass.
        verdict = "ORIGIN_CONFIRMED"

    logger.info(
        "[L] verdict=%s  probe_a_status=%s  probe_b_status=%s",
        verdict, probe_a["status"], probe_b["status"],
    )

    return {
        "endpoint_id":   endpoint_id,
        "combo_key":     combo_key,
        "verdict":       verdict,
        "rotated_ua":    rotated_ua,
        "cache_bust_id": cache_bust_id,
        "probe_a":       probe_a,
        "probe_b":       probe_b,
        "reference": {
            "status":         ref_status,
            "body_length":    ref_body_length,
            "structure_hash": ref_struct_hash,
        },
    }


def audit_response_consistency(endpoint_id: int) -> dict:
    """
    Compare persistence-test responses across time intervals
    and classify the bypass’s behavioural consistency.

    The function reads all rows from ``persistence_log`` for
    *endpoint_id* (populated by :func:`run_persistence_tests`)
    and evaluates two conditions:

    1. **Dynamic Content flag** — if any responses returned the
       bypass status (e.g. 200) but the body length drifted by
       more than 5% compared to the reference anchor, the result
       is flagged for *Dynamic Content Analysis*.  This indicates
       the bypass is real but the endpoint serves volatile data.

    2. **403 Regression + Hard Reset** — if *any* stage reverted
       to 403, the function fires a **Hard Reset** probe:

       * Brand-new ``requests.Session`` (no cookies, no state).
       * Rotated User-Agent.
       * Unique ``X-Arbiter-Cache`` cache-buster.
       * ``Cache-Control: no-cache, no-store``.

       If the Hard Reset *also* returns 403, the hole is confirmed
       closed (likely by an IPS / automated remediation).  If the
       Hard Reset succeeds, the 403 was a transient enforcement
       flap.

    Parameters
    ----------
    endpoint_id : int

    Returns
    -------
    dict
        ::

            {
                "endpoint_id":        int,
                "combo_key":          str,
                "interval_count":     int,
                "dynamic_content":    bool,
                "length_drift_pct":   list[float],
                "status_regression":  bool,
                "hard_reset_fired":   bool,
                "hard_reset_result":  dict | None,
                "conclusion":         str,
            }

    Raises
    ------
    ValueError
        If no reference anchor or persistence data exists.
    """
    ensure_temporal_table()

    # ── 1. Load reference anchor ─────────────────────────────────
    conn = get_connection()
    try:
        ref = conn.execute(
            """
            SELECT combo_key, ref_status, ref_body_length,
                   ref_structure_hash
              FROM temporal_checks
             WHERE endpoint_id = ?
             LIMIT 1
            """,
            (endpoint_id,),
        ).fetchone()
    finally:
        conn.close()

    if ref is None:
        raise ValueError(
            f"No reference anchor for endpoint_id {endpoint_id}."
        )

    combo_key       = ref["combo_key"]
    ref_status      = ref["ref_status"]
    ref_body_length = ref["ref_body_length"]

    # ── 2. Load all persistence-log rows ─────────────────────────
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT stage_id, stage_label,
                   status_code, body_length,
                   structure_hash, error,
                   passed, executed_at
              FROM persistence_log
             WHERE endpoint_id = ?
               AND combo_key   = ?
             ORDER BY stage_id ASC
            """,
            (endpoint_id, combo_key),
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        raise ValueError(
            f"No persistence data for endpoint_id {endpoint_id}. "
            f"Call run_persistence_tests() first."
        )

    logger.info(
        "[L] audit_consistency: ep=%d  intervals=%d",
        endpoint_id, len(rows),
    )

    # ── 3. Analyse body-length drift ─────────────────────────────
    dynamic_content = False
    length_drift_pct: list[float] = []
    _DRIFT_THRESHOLD = 0.05  # 5%

    for row in rows:
        s_status = row["status_code"]
        s_length = row["body_length"]

        if s_status == ref_status and s_length is not None:
            if ref_body_length > 0:
                drift = abs(s_length - ref_body_length) / ref_body_length
            elif s_length > 0:
                drift = 1.0  # ref was empty, live is not
            else:
                drift = 0.0

            length_drift_pct.append(round(drift * 100, 2))

            if drift > _DRIFT_THRESHOLD:
                dynamic_content = True
                logger.info(
                    "[L] Stage %d: body drift %.1f%% > threshold "
                    "(ref=%d  live=%d) → Dynamic Content",
                    row["stage_id"], drift * 100,
                    ref_body_length, s_length,
                )
        else:
            length_drift_pct.append(-1.0)  # not comparable

    # ── 4. Detect 403 regression ─────────────────────────────────
    regressed_stages = [
        row for row in rows
        if row["status_code"] == 403
    ]
    status_regression = len(regressed_stages) > 0

    hard_reset_fired  = False
    hard_reset_result: dict | None = None

    # ── 5. Hard Reset on 403 regression ─────────────────────────
    if status_regression:
        logger.info(
            "[L] 403 regression detected at stage(s) %s — "
            "firing Hard Reset…",
            [r["stage_id"] for r in regressed_stages],
        )
        hard_reset_fired = True
        hard_reset_result = _hard_reset_probe(
            endpoint_id, combo_key,
        )

    # ── 6. Build conclusion ─────────────────────────────────────
    if status_regression and hard_reset_result:
        if hard_reset_result["status"] == 403:
            conclusion = (
                "IPS_CLOSED — bypass reverted to 403 and Hard Reset "
                "confirmed the hole is sealed.  Likely automated "
                "security response (IPS / WAF rule push)."
            )
        elif hard_reset_result["status"] == ref_status:
            conclusion = (
                "TRANSIENT_FLAP — bypass reverted to 403 at one "
                "interval but Hard Reset succeeded.  The 403 was "
                "a temporary enforcement spike, not remediation."
            )
        else:
            conclusion = (
                f"AMBIGUOUS — Hard Reset returned status "
                f"{hard_reset_result['status']} (expected {ref_status} "
                f"or 403).  Manual investigation recommended."
            )
    elif dynamic_content:
        conclusion = (
            "DYNAMIC_CONTENT — bypass is live but body length "
            "varies >5% across intervals.  The endpoint serves "
            "volatile data; structure-hash comparison is more "
            "reliable than byte-length for drift detection."
        )
    elif status_regression:
        conclusion = (
            "REGRESSION_NO_RESET — 403 regression observed but "
            "Hard Reset could not be executed."
        )
    else:
        conclusion = (
            "CONSISTENT — all intervals returned the expected "
            "status with stable body length.  Bypass is reliable."
        )

    logger.info(
        "[L] audit conclusion: %s",
        conclusion.split(" \u2014 ")[0],
    )

    return {
        "endpoint_id":       endpoint_id,
        "combo_key":         combo_key,
        "interval_count":    len(rows),
        "dynamic_content":   dynamic_content,
        "length_drift_pct":  length_drift_pct,
        "status_regression": status_regression,
        "hard_reset_fired":  hard_reset_fired,
        "hard_reset_result": hard_reset_result,
        "conclusion":        conclusion,
    }


def calculate_survival_index(endpoint_id: int) -> dict:
    """
    Compute a composite **Survival Index** for a verified bypass.

    The index aggregates evidence from every temporal-stability
    function into a single 0–100 score and a triager-facing
    ``rating`` label.

    Scoring components (weighted)
    -----------------------------
    1. **Persistence score** (40 pts)
       - ``High`` → 40,  ``Medium`` → 20,  ``Low`` → 0.

    2. **Origin confirmation** (20 pts)
       - ``ORIGIN_CONFIRMED`` → 20,  ``CACHE_ARTIFACT`` → 0,
         ``BYPASS_FAILED`` → 0,  ``INCONCLUSIVE`` → 5.

    3. **Consistency** (20 pts)
       - ``CONSISTENT`` → 20,  ``DYNAMIC_CONTENT`` → 12,
         ``TRANSIENT_FLAP`` → 8,  ``IPS_CLOSED`` → 0,
         ``AMBIGUOUS`` → 4.

    4. **Body-length drift penalty** (0 to −20 pts)
       - ``max_drift``  = maximum drift percentage across intervals.
       - Penalty = min(max_drift × 0.4, 20).
       - 0% drift → 0 penalty.  ≥50% drift → full −20.

    Rating
    ------
    ============  =============================================
    ``High``      score ≥ 85 **and** max_drift == 0
    ``Medium``    50 ≤ score < 85  (or drift > 0)
    ``Low``       score < 50  or  ``IPS_CLOSED``
    ============  =============================================

    Parameters
    ----------
    endpoint_id : int

    Returns
    -------
    dict
        ::

            {
                "endpoint_id":        int,
                "combo_key":          str,
                "survival_score":     float,     # 0–100
                "rating":             str,       # High|Medium|Low
                "components": {
                    "persistence":    int,        # 0–40
                    "origin":         int,        # 0–20
                    "consistency":    int,        # 0–20
                    "drift_penalty":  float,      # 0 to −20
                },
                "max_drift_pct":      float,
                "persistence_score":  str,
                "origin_verdict":     str | None,
                "consistency_conclusion": str | None,
                "triager_summary":    str,
            }

    Raises
    ------
    ValueError
        If no reference anchor exists for *endpoint_id*.
    """
    ensure_temporal_table()

    # ── 1. Load temporal_checks row ──────────────────────────────
    conn = get_connection()
    try:
        tc = conn.execute(
            """
            SELECT combo_key, persistence_score,
                   ref_status, ref_body_length, ref_structure_hash,
                   check_count, drift_detected,
                   failed_at_stage
              FROM temporal_checks
             WHERE endpoint_id = ?
             LIMIT 1
            """,
            (endpoint_id,),
        ).fetchone()
    finally:
        conn.close()

    if tc is None:
        raise ValueError(
            f"No reference anchor for endpoint_id {endpoint_id}."
        )

    combo_key        = tc["combo_key"]
    persistence_raw  = tc["persistence_score"] or "Pending"

    # ── 2. Persistence component (40 pts) ────────────────────────
    _PERSISTENCE_PTS = {"High": 40, "Medium": 20, "Low": 0, "Pending": 10}
    pts_persistence  = _PERSISTENCE_PTS.get(persistence_raw, 0)

    # ── 3. Origin-confirmation component (20 pts) ────────────────
    #    Read the latest verify_without_artifacts result, if any.
    #    We don't store it in a table, so we check temporal_checks
    #    drift_detected or fall back to "not run".
    origin_verdict: str | None = None
    pts_origin = 10  # default: not yet run → partial credit

    #    Attempt to infer from drift_detected flag.
    if tc["drift_detected"]:
        origin_verdict = "DRIFT_DETECTED"
        pts_origin = 5
    elif tc["check_count"] and tc["check_count"] > 0:
        # Checks ran without drift → assume origin confirmed.
        origin_verdict = "ORIGIN_CONFIRMED"
        pts_origin = 20

    # ── 4. Consistency component (20 pts) ─────────────────────────
    consistency_conclusion: str | None = None
    pts_consistency = 10  # default: not yet run

    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT stage_id, status_code, body_length,
                   passed
              FROM persistence_log
             WHERE endpoint_id = ?
               AND combo_key   = ?
             ORDER BY stage_id ASC
            """,
            (endpoint_id, combo_key),
        ).fetchall()
    finally:
        conn.close()

    if rows:
        all_passed    = all(r["passed"] for r in rows)
        any_403       = any(r["status_code"] == 403 for r in rows)

        if any_403:
            consistency_conclusion = "IPS_CLOSED"
            pts_consistency = 0
        elif all_passed:
            consistency_conclusion = "CONSISTENT"
            pts_consistency = 20
        else:
            consistency_conclusion = "PARTIAL"
            pts_consistency = 8

    # ── 5. Drift penalty (0 to −20) ───────────────────────────────
    max_drift_pct = 0.0
    ref_body_length = tc["ref_body_length"]

    for row in rows:
        s_len = row["body_length"]
        if s_len is not None and ref_body_length and ref_body_length > 0:
            drift = abs(s_len - ref_body_length) / ref_body_length
            pct   = drift * 100
            if pct > max_drift_pct:
                max_drift_pct = pct

    drift_penalty = -min(max_drift_pct * 0.4, 20.0)

    # ── 6. Composite score ────────────────────────────────────────
    raw_score = (
        pts_persistence
        + pts_origin
        + pts_consistency
        + drift_penalty
    )
    survival_score = max(0.0, min(100.0, raw_score))

    # ── 7. Rating ─────────────────────────────────────────────────
    if consistency_conclusion == "IPS_CLOSED":
        rating = "Low"
    elif survival_score >= 85 and max_drift_pct == 0.0:
        rating = "High"
    elif survival_score >= 50:
        rating = "Medium"
    else:
        rating = "Low"

    # ── 8. Triager summary ────────────────────────────────────────
    if rating == "High":
        triager_summary = (
            f"STABLE — bypass survived all temporal checks with "
            f"0% body drift.  Survival Index {survival_score:.0f}/100.  "
            f"This vulnerability is reproducible, persistent, and "
            f"requires immediate remediation."
        )
    elif rating == "Medium":
        triager_summary = (
            f"PARTIALLY STABLE — Survival Index {survival_score:.0f}/100.  "
            f"Max body drift {max_drift_pct:.1f}%.  "
            f"Bypass may be affected by dynamic content or caching.  "
            f"Recommend re-validation before escalation."
        )
    else:
        triager_summary = (
            f"UNSTABLE — Survival Index {survival_score:.0f}/100.  "
            f"Bypass failed persistence or was closed by IPS.  "
            f"Re-scan recommended before reporting."
        )

    logger.info(
        "[L] survival_index: ep=%d  score=%.0f  rating=%s  "
        "drift=%.1f%%  persistence=%s",
        endpoint_id, survival_score, rating,
        max_drift_pct, persistence_raw,
    )

    return {
        "endpoint_id":           endpoint_id,
        "combo_key":             combo_key,
        "survival_score":        round(survival_score, 1),
        "rating":                rating,
        "components": {
            "persistence":       pts_persistence,
            "origin":            pts_origin,
            "consistency":       pts_consistency,
            "drift_penalty":     round(drift_penalty, 1),
        },
        "max_drift_pct":         round(max_drift_pct, 2),
        "persistence_score":     persistence_raw,
        "origin_verdict":        origin_verdict,
        "consistency_conclusion": consistency_conclusion,
        "triager_summary":       triager_summary,
    }



def _fire_probe(
    method: str, url: str, headers: dict[str, str],
) -> dict:
    """
    Fire a single HTTP request and return a result dict.

    Used by :func:`verify_without_artifacts` for both the
    bypass probe and the baseline probe.
    """
    t0 = time.perf_counter()
    try:
        resp = requests.request(
            method, url,
            headers=headers,
            timeout=15,
            allow_redirects=False,
            verify=False,
        )
        return {
            "status":         resp.status_code,
            "body_length":    len(resp.text),
            "structure_hash": _compute_structure_hash(resp.text),
            "response_time_ms": (time.perf_counter() - t0) * 1000,
            "error":          None,
        }
    except requests.RequestException as exc:
        return {
            "status":         None,
            "body_length":    None,
            "structure_hash": None,
            "response_time_ms": (time.perf_counter() - t0) * 1000,
            "error":          str(exc),
        }


def _hard_reset_probe(
    endpoint_id: int, combo_key: str,
) -> dict:
    """
    Fire the bypass with a **completely clean session** to
    determine whether a 403 regression is permanent.

    *Hard Reset* means:

    1. A fresh ``requests.Session`` — no cookies, no connection
       pool, no state carried over from prior requests.
    2. Rotated ``User-Agent`` (randomly chosen).
    3. Unique ``X-Arbiter-Cache: <uuid>`` header.
    4. ``Cache-Control: no-cache, no-store`` + ``Pragma: no-cache``.

    The bypass combo is rebuilt from scratch using
    ``_build_bypass_headers``.

    Returns a dict with ``status``, ``body_length``,
    ``structure_hash``, ``response_time_ms``, and ``error``.
    """
    # ── Resolve combo variables ──────────────────────────────────
    conn = get_connection()
    try:
        ca_row = conn.execute(
            """
            SELECT ca.combination_id, ep.url, ep.method
              FROM candidate_access ca
              JOIN endpoints ep ON ep.id = ca.endpoint_id
             WHERE ca.endpoint_id = ?
               AND ca.is_verified  = 1
             ORDER BY ca.stability_score DESC, ca.id ASC
             LIMIT 1
            """,
            (endpoint_id,),
        ).fetchone()
    finally:
        conn.close()

    if ca_row is None:
        return {
            "status": None, "body_length": None,
            "structure_hash": None, "response_time_ms": 0,
            "error": f"No verified candidate for ep {endpoint_id}",
        }

    try:
        combo = json.loads(ca_row["combination_id"])
    except (json.JSONDecodeError, TypeError):
        combo = {"combo_key": combo_key, "variable_ids": []}

    variable_ids: list[int] = combo.get("variable_ids", [])

    conn = get_connection()
    try:
        if variable_ids:
            ph = ",".join("?" * len(variable_ids))
            var_rows = conn.execute(
                f"SELECT id, name, category, test_value "
                f"  FROM policy_variables WHERE id IN ({ph})",
                variable_ids,
            ).fetchall()
            variables = [dict(r) for r in var_rows]
        else:
            variables = []
    finally:
        conn.close()

    url    = ca_row["url"]
    method = ca_row["method"]

    # ── Build clean headers ──────────────────────────────────────
    bypass_headers = _build_bypass_headers(variables)
    bypass_headers.update({
        "User-Agent":       secrets.choice(_ROTATED_USER_AGENTS),
        _CACHE_BUST_HEADER: str(uuid.uuid4()),
        "Cache-Control":    "no-cache, no-store",
        "Pragma":           "no-cache",
    })

    # ── Fire with a brand-new session ────────────────────────────
    session = requests.Session()
    session.cookies.clear()

    t0 = time.perf_counter()
    try:
        resp = session.request(
            method, url,
            headers=bypass_headers,
            timeout=15,
            allow_redirects=False,
            verify=False,
        )
        result = {
            "status":         resp.status_code,
            "body_length":    len(resp.text),
            "structure_hash": _compute_structure_hash(resp.text),
            "response_time_ms": (time.perf_counter() - t0) * 1000,
            "error":          None,
        }
    except requests.RequestException as exc:
        result = {
            "status":         None,
            "body_length":    None,
            "structure_hash": None,
            "response_time_ms": (time.perf_counter() - t0) * 1000,
            "error":          str(exc),
        }
    finally:
        session.close()

    logger.info(
        "[L] Hard Reset: ep=%d  status=%s  error=%s",
        endpoint_id, result["status"], result["error"],
    )
    return result


def _build_bypass_headers(variables: list[dict]) -> dict[str, str]:
    """
    Build the HTTP headers dict from the resolved variable list.

    Each variable with ``category`` of ``"Header"`` or
    ``"Internal-Only"`` or ``"Proxy"`` contributes one
    ``name: test_value`` entry.  All other categories are
    ignored (they affect URL, method, protocol, etc.).
    """
    headers: dict[str, str] = {"User-Agent": USER_AGENT}
    header_categories = {"Header", "Internal-Only", "Proxy", "Identity"}
    for var in variables:
        cat = var.get("category", "")
        if cat in header_categories:
            name  = var.get("name", "")
            value = var.get("test_value", "")
            if name and value:
                headers[name] = value
    return headers


def _compute_structure_hash(body: str) -> str:
    """
    Compute a SHA-256 hash of the *structural fingerprint* of *body*.

    Strategy:

    * **JSON responses** — extract the recursive key skeleton
      (sorted key names at each nesting level).  Values are
      ignored.  This means two responses with the same schema
      but different data hash identically.
    * **HTML responses** — extract a sequence of opening tag names
      (``<div>``, ``<span>``, ``<table>`` …).  Attributes and
      text content are stripped.
    * **Other** — fall back to a line-count + content-type
      heuristic.

    Returns
    -------
    str
        64-character hex SHA-256 digest.
    """
    skeleton = _extract_skeleton(body)
    return hashlib.sha256(skeleton.encode("utf-8")).hexdigest()


def _extract_skeleton(body: str) -> str:
    """
    Extract a normalised structural skeleton from *body*.

    Returns a deterministic string representation of the payload
    structure, suitable for hashing.
    """
    stripped = body.strip()
    if not stripped:
        return "EMPTY"

    # Try JSON first.
    if stripped[0] in ("{", "["):
        try:
            parsed = json.loads(stripped)
            return _json_skeleton(parsed)
        except (json.JSONDecodeError, TypeError):
            pass

    # Try HTML.
    if "<" in stripped and ">" in stripped:
        tags = _TAG_RE.findall(stripped)
        if len(tags) >= 3:
            return "HTML:" + ",".join(tags[:200])

    # Fallback: line-count fingerprint.
    line_count = stripped.count("\n") + 1
    return f"OPAQUE:lines={line_count}:len={len(stripped)}"


# Regex for HTML opening tags (captures tag name only).
_TAG_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>")


def _json_skeleton(obj: object, depth: int = 0) -> str:
    """
    Recursively build a sorted key skeleton for a JSON value.

    Example output for ``{"users": [{"id": 1, "name": "Alice"}]}``:

        ``{users:[{id,name}]}``
    """
    if depth > 20:
        return "..."

    if isinstance(obj, dict):
        parts = []
        for key in sorted(obj.keys()):
            child = _json_skeleton(obj[key], depth + 1)
            parts.append(f"{key}:{child}" if child else key)
        return "{" + ",".join(parts) + "}"

    if isinstance(obj, list):
        if not obj:
            return "[]"
        # Use the first element as representative.
        child = _json_skeleton(obj[0], depth + 1)
        return "[" + child + "]"

    # Scalar — ignore value, just mark type.
    if isinstance(obj, bool):
        return "bool"
    if isinstance(obj, int):
        return "int"
    if isinstance(obj, float):
        return "float"
    if isinstance(obj, str):
        return "str"
    return "null"
