"""
Contrast engine for the 403 bypass scanner.

Builds a *Context Triad* of three distinct request profiles for every
verified bypass, enabling side-by-side comparison that proves data
access is causally tied to the discovered bypass rather than a
misconfiguration that exposes the data to everyone.

Public API
----------
``orchestrate_context_triad(endpoint_id)``
    Prepares three request profiles:

    1. **Unauthenticated Baseline** — a clean request with no special
       headers (the "Control").
    2. **Authenticated** — a request carrying a valid session cookie or
       bearer token, if the user supplied one via environment variable
       (``ARBITER_AUTH_COOKIE`` or ``ARBITER_AUTH_TOKEN``).
    3. **Arbiter Bypass** — the exact minimal combination discovered in
       Section E that flips the endpoint from 403 → 200.

``execute_contrast_test(endpoint_id)``
    Executes all three triad requests nearly simultaneously (within a
    5-second window) to ensure backend state hasn't changed between
    measurements.  Captures full response body, status code, and
    headers for each profile, then persists the results to the
    ``context_contrast_results`` table.

``generate_logic_diff(endpoint_id)``
    Uses ``difflib`` to compare the Unauthenticated Baseline against
    the Arbiter Bypass response.  Highlights data blocks gained,
    computes an *Information Gain* percentage, and flags *Full
    Privilege Parity* when the bypass exposes ≥100% of authenticated
    data.

``infer_auth_failure_point(endpoint_id)``
    Logic-inference function that categorises the root cause of the
    access-control failure into one of three classes:

    * **Edge vs Origin** — WAF/CDN blocks the baseline, bypass
      reaches the origin directly.
    * **Incomplete Check** — application returns a login-required
      page but the bypass obtains real data.
    * **Trust-Failure** — bypass injects internal/proxy headers that
      the application blindly trusts.

``format_contrast_proof(endpoint_id)``
    Generate a side-by-side Markdown *Visual Smoking Gun* table for
    bug reports, comparing the unauthenticated baseline (403) against
    the bypass (200) with sensitive data redacted.
"""

from __future__ import annotations

import difflib
import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

import requests  # type: ignore

from bypasser.baseline import USER_AGENT  # type: ignore
from bypasser.db import get_connection  # type: ignore
from bypasser.extraction import _REDACT_PATTERNS  # type: ignore
from bypasser.probing import (  # type: ignore
    _apply_protocol,
    _resolve_header_name,
    _substitute_object_id,
    _HEADER_CATEGORIES,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────
#  Environment-variable keys for optional authentication credentials.
# ─────────────────────────────────────────────────────────────────────
_ENV_AUTH_COOKIE = "ARBITER_AUTH_COOKIE"   # e.g. "session=abc123..."
_ENV_AUTH_TOKEN  = "ARBITER_AUTH_TOKEN"    # e.g. "Bearer eyJ..."
_ENV_AUTH_HEADER = "ARBITER_AUTH_HEADER"   # custom header name (default: Authorization)

# Maximum wall-clock time allowed for the entire triad execution.
_TRIAD_TIMEOUT_SECONDS = 5


# ═══════════════════════════════════════════════════════════════════════
#  Public API
# ═══════════════════════════════════════════════════════════════════════

def orchestrate_context_triad(endpoint_id: int) -> dict[str, Any]:
    """
    Prepare three distinct request profiles for a verified bypass.

    The triad is the foundation for *comparative proof*: by showing
    the same endpoint under three authentication contexts, a triager
    can immediately see that the bypass grants access identical to (or
    exceeding) a legitimately authenticated session.

    Profiles
    --------
    1. **control** — Unauthenticated Baseline.
       A plain ``GET`` (or the endpoint's native method) with only
       ``User-Agent`` set.  Expected result: ``403 Forbidden``.

    2. **authenticated** — Authenticated Request *(optional)*.
       If the user supplied ``ARBITER_AUTH_COOKIE`` or
       ``ARBITER_AUTH_TOKEN`` via environment variables, this profile
       includes those credentials.  Expected result: ``200 OK`` with
       full data.  If no credentials are configured, this profile is
       returned with ``available=False``.

    3. **bypass** — Arbiter Bypass Request.
       The minimal combination from ``candidate_access`` (Section E)
       reconstructed with exact headers, URL mutations, and method
       overrides.  Expected result: ``200 OK`` — matching the
       authenticated profile.

    Parameters
    ----------
    endpoint_id : int

    Returns
    -------
    dict
        ::

            {
                "endpoint_id":   int,
                "url":           str,
                "method":        str,
                "profiles": {
                    "control": {
                        "label":      "Unauthenticated Baseline",
                        "method":     str,
                        "url":        str,
                        "headers":    dict[str, str],
                        "expected":   int,  # expected HTTP status
                        "available":  True,
                    },
                    "authenticated": {
                        "label":      "Authenticated Session",
                        "method":     str,
                        "url":        str,
                        "headers":    dict[str, str],
                        "expected":   int,
                        "available":  bool,
                        "auth_type":  str,  # "cookie" | "bearer" | "none"
                    },
                    "bypass": {
                        "label":      "Arbiter Bypass",
                        "method":     str,
                        "url":        str,
                        "headers":    dict[str, str],
                        "combo_key":  str,
                        "variables":  list[dict],
                        "primer_methods": list[str] | None,
                        "expected":   int,
                        "available":  True,
                    },
                },
                "comparison_note": str,
            }

    Raises
    ------
    ValueError
        If the endpoint does not exist or has no verified bypass.
    """
    conn = get_connection()
    try:
        # ── 1. Endpoint data ─────────────────────────────────────
        ep = conn.execute(
            "SELECT id, url, method FROM endpoints WHERE id = ?",
            (endpoint_id,),
        ).fetchone()
        if ep is None:
            raise ValueError(
                f"endpoint_id {endpoint_id} not found."
            )

        url: str    = ep["url"]
        method: str = ep["method"]

        # ── 2. Best verified bypass combo ────────────────────────
        ca_row = conn.execute(
            """
            SELECT combo_key, combination_id, new_status
              FROM candidate_access
             WHERE endpoint_id = ?
               AND is_verified  = 1
             ORDER BY impact_score DESC,
                      json_extract(combination_id, '$.depth') ASC
             LIMIT 1
            """,
            (endpoint_id,),
        ).fetchone()

        if ca_row is None:
            raise ValueError(
                f"No verified bypass found for endpoint_id "
                f"{endpoint_id}."
            )

        combo_key: str  = ca_row["combo_key"]
        bypass_status   = ca_row["new_status"] or 200
        combination_raw = ca_row["combination_id"]

        # ── 3. Resolve variable definitions ──────────────────────
        try:
            combo_desc = (
                json.loads(combination_raw)
                if isinstance(combination_raw, str)
                else {}
            )
        except (json.JSONDecodeError, TypeError):
            combo_desc = {}

        variable_ids = combo_desc.get("variable_ids", [])

        variables: list[dict] = []
        if variable_ids:
            placeholders = ",".join("?" for _ in variable_ids)
            var_rows = conn.execute(
                f"""
                SELECT id, name, category, test_value
                  FROM policy_variables
                 WHERE id IN ({placeholders})
                 ORDER BY id
                """,
                variable_ids,
            ).fetchall()
            variables = [
                {
                    "id":         r["id"],
                    "name":       r["name"],
                    "category":   r["category"],
                    "test_value": r["test_value"],
                }
                for r in var_rows
            ]

    finally:
        conn.close()

    # ── Profile 1: Unauthenticated Baseline (Control) ────────────
    control_profile = {
        "label":     "Unauthenticated Baseline",
        "method":    method,
        "url":       url,
        "headers":   {"User-Agent": USER_AGENT},
        "expected":  403,
        "available": True,
    }

    # ── Profile 2: Authenticated (if credentials provided) ───────
    authenticated_profile = _build_authenticated_profile(
        url, method,
    )

    # ── Profile 3: Arbiter Bypass ────────────────────────────────
    bypass_req = _build_bypass_request(
        url, method, variables,
    )

    bypass_profile = {
        "label":          "Arbiter Bypass",
        "method":         bypass_req["method"],
        "url":            bypass_req["url"],
        "headers":        bypass_req["headers"],
        "combo_key":      combo_key,
        "variables":      variables,
        "primer_methods": bypass_req["primer_methods"],
        "expected":       bypass_status,
        "available":      True,
    }

    # ── Comparison note ──────────────────────────────────────────
    auth_avail = authenticated_profile["available"]
    if auth_avail:
        comparison_note = (
            "Three-way comparison available. Compare bypass response "
            "against both the 403 control and the authenticated "
            "session to prove equivalent access."
        )
    else:
        comparison_note = (
            "Two-way comparison only (no auth credentials supplied). "
            "Set ARBITER_AUTH_COOKIE or ARBITER_AUTH_TOKEN to enable "
            "three-way proof."
        )

    result = {
        "endpoint_id": endpoint_id,
        "url":         url,
        "method":      method,
        "profiles": {
            "control":       control_profile,
            "authenticated": authenticated_profile,
            "bypass":        bypass_profile,
        },
        "comparison_note": comparison_note,
    }

    logger.info(
        "[TRIAD] endpoint %d: control=%s  auth=%s  bypass=%s (%s)",
        endpoint_id,
        "ready",
        "ready" if auth_avail else "no-creds",
        "ready",
        combo_key,
    )

    return result


def execute_contrast_test(endpoint_id: int) -> dict[str, Any]:
    """
    Execute the Context Triad requests and persist results.

    Fires all available profiles **nearly simultaneously** using a
    thread pool — the entire batch must complete within 5 seconds to
    ensure the backend state has not changed between measurements.

    For bypass profiles that include ``primer_methods``, the primer
    requests are sent first (sequentially), then the final bypass
    request is timed alongside the other profiles.

    Results are written to ``context_contrast_results`` and returned
    as a structured comparison dict.

    Parameters
    ----------
    endpoint_id : int

    Returns
    -------
    dict
        ::

            {
                "endpoint_id":       int,
                "url":               str,
                "wall_clock_ms":     float,   # total elapsed time
                "within_window":     bool,    # True if < 5 000 ms
                "profiles_executed": int,     # 2 or 3
                "results": {
                    "control": { ... },
                    "authenticated": { ... } | None,
                    "bypass": { ... },
                },
                "verdict":           str,
            }

    Raises
    ------
    ValueError
        Propagated from ``orchestrate_context_triad`` if the endpoint
        has no verified bypass.
    """
    triad = orchestrate_context_triad(endpoint_id)
    profiles = triad["profiles"]

    # Determine which profiles to actually fire.
    keys_to_run: list[str] = ["control", "bypass"]
    if profiles["authenticated"]["available"]:
        keys_to_run.append("authenticated")

    # ── Handle primer requests (sequential, before the timed window) ─
    bypass_prof = profiles["bypass"]
    primer_methods = bypass_prof.get("primer_methods") or []
    if primer_methods:
        logger.info(
            "[CONTRAST] endpoint %d: sending %d primer request(s) "
            "before timed window...",
            endpoint_id, len(primer_methods),
        )
        for pm in primer_methods:
            try:
                requests.request(
                    pm,
                    bypass_prof["url"],
                    headers=bypass_prof["headers"],
                    timeout=_TRIAD_TIMEOUT_SECONDS,
                )
            except requests.RequestException as exc:
                logger.warning(
                    "[CONTRAST] primer %s failed: %s", pm, exc,
                )

    # ── Fire all profiles concurrently ───────────────────────────
    wall_start = time.perf_counter()
    raw_results: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=len(keys_to_run)) as pool:
        future_map = {
            pool.submit(
                _fire_profile, key, profiles[key],  # type: ignore
            ): key
            for key in keys_to_run
        }

        for future in as_completed(
            future_map,
            timeout=_TRIAD_TIMEOUT_SECONDS,
        ):
            key = future_map[future]
            try:
                raw_results[key] = future.result()
            except Exception as exc:
                logger.warning(
                    "[CONTRAST] %s request failed: %s", key, exc,
                )
                raw_results[key] = _error_result(
                    profiles[key], str(exc),
                )

    wall_ms = (time.perf_counter() - wall_start) * 1000
    within_window = wall_ms < (_TRIAD_TIMEOUT_SECONDS * 1000)

    # ── Persist to database ──────────────────────────────────────
    executed_at = _now_iso()
    conn = get_connection()
    try:
        for key in keys_to_run:
            r = raw_results[key]
            prof = profiles[key]
            conn.execute(
                """
                INSERT INTO context_contrast_results (
                    endpoint_id, profile_key, label,
                    method, url, request_headers,
                    status_code, response_headers, body_text,
                    body_length, response_time_ms,
                    expected_status, status_match, executed_at
                ) VALUES (?, ?, ?, ?, ?, ?,  ?, ?, ?,  ?, ?,  ?, ?, ?)
                ON CONFLICT(endpoint_id, profile_key)
                DO UPDATE SET
                    label            = excluded.label,
                    method           = excluded.method,
                    url              = excluded.url,
                    request_headers  = excluded.request_headers,
                    status_code      = excluded.status_code,
                    response_headers = excluded.response_headers,
                    body_text        = excluded.body_text,
                    body_length      = excluded.body_length,
                    response_time_ms = excluded.response_time_ms,
                    expected_status  = excluded.expected_status,
                    status_match     = excluded.status_match,
                    executed_at      = excluded.executed_at
                """,
                (
                    endpoint_id,
                    key,
                    prof.get("label", key),
                    prof.get("method", "GET"),
                    prof.get("url", ""),
                    json.dumps(prof.get("headers", {})),
                    r["status_code"],
                    json.dumps(r["response_headers"]),
                    r["body_text"],
                    r["body_length"],
                    r["response_time_ms"],
                    prof.get("expected", 0),
                    1 if r["status_code"] == prof.get("expected", 0) else 0,
                    executed_at,
                ),
            )
        conn.commit()
    finally:
        conn.close()

    # ── Build verdict ────────────────────────────────────────────
    ctrl = raw_results.get("control", {})
    byp  = raw_results.get("bypass", {})
    auth = raw_results.get("authenticated")

    verdict = _compute_verdict(ctrl, byp, auth, profiles)

    logger.info(
        "[CONTRAST] endpoint %d: wall=%.0fms  window=%s  "
        "ctrl=%d  bypass=%d  auth=%s  verdict=%s",
        endpoint_id,
        wall_ms,
        "OK" if within_window else "EXCEEDED",
        ctrl.get("status_code", 0),
        byp.get("status_code", 0),
        str(auth["status_code"]) if auth else "n/a",
        verdict,
    )

    # ── Return structured result ─────────────────────────────────
    result_profiles = {
        "control": ctrl,
        "bypass":  byp,
    }
    if auth is not None:
        result_profiles["authenticated"] = auth

    return {
        "endpoint_id":       endpoint_id,
        "url":               triad["url"],
        "wall_clock_ms":     round(float(wall_ms), 2),  # type: ignore
        "within_window":     within_window,
        "profiles_executed": len(keys_to_run),
        "results":           result_profiles,
        "verdict":           verdict,
    }


def generate_logic_diff(endpoint_id: int) -> dict[str, Any]:
    """
    Compare the Unauthenticated Baseline against the Arbiter Bypass.

    Reads the stored responses from ``context_contrast_results``
    (populated by :func:`execute_contrast_test`), then:

    1. Produces a ``difflib.unified_diff`` between the control body
       and the bypass body.
    2. Extracts every *gained* data block — lines present in the
       bypass but absent from the baseline.
    3. Calculates **Information Gain** as::

           gain_pct = (bypass_unique_lines / bypass_total_lines) * 100

    4. If an authenticated profile exists and the bypass body length
       is ≥ 90 % of the authenticated body length, the result is
       flagged as **Full Privilege Parity** — the bypass yields as
       much data as a legitimately authenticated session.

    Parameters
    ----------
    endpoint_id : int

    Returns
    -------
    dict
        ::

            {
                "endpoint_id":       int,
                "unified_diff":      str,
                "gained_blocks":     list[str],
                "gained_line_count": int,
                "baseline_lines":    int,
                "bypass_lines":      int,
                "information_gain_pct": float,
                "privilege_parity":  str,
                "parity_detail":     str,
            }

    Raises
    ------
    ValueError
        If no contrast results exist for *endpoint_id*.
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT profile_key, body_text, body_length
              FROM context_contrast_results
             WHERE endpoint_id = ?
            """,
            (endpoint_id,),
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        raise ValueError(
            f"No contrast results for endpoint_id {endpoint_id}. "
            f"Run execute_contrast_test() first."
        )

    bodies: dict[str, str] = {}
    lengths: dict[str, int] = {}
    for r in rows:
        bodies[r["profile_key"]]  = r["body_text"] or ""
        lengths[r["profile_key"]] = r["body_length"] or 0

    ctrl_body   = bodies.get("control", "")
    bypass_body = bodies.get("bypass", "")
    auth_body   = bodies.get("authenticated")

    # ── 1. Unified diff ──────────────────────────────────────────
    ctrl_lines   = ctrl_body.splitlines(keepends=True)
    bypass_lines = bypass_body.splitlines(keepends=True)

    diff_lines = list(difflib.unified_diff(
        ctrl_lines,
        bypass_lines,
        fromfile="control  (Unauthenticated Baseline)",
        tofile="bypass   (Arbiter Bypass)",
        lineterm="",
    ))
    unified_diff_str = "\n".join(diff_lines)

    # ── 2. Extract gained blocks ─────────────────────────────────
    gained_blocks = _extract_gain_blocks(diff_lines)
    gained_line_count = sum(
        block.count("\n") + 1 for block in gained_blocks
    )

    # ── 3. Information Gain % ────────────────────────────────────
    bypass_line_count = len(bypass_lines)
    ctrl_line_count   = len(ctrl_lines)

    if bypass_line_count > 0:
        info_gain_pct = (
            gained_line_count / bypass_line_count
        ) * 100.0
    else:
        info_gain_pct = 0.0

    info_gain_pct = min(info_gain_pct, 100.0)

    # ── 4. Privilege Parity assessment ───────────────────────────
    parity, detail = _assess_privilege_parity(
        bypass_body, auth_body,
        lengths.get("bypass", 0),
        lengths.get("authenticated", 0),
    )

    logger.info(
        "[LOGIC-DIFF] endpoint %d: +%d lines gained  "
        "gain=%.1f%%  parity=%s",
        endpoint_id, gained_line_count,
        info_gain_pct, parity,
    )

    return {
        "endpoint_id":         endpoint_id,
        "unified_diff":        unified_diff_str,
        "gained_blocks":       gained_blocks,
        "gained_line_count":   gained_line_count,
        "baseline_lines":      ctrl_line_count,
        "bypass_lines":        bypass_line_count,
        "information_gain_pct": round(float(info_gain_pct), 2),  # type: ignore
        "privilege_parity":    parity,
        "parity_detail":       detail,
    }


def infer_auth_failure_point(endpoint_id: int) -> dict[str, Any]:
    """
    Categorise the root cause of the access-control failure.

    Reads the stored contrast results from
    ``context_contrast_results`` and the bypass combination's
    variable definitions, then applies three heuristic classifiers
    in priority order:

    1. **Edge vs Origin** — the baseline response contains WAF /
       CDN fingerprints (e.g. ``cf-ray``, ``x-sucuri-id``,
       ``server: cloudflare``, ``<title>Attention Required</title>``)
       but the bypass response does *not*.  This means the bypass
       circumvents the edge layer and hits the origin server.

    2. **Incomplete Check** — the baseline body contains
       authentication-required signals (``"login"``,
       ``"sign in"`` , ``"unauthorized"`` , ``"session expired"``)
       while the bypass body contains real data.  The application
       checks authentication but the bypass satisfies a weaker or
       alternative code path.

    3. **Trust-Failure** — the bypass combination includes header
       variables in the ``Internal-Only`` or ``Proxy`` categories
       (e.g. ``X-Forwarded-For``, ``X-Real-IP``,
       ``X-Original-URL``).  The application blindly trusts these
       headers to grant access.

    If none of the classifiers fire, the result is
    ``Unknown / Unclassified``.

    Parameters
    ----------
    endpoint_id : int

    Returns
    -------
    dict
        ::

            {
                "endpoint_id":     int,
                "failure_class":   str,
                "confidence":      str,   # "high" | "medium" | "low"
                "evidence":        list[str],
                "detail":          str,
                "bypass_headers":  list[str],
            }

    Raises
    ------
    ValueError
        If no contrast results exist for *endpoint_id*.
    """
    conn = get_connection()
    try:
        # ── 1. Contrast results ──────────────────────────────────
        rows = conn.execute(
            """
            SELECT profile_key, status_code,
                   response_headers, body_text, body_length
              FROM context_contrast_results
             WHERE endpoint_id = ?
            """,
            (endpoint_id,),
        ).fetchall()

        if not rows:
            raise ValueError(
                f"No contrast results for endpoint_id {endpoint_id}. "
                f"Run execute_contrast_test() first."
            )

        profiles: dict[str, dict] = {}
        for r in rows:
            profiles[r["profile_key"]] = {
                "status_code":      r["status_code"],
                "response_headers": _safe_json(r["response_headers"]),
                "body_text":        r["body_text"] or "",
                "body_length":      r["body_length"] or 0,
            }

        # ── 2. Bypass combo variables ────────────────────────────
        ca_row = conn.execute(
            """
            SELECT combination_id
              FROM candidate_access
             WHERE endpoint_id = ?
               AND is_verified  = 1
             ORDER BY impact_score DESC
             LIMIT 1
            """,
            (endpoint_id,),
        ).fetchone()

        variable_rows: list[dict] = []
        if ca_row:
            combo_desc = _safe_json(ca_row["combination_id"])
            var_ids = combo_desc.get("variable_ids", [])
            if var_ids:
                ph = ",".join("?" for _ in var_ids)
                variable_rows = [
                    {
                        "name":     vr["name"],
                        "category": vr["category"],
                        "value":    vr["test_value"],
                    }
                    for vr in conn.execute(
                        f"""
                        SELECT name, category, test_value
                          FROM policy_variables
                         WHERE id IN ({ph})
                        """,
                        var_ids,
                    ).fetchall()
                ]
    finally:
        conn.close()

    ctrl = profiles.get("control", {})
    byp  = profiles.get("bypass", {})

    ctrl_body    = ctrl.get("body_text", "")
    byp_body     = byp.get("body_text", "")
    ctrl_headers = ctrl.get("response_headers", {})
    byp_headers  = byp.get("response_headers", {})
    ctrl_status  = ctrl.get("status_code", 0)
    byp_status   = byp.get("status_code", 0)

    bypass_header_names = [
        v["name"] for v in variable_rows
        if v["category"] in ("Internal-Only", "Proxy", "Identity")
    ]

    evidence: list[str] = []

    # ── Classifier 1: Edge vs Origin ─────────────────────────────
    edge_result = _detect_edge_vs_origin(
        ctrl_headers, ctrl_body, byp_headers, byp_body,
    )
    if edge_result:
        evidence.extend(edge_result["signals"])
        logger.info(
            "[INFER] endpoint %d: Edge-vs-Origin  signals=%s",
            endpoint_id, edge_result["signals"],
        )
        return {
            "endpoint_id":    endpoint_id,
            "failure_class":  "Edge vs Origin",
            "confidence":     edge_result["confidence"],
            "evidence":       evidence,
            "detail":         (
                "The unauthenticated baseline is blocked by a "
                "WAF / CDN edge layer, but the bypass request "
                "reaches the origin server directly, bypassing "
                "edge-level access controls."
            ),
            "bypass_headers": bypass_header_names,
        }

    # ── Classifier 2: Incomplete Check ───────────────────────────
    incomplete = _detect_incomplete_check(
        ctrl_status, ctrl_body, byp_status, byp_body,
    )
    if incomplete:
        evidence.extend(incomplete["signals"])
        logger.info(
            "[INFER] endpoint %d: Incomplete-Check  signals=%s",
            endpoint_id, incomplete["signals"],
        )
        return {
            "endpoint_id":    endpoint_id,
            "failure_class":  "Incomplete Check",
            "confidence":     incomplete["confidence"],
            "evidence":       evidence,
            "detail":         (
                "The baseline returns a login / authentication-"
                "required response, but the bypass obtains real "
                "data — the application's auth check is present "
                "but can be satisfied with the bypass combination."
            ),
            "bypass_headers": bypass_header_names,
        }

    # ── Classifier 3: Trust-Failure ──────────────────────────────
    trust = _detect_trust_failure(variable_rows)
    if trust:
        evidence.extend(trust["signals"])
        logger.info(
            "[INFER] endpoint %d: Trust-Failure  signals=%s",
            endpoint_id, trust["signals"],
        )
        return {
            "endpoint_id":    endpoint_id,
            "failure_class":  "Trust-Failure",
            "confidence":     trust["confidence"],
            "evidence":       evidence,
            "detail":         (
                "The bypass injects internal or proxy headers "
                f"({', '.join(bypass_header_names)}) that the "
                "application blindly trusts for authentication "
                "or authorization decisions."
            ),
            "bypass_headers": bypass_header_names,
        }

    # ── No classifier matched ────────────────────────────────────
    logger.info(
        "[INFER] endpoint %d: no classifier matched.",
        endpoint_id,
    )
    return {
        "endpoint_id":    endpoint_id,
        "failure_class":  "Unknown / Unclassified",
        "confidence":     "low",
        "evidence":       [],
        "detail":         (
            "None of the heuristic classifiers matched. "
            "Manual analysis is recommended."
        ),
        "bypass_headers": bypass_header_names,
    }


def format_contrast_proof(endpoint_id: int) -> dict:
    """
    Generate a side-by-side Markdown proof table for bug reports.

    Reads the stored contrast results from
    ``context_contrast_results``, redacts sensitive data in the
    bypass body, and produces a ready-to-paste Markdown document
    that shows:

    * **Column 1** — Unauthenticated User (Status 403 / Body: Error)
    * **Column 2** — Arbiter-403 Bypass (Status 200 / Body:
      ``[Redacted Sensitive Data]``)

    The document also includes the request details (method, URL,
    headers), response body snippets, and an impact summary.

    Parameters
    ----------
    endpoint_id : int

    Returns
    -------
    dict
        ::

            {
                "endpoint_id":   int,
                "markdown":      str,
                "file_path":     str,
                "profiles_used": list[str],
            }

    Raises
    ------
    ValueError
        If no contrast results exist for *endpoint_id*.
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT profile_key, label, method, url,
                   request_headers, status_code,
                   response_headers, body_text, body_length,
                   response_time_ms, expected_status, status_match
              FROM context_contrast_results
             WHERE endpoint_id = ?
            """,
            (endpoint_id,),
        ).fetchall()

        ep = conn.execute(
            "SELECT url, method FROM endpoints WHERE id = ?",
            (endpoint_id,),
        ).fetchone()
    finally:
        conn.close()

    if not rows:
        raise ValueError(
            f"No contrast results for endpoint_id {endpoint_id}. "
            f"Run execute_contrast_test() first."
        )

    profiles: dict[str, dict] = {}
    for r in rows:
        profiles[r["profile_key"]] = dict(r)

    ctrl = profiles.get("control", {})
    byp  = profiles.get("bypass", {})
    auth = profiles.get("authenticated")

    ep_url    = ep["url"] if ep else "unknown"
    ep_method = ep["method"] if ep else "GET"

    # ── Redact bypass body ───────────────────────────────────────
    byp_body_raw  = byp.get("body_text", "")
    byp_body_safe = _redact_body(byp_body_raw)
    ctrl_body     = ctrl.get("body_text", "")

    # ── Build Markdown ───────────────────────────────────────────
    lines: list[str] = []

    lines.append(
        f"# \U0001f513 403 Bypass Proof \u2014 Endpoint #{endpoint_id}"
    )
    lines.append("")
    lines.append(f"> **Target:** `{ep_method} {ep_url}`")
    lines.append(f"> **Generated:** {_now_iso()}")
    lines.append("")

    # ── Side-by-side comparison table ────────────────────────────
    lines.append("## Visual Comparison")
    lines.append("")
    lines.append(
        "| Aspect | \U0001f6ab Unauthenticated User | "
        "\u2705 Arbiter-403 Bypass |"
    )
    lines.append("|---|---|---|")

    ctrl_status = ctrl.get("status_code", 0)
    byp_status  = byp.get("status_code", 0)
    lines.append(
        f"| **Status Code** | `{ctrl_status}` | `{byp_status}` |"
    )

    ctrl_match = (
        "\u2705 Expected" if ctrl.get("status_match") else "\u274c Unexpected"
    )
    byp_match = (
        "\u2705 Expected" if byp.get("status_match") else "\u274c Unexpected"
    )
    lines.append(
        f"| **Status Match** | {ctrl_match} | {byp_match} |"
    )

    lines.append(
        f"| **Body Size** | {ctrl.get('body_length', 0):,} bytes | "
        f"{byp.get('body_length', 0):,} bytes |"
    )

    lines.append(
        f"| **Response Time** | "
        f"{ctrl.get('response_time_ms', 0):.0f} ms | "
        f"{byp.get('response_time_ms', 0):.0f} ms |"
    )

    ctrl_preview = _body_preview(ctrl_body, 120)
    byp_preview  = _body_preview(byp_body_safe, 120)
    lines.append(
        f"| **Body Preview** | `{ctrl_preview}` | "
        f"`{byp_preview}` |"
    )

    lines.append("")

    # ── Request details ──────────────────────────────────────────
    lines.append("## Request Details")
    lines.append("")
    lines.append("### Unauthenticated Baseline (Control)")
    lines.append("")
    lines.append("```http")
    lines.append(
        f"{ctrl.get('method', 'GET')} {ctrl.get('url', ep_url)}"
    )
    ctrl_hdrs = _safe_json(ctrl.get("request_headers", "{}"))
    for k, v in ctrl_hdrs.items():
        lines.append(f"{k}: {v}")
    lines.append("```")
    lines.append("")

    lines.append("### Arbiter Bypass")
    lines.append("")
    lines.append("```http")
    lines.append(
        f"{byp.get('method', 'GET')} {byp.get('url', ep_url)}"
    )
    byp_hdrs = _safe_json(byp.get("request_headers", "{}"))
    for k, v in byp_hdrs.items():
        lines.append(f"{k}: {v}")
    lines.append("```")
    lines.append("")

    # ── Full redacted response bodies ────────────────────────────
    lines.append("## Response Bodies")
    lines.append("")
    lines.append("### Control Response (403)")
    lines.append("")
    lines.append("```")
    lines.append(_body_preview(ctrl_body, 2000))
    lines.append("```")
    lines.append("")

    lines.append("### Bypass Response (200) \u2014 Redacted")
    lines.append("")
    lines.append("```")
    lines.append(_body_preview(byp_body_safe, 2000))
    lines.append("```")
    lines.append("")

    # ── Authenticated comparison (if available) ──────────────────
    if auth and auth.get("status_code"):
        auth_body_safe = _redact_body(auth.get("body_text", ""))
        lines.append("### Authenticated Response \u2014 Redacted")
        lines.append("")
        lines.append(
            f"> Status: `{auth.get('status_code', 0)}` \u00b7 "
            f"Body: {auth.get('body_length', 0):,} bytes"
        )
        lines.append("")
        lines.append("```")
        lines.append(_body_preview(auth_body_safe, 2000))
        lines.append("```")
        lines.append("")

    # ── Impact summary ───────────────────────────────────────────
    lines.append("## Impact Summary")
    lines.append("")

    info_gain = 0.0
    byp_len  = byp.get("body_length", 0)
    ctrl_len = ctrl.get("body_length", 0)
    gain_bytes = max(byp_len - ctrl_len, 0)
    if byp_len > 0:
        info_gain = (gain_bytes / byp_len) * 100.0

    lines.append(
        f"- **Information Gain:** {info_gain:.1f}% "
        f"(bypass exposes {gain_bytes:,} additional bytes)"
    )

    if auth:
        auth_len = auth.get("body_length", 0)
        if auth_len > 0 and byp_len / auth_len >= 0.9:
            lines.append(
                "- **\U0001f534 Full Privilege Parity:** The bypass "
                "exposes 100% of the data an authenticated admin "
                "would see."
            )
        elif auth_len > 0:
            ratio = byp_len / auth_len * 100
            lines.append(
                f"- **Privilege Overlap:** {ratio:.0f}% of "
                f"authenticated data exposed."
            )

    lines.append("")
    lines.append("---")
    lines.append(
        "*Generated by Arbiter-403 Contrast Engine. "
        "Sensitive data has been automatically redacted.*"
    )

    markdown = "\n".join(lines)

    # ── Save to file ─────────────────────────────────────────────
    file_path = f"contrast_proof_{endpoint_id}.md"
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(markdown)

    profiles_used = ["control", "bypass"]
    if auth:
        profiles_used.append("authenticated")

    logger.info(
        "[PROOF] endpoint %d: wrote %d-byte proof to %s",
        endpoint_id, len(markdown), file_path,
    )

    return {
        "endpoint_id":   endpoint_id,
        "markdown":      markdown,
        "file_path":     file_path,
        "profiles_used": profiles_used,
    }


# ═══════════════════════════════════════════════════════════════════════
#  Internal helpers
# ═══════════════════════════════════════════════════════════════════════

def _redact_body(body: str) -> str:
    """Apply redaction patterns from ``extraction`` to a body string."""
    result = body
    for pattern, replacement in _REDACT_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def _body_preview(body: str, max_chars: int) -> str:
    """
    Return a truncated preview of *body*, capped at *max_chars*.

    Pipe characters are escaped so they don't break Markdown tables.
    """
    cleaned = body.replace("\r\n", "\n").replace("\r", "\n")
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars] + " ...[truncated]"  # type: ignore
    # Escape pipe characters for Markdown table safety.
    cleaned = cleaned.replace("|", "\\|")
    return cleaned


# ── WAF / CDN fingerprint patterns ──────────────────────────────────
_WAF_HEADER_SIGNALS: dict[str, list[str]] = {
    "cf-ray":          ["Cloudflare"],
    "cf-cache-status": ["Cloudflare"],
    "x-sucuri-id":     ["Sucuri"],
    "x-sucuri-cache":  ["Sucuri"],
    "x-akamai-transformed": ["Akamai"],
    "x-amz-cf-id":     ["AWS CloudFront"],
    "x-amz-apigw-id":  ["AWS API Gateway"],
    "x-azure-ref":     ["Azure Front Door"],
}

_WAF_SERVER_PATTERNS: list[tuple[str, str]] = [
    ("cloudflare",    "Cloudflare"),
    ("sucuri",        "Sucuri"),
    ("akamai",        "Akamai"),
    ("awselb",        "AWS ELB"),
    ("bigip",         "F5 BIG-IP"),
    ("imperva",       "Imperva"),
    ("incapsula",     "Imperva/Incapsula"),
    ("barracuda",     "Barracuda"),
]

_WAF_BODY_PATTERNS: list[tuple[str, str]] = [
    ("attention required",       "Cloudflare challenge page"),
    ("cf-browser-verification",  "Cloudflare JavaScript challenge"),
    ("access denied",            "WAF block page"),
    ("request blocked",          "WAF block page"),
    ("web application firewall", "WAF block page"),
    ("ddos protection",          "DDoS protection interstitial"),
]

# ── Auth-required signals in baseline body ──────────────────────────
_AUTH_BODY_PATTERNS: list[str] = [
    "login",
    "log in",
    "sign in",
    "signin",
    "unauthorized",
    "unauthenticated",
    "authentication required",
    "session expired",
    "session timeout",
    "please authenticate",
    "access denied",
    "forbidden",
    "permission denied",
    "not authorized",
    "requires authentication",
    "must be logged in",
    "redirect_to_login",
    "www-authenticate",
]

# ── Headers that indicate proxy / internal trust ────────────────────
_TRUST_HEADER_CATEGORIES = frozenset({"Internal-Only", "Proxy"})


def _safe_json(raw: str | None) -> dict:
    """Parse a JSON string, returning ``{}`` on any failure."""
    if not raw:
        return {}
    try:
        result = json.loads(raw)
        return result if isinstance(result, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _detect_edge_vs_origin(
    ctrl_headers: dict,
    ctrl_body: str,
    byp_headers: dict,
    byp_body: str,
) -> dict | None:
    """
    Detect if the baseline is blocked by a WAF/CDN edge layer while
    the bypass reaches the origin.

    Returns ``{"signals": [...], "confidence": "high"|"medium"}``
    or ``None``.
    """
    signals: list[str] = []

    # Check response headers for WAF fingerprints.
    ctrl_hdr_lower = {k.lower(): v for k, v in ctrl_headers.items()}
    byp_hdr_lower  = {k.lower(): v for k, v in byp_headers.items()}

    for header_key, waf_names in _WAF_HEADER_SIGNALS.items():
        if header_key in ctrl_hdr_lower and header_key not in byp_hdr_lower:
            signals.append(
                f"Header '{header_key}' present in control "
                f"(from {waf_names[0]}) but absent in bypass"
            )

    # Check 'Server' header for WAF patterns.
    ctrl_server = ctrl_hdr_lower.get("server", "").lower()
    byp_server  = byp_hdr_lower.get("server", "").lower()
    for pattern, waf_name in _WAF_SERVER_PATTERNS:
        if pattern in ctrl_server and pattern not in byp_server:
            signals.append(
                f"Control Server header contains '{pattern}' "
                f"({waf_name}) but bypass does not"
            )

    # Check body content for WAF challenge pages.
    ctrl_body_lower = ctrl_body.lower()
    for pattern, desc in _WAF_BODY_PATTERNS:
        if pattern in ctrl_body_lower:
            signals.append(f"Control body contains '{pattern}' ({desc})")

    if not signals:
        return None

    confidence = "high" if len(signals) >= 2 else "medium"
    return {"signals": signals, "confidence": confidence}


def _detect_incomplete_check(
    ctrl_status: int,
    ctrl_body: str,
    byp_status: int,
    byp_body: str,
) -> dict | None:
    """
    Detect if the baseline shows a login/auth-required page while the
    bypass returns real data.

    Returns ``{"signals": [...], "confidence": "high"|"medium"}``
    or ``None``.
    """
    # Bypass must be a success response with a non-trivial body.
    if not (200 <= byp_status < 300 and len(byp_body) > 50):
        return None

    # Control should be a 4xx or contain auth signals.
    signals: list[str] = []
    ctrl_body_lower = ctrl_body.lower()

    if ctrl_status in (401, 403, 407):
        signals.append(
            f"Control returned HTTP {ctrl_status}"
        )

    matched_patterns: list[str] = []
    for pattern in _AUTH_BODY_PATTERNS:
        if pattern in ctrl_body_lower:
            matched_patterns.append(pattern)

    if matched_patterns:
        signals.append(
            f"Control body contains auth signals: "
            f"{', '.join(matched_patterns[:5])}"  # type: ignore
        )

    # Check for redirect-to-login in control headers or body.
    if re.search(
        r'(location|redirect).*(/login|/signin|/auth|/sso)',
        ctrl_body_lower,
    ):
        signals.append("Control body references login/SSO redirect")

    if not signals:
        return None

    # Bypass has real data — check it doesn't also look like an
    # auth page.
    byp_body_lower = byp_body.lower()
    byp_auth_hits = sum(
        1 for p in _AUTH_BODY_PATTERNS if p in byp_body_lower
    )
    if byp_auth_hits >= 3:
        return None  # Bypass also looks like a login page.

    confidence = "high" if len(signals) >= 2 else "medium"
    return {"signals": signals, "confidence": confidence}


def _detect_trust_failure(
    variable_rows: list[dict],
) -> dict | None:
    """
    Detect if the bypass relies on internal/proxy headers that the
    application blindly trusts.

    Returns ``{"signals": [...], "confidence": "high"|"medium"}``
    or ``None``.
    """
    signals: list[str] = []

    for var in variable_rows:
        cat = var.get("category", "")
        name = var.get("name", "")

        if cat in _TRUST_HEADER_CATEGORIES:
            signals.append(
                f"Bypass uses {cat} header '{name}' — "
                f"application trusts it for auth decisions"
            )

    if not signals:
        return None

    confidence = "high" if len(signals) >= 2 else "medium"
    return {"signals": signals, "confidence": confidence}


def _extract_gain_blocks(diff_lines: list[str]) -> list[str]:
    """
    Parse unified-diff output and return contiguous blocks of lines
    that are **only** present in the bypass (``+`` lines).

    Each block is a multi-line string of consecutive additions.
    Diff meta-lines (``+++``, ``---``, ``@@``) are excluded.
    """
    blocks: list[str] = []
    current: list[str] = []

    for line in diff_lines:
        # Skip diff headers.
        if line.startswith("---") or line.startswith("+++"):
            continue
        if line.startswith("@@"):
            # Flush any accumulated block.
            if current:
                blocks.append("\n".join(current))
                current = []
            continue

        if line.startswith("+"):
            # Strip the leading "+" marker.
            current.append(line[1:])  # type: ignore
        else:
            # Context or removal line → flush block.
            if current:
                blocks.append("\n".join(current))
                current = []

    # Flush trailing block.
    if current:
        blocks.append("\n".join(current))

    return blocks


def _assess_privilege_parity(
    bypass_body: str,
    auth_body: str | None,
    bypass_length: int,
    auth_length: int,
) -> tuple[str, str]:
    """
    Determine whether the bypass achieves *Full Privilege Parity*.

    Parity levels
    -------------
    - ``Full Privilege Parity``  — bypass body ≥ 90 % of
      authenticated body length **and** 100 % of non-whitespace
      content lines in the authenticated body appear in the bypass.
    - ``High Privilege Overlap`` — bypass body ≥ 75 % of
      authenticated body length.
    - ``Partial Overlap``        — bypass body ≥ 25 % of
      authenticated body length.
    - ``Minimal Overlap``        — bypass body < 25 % of
      authenticated body length.
    - ``No Auth Reference``      — no authenticated profile is
      available for comparison.

    Returns ``(parity_label, detail_string)``.
    """
    if auth_body is None or auth_length == 0:
        return (
            "No Auth Reference",
            "No authenticated response available for comparison.",
        )

    if bypass_length == 0:
        return (
            "Minimal Overlap",
            "Bypass returned an empty body.",
        )

    ratio = bypass_length / auth_length

    # Line-level content check for full parity.
    if ratio >= 0.9:
        auth_lines = {
            l.strip()
            for l in (auth_body.splitlines() if auth_body else [])
            if l.strip()
        }
        bypass_lines = {
            l.strip()
            for l in bypass_body.splitlines()
            if l.strip()
        }
        if auth_lines and auth_lines.issubset(bypass_lines):
            return (
                "Full Privilege Parity",
                f"Bypass contains 100% of authenticated content "
                f"({bypass_length} vs {auth_length} bytes, "
                f"ratio={ratio:.2f}). The bypass grants the same "
                f"data access as a legitimate admin session.",
            )
        return (
            "Full Privilege Parity",
            f"Bypass body length is ≥90% of authenticated "
            f"({bypass_length} vs {auth_length} bytes, "
            f"ratio={ratio:.2f}).",
        )

    if ratio >= 0.75:
        return (
            "High Privilege Overlap",
            f"Bypass body is {ratio:.0%} of authenticated "
            f"({bypass_length} vs {auth_length} bytes).",
        )

    if ratio >= 0.25:
        return (
            "Partial Overlap",
            f"Bypass body is {ratio:.0%} of authenticated "
            f"({bypass_length} vs {auth_length} bytes).",
        )

    return (
        "Minimal Overlap",
        f"Bypass body is only {ratio:.0%} of authenticated "
        f"({bypass_length} vs {auth_length} bytes).",
    )


def _fire_profile(key: str, profile: Any) -> dict[str, Any]:
    """
    Execute a single HTTP request for the given profile.

    Captures status code, response headers, full body text, body
    length, and round-trip time.
    """
    method  = profile.get("method", "GET")
    url     = profile.get("url", "")
    headers = profile.get("headers", {})

    t0 = time.perf_counter()
    try:
        resp = requests.request(
            method, url,
            headers=headers,
            timeout=_TRIAD_TIMEOUT_SECONDS,
            allow_redirects=True,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000

        return {
            "profile_key":      key,
            "status_code":      resp.status_code,
            "response_headers": dict(resp.headers),
            "body_text":        resp.text,
            "body_length":      len(resp.content),
            "response_time_ms": round(float(elapsed_ms), 2),  # type: ignore
            "error":            None,
        }

    except requests.RequestException as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return {
            "profile_key":      key,
            "status_code":      0,
            "response_headers": {},
            "body_text":        "",
            "body_length":      0,
            "response_time_ms": round(float(elapsed_ms), 2),  # type: ignore
            "error":            str(exc),
        }


def _error_result(profile: dict, error_msg: str) -> dict:
    """Return a zeroed-out result dict for a failed request."""
    return {
        "profile_key":      profile.get("label", "unknown"),
        "status_code":      0,
        "response_headers": {},
        "body_text":        "",
        "body_length":      0,
        "response_time_ms": 0.0,
        "error":            error_msg,
    }


def _compute_verdict(
    ctrl: dict,
    bypass: dict,
    auth: dict | None,
    profiles: dict,
) -> str:
    """
    Determine the overall contrast verdict.

    Verdicts
    --------
    - ``BYPASS_CONFIRMED``   — Control=403, Bypass=200 (or expected).
    - ``FULL_EQUIVALENCE``   — Bypass response matches authenticated
                               response (status + body length ±10%).
    - ``PARTIAL_MATCH``      — Bypass returns 200 but body differs
                               significantly from authenticated.
    - ``INCONCLUSIVE``       — Unexpected status codes or errors.
    - ``CONTROL_LEAKED``     — Control also returned 200 — the
                               endpoint might be open to everyone.
    """
    ctrl_status   = ctrl.get("status_code", 0)
    bypass_status = bypass.get("status_code", 0)
    expected      = profiles.get("bypass", {}).get("expected", 200)

    # Control also returned a success → endpoint is open.
    if 200 <= ctrl_status < 300:
        return "CONTROL_LEAKED"

    # Bypass didn't return the expected status.
    if bypass_status != expected:
        return "INCONCLUSIVE"

    # If authenticated profile is available, compare bodies.
    if auth is not None and auth.get("status_code", 0) == 200:
        auth_len   = auth.get("body_length", 0)
        bypass_len = bypass.get("body_length", 0)

        if auth_len > 0:
            ratio = bypass_len / auth_len
            if 0.9 <= ratio <= 1.1:
                return "FULL_EQUIVALENCE"
            else:
                return "PARTIAL_MATCH"

    # No auth to compare against — simple confirmation.
    return "BYPASS_CONFIRMED"


def _now_iso() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _build_authenticated_profile(
    url: str,
    method: str,
) -> dict:
    """
    Build the *Authenticated* request profile from environment
    variables.

    Checks (in priority order):
    1. ``ARBITER_AUTH_COOKIE``  → sent as ``Cookie`` header.
    2. ``ARBITER_AUTH_TOKEN``   → sent as ``Authorization`` header
       (or a custom header name from ``ARBITER_AUTH_HEADER``).

    Returns a profile dict with ``available=False`` if no credentials
    are configured.
    """
    headers: dict[str, str] = {"User-Agent": USER_AGENT}

    cookie_val = os.environ.get(_ENV_AUTH_COOKIE, "").strip()
    token_val  = os.environ.get(_ENV_AUTH_TOKEN, "").strip()
    auth_type  = "none"

    if cookie_val:
        headers["Cookie"] = cookie_val
        auth_type = "cookie"

    elif token_val:
        header_name = os.environ.get(
            _ENV_AUTH_HEADER, "Authorization",
        ).strip()
        headers[header_name] = token_val
        auth_type = "bearer"

    available = auth_type != "none"

    return {
        "label":     "Authenticated Session",
        "method":    method,
        "url":       url,
        "headers":   headers,
        "expected":  200,
        "available": available,
        "auth_type": auth_type,
    }


def _build_bypass_request(
    url: str,
    method: str,
    variables: list[dict],
) -> dict:
    """
    Reconstruct the bypass request from the resolved variable list.

    Mirrors the logic in ``extraction._build_extraction_request`` but
    without substituting a specific object_id (the triad compares
    requests at the *endpoint* level, not the object level).

    Returns ``{url, method, headers, primer_methods}``.
    """
    combo_url     = url
    combo_method  = method
    combo_headers: dict[str, str] = {"User-Agent": USER_AGENT}
    primer_methods: list[str] = []

    for var in variables:
        name     = var.get("name", "")
        category = var.get("category", "")
        value    = var.get("test_value", "")

        # ── Header mutations ─────────────────────────────────────
        if category in _HEADER_CATEGORIES:
            resolved = _resolve_header_name(name, category)
            combo_headers[resolved] = value

        # ── Protocol / URL rewrites ──────────────────────────────
        elif category == "protocol":
            combo_url = _apply_protocol(combo_url, name, value)

        # ── Method overrides ─────────────────────────────────────
        elif category == "method_sequence":
            parts = value.split(",") if value else [name]
            parts = [p.strip() for p in parts if p.strip()]
            if len(parts) >= 2:
                primer_methods = parts[:-1]  # type: ignore
                combo_method = parts[-1]
            elif parts:
                combo_method = parts[0]

        # ── Direct method override ───────────────────────────────
        elif category == "method_override":
            combo_method = value or name

    return {
        "url":            combo_url,
        "method":         combo_method,
        "headers":        combo_headers,
        "primer_methods": primer_methods if primer_methods else None,
    }

