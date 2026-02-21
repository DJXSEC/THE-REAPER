"""
Pagination-parameter detection and probing  (pagination module).

After a bypass is confirmed on a list-style endpoint, this module
detects pagination parameters (``limit``, ``offset``, ``page``,
``size``, ``per_page``, ``skip``, ``count``, ``start``, etc.) and
probes them to determine:

* Whether the server can be forced to return larger data chunks
  (limit escalation).
* The maximum reachable page / offset before a secondary 403 or
  empty response terminates the dataset.
* Whether the server silently caps the response (e.g., you request
  1 000 items but always receive exactly 100 — a **Silent Cap**).

All results are persisted to the ``pagination_reach`` table.
"""

from __future__ import annotations

import json
import logging
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from bypasser.db import get_connection  # type: ignore
from bypasser.probing import _execute_request  # type: ignore
from bypasser.transitions import _build_combo_request  # type: ignore

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
#  Known pagination parameter names
# ═══════════════════════════════════════════════════════════════════════

_PAGINATION_PARAMS: set[str] = {
    "limit", "offset", "page", "size", "per_page", "perpage",
    "pagesize", "page_size", "skip", "count", "start", "from",
    "take", "top", "max", "maxresults", "max_results",
    "items", "rows", "num", "number", "p",
}

# Limit-style params — control how many items per response.
_LIMIT_PARAMS: set[str] = {
    "limit", "size", "per_page", "perpage", "pagesize", "page_size",
    "count", "take", "top", "max", "maxresults", "max_results",
    "items", "rows", "num", "number",
}

# Offset-style params — control which segment of data is returned.
_OFFSET_PARAMS: set[str] = {
    "offset", "page", "skip", "start", "from", "p",
}

# Escalation values to try for limit-style params (ascending).
_LIMIT_ESCALATION = [50, 100, 250, 500, 1000, 5000, 10000]

# Jump values to try for offset/page params (ascending).
_OFFSET_JUMPS = [10, 50, 100, 500, 1000, 5000, 10000]

# Pattern to estimate row count from JSON array length.
_JSON_ARRAY_LEN_RE = re.compile(r"^\s*\[")


# ═══════════════════════════════════════════════════════════════════════
#  Public API
# ═══════════════════════════════════════════════════════════════════════

def probe_pagination_limits(endpoint_id: int) -> list[dict]:
    """
    For every verified bypass on *endpoint_id*, detect pagination
    parameters and probe them to measure the dataset's reachable
    extent through the bypassed authorisation boundary.

    Detection
    ---------
    Pagination parameters are detected from two sources:

    1. **URL query string** — any ``?key=value`` pair whose key
       (case-insensitive) matches a known pagination name.
    2. **Response body heuristics** — if the JSON response contains
       keys like ``next_page``, ``total_pages``, ``total_count``,
       ``has_more``, etc., the function infers that the endpoint
       is paginated even if no URL param is present, and injects
       ``?page=`` / ``?offset=`` / ``?limit=`` probes.

    Probing strategy
    ----------------
    **Limit escalation** — for limit-style params, the function
    tries increasingly large values (50 → 10 000) to see if the
    server returns more data per request.

    **Offset / page jumping** — for offset-style params, the function
    performs a linear sweep with increasing jumps (10 → 10 000) to
    find the maximum value that still returns data without
    triggering a secondary 403 or an empty response.

    A probe "holds" when:

    * HTTP status matches the original bypass status, **and**
    * The body is ≥ 50 bytes.

    An offset/page probe is considered the "max reached" when the
    *next* larger jump fails (403, empty, or error).

    Row-count estimation
    --------------------
    For JSON array responses, the function counts top-level array
    elements to estimate how many rows/records each probe returned.

    Returns
    -------
    list[dict]
        One dict per probe::

            {
                "endpoint_id":    int,
                "combo_key":      str,
                "param_name":     str,
                "probe_type":     str,   # "limit_escalation" or "offset_jump"
                "original_value": str,
                "probed_value":   str,
                "probe_url":      str,
                "http_status":    int | None,
                "body_length":    int,
                "row_count_est":  int | None,
                "bypass_held":    bool,
                "is_max_reached": bool,
                "hard_cap":       int | None,
                "error":          str | None,
            }
    """
    # ── 0.  Fetch endpoint + verified candidates ──────────────────
    conn = get_connection()
    try:
        ep = conn.execute(
            "SELECT id, url, method FROM endpoints WHERE id = ?",
            (endpoint_id,),
        ).fetchone()
        if ep is None:
            raise ValueError(f"endpoint_id {endpoint_id} not found.")

        candidates = conn.execute(
            """
            SELECT ca.id, ca.combination_id, ca.new_status
              FROM candidate_access ca
             WHERE ca.endpoint_id = ?
               AND ca.is_verified = 1
             ORDER BY ca.id
            """,
            (endpoint_id,),
        ).fetchall()
    finally:
        conn.close()

    if not candidates:
        logger.info(
            "[PAG] endpoint %d: no verified candidates.", endpoint_id,
        )
        return []

    base_url: str = ep["url"]
    method: str   = ep["method"]

    all_results: list[dict] = []

    for cand in candidates:
        combo_info = json.loads(cand["combination_id"])
        combo_key  = combo_info["combo_key"]
        var_ids    = combo_info["variable_ids"]
        bypass_status: int = cand["new_status"]

        variables = _load_variables(var_ids)
        if not variables:
            continue

        # ── 1.  Baseline bypass request ───────────────────────────
        base_req  = _build_combo_request(base_url, method, variables)
        base_resp = _execute_request(
            base_req["method"], base_req["url"], base_req["headers"],
            base_req["primer_methods"],
        )
        if base_resp["error"] is not None:
            continue

        base_body: str = base_resp["body"]

        # ── 2.  Detect pagination parameters ──────────────────────
        detected = _detect_pagination_params(base_url, base_body)

        if not detected:
            logger.info(
                "  [PAG] %-28s  no pagination params detected.",
                combo_key,
            )
            continue

        logger.info(
            "[PAG] %-28s  detected params: %s",
            combo_key,
            ", ".join(f"{p['name']}={p['value']}" for p in detected),
        )

        # ── 3.  Probe each detected parameter ────────────────────
        for param in detected:
            pname = param["name"]
            pval  = param["value"]

            if pname.lower() in _LIMIT_PARAMS:
                results = _probe_limit_escalation(
                    base_url, method, variables, bypass_status,
                    base_body, combo_key, endpoint_id, pname, pval,
                )
                all_results.extend(results)

            if pname.lower() in _OFFSET_PARAMS:
                results = _probe_offset_jump(
                    base_url, method, variables, bypass_status,
                    combo_key, endpoint_id, pname, pval,
                )
                all_results.extend(results)

    logger.info(
        "[PAG] endpoint %d: %d probe(s), %d held.",
        endpoint_id, len(all_results),
        sum(1 for r in all_results if r["bypass_held"]),
    )
    return all_results


# ═══════════════════════════════════════════════════════════════════════
#  Parameter detection
# ═══════════════════════════════════════════════════════════════════════

# JSON keys that indicate a paginated response.
_PAGINATION_BODY_HINTS = re.compile(
    r'"(?:next_page|prev_page|total_pages|total_count|total_items|'
    r"total_records|has_more|has_next|page_count|current_page|"
    r'last_page|total|pages|next_url|next_cursor|cursor)"',
    re.IGNORECASE,
)


def _detect_pagination_params(
    url: str, body: str,
) -> list[dict]:
    """
    Return a list of ``{"name": …, "value": …}`` dicts for every
    pagination parameter found in the URL or inferred from the body.
    """
    results: list[dict] = []
    seen: set[str] = set()

    # 1.  Explicit URL query params.
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    for key, values in qs.items():
        if key.lower() in _PAGINATION_PARAMS:
            val = values[0] if values else ""
            if key.lower() not in seen:
                seen.add(key.lower())
                results.append({"name": key, "value": val})

    # 2.  Body heuristics — if the response hints at pagination
    #     but no params were in the URL, inject defaults.
    if _PAGINATION_BODY_HINTS.search(body):
        for default_param in ("page", "offset", "limit"):
            if default_param not in seen:
                seen.add(default_param)
                results.append({"name": default_param, "value": "0"})

    return results


# ═══════════════════════════════════════════════════════════════════════
#  Limit escalation
# ═══════════════════════════════════════════════════════════════════════

def _probe_limit_escalation(
    base_url: str,
    method: str,
    variables: list[dict],
    bypass_status: int,
    base_body: str,
    combo_key: str,
    endpoint_id: int,
    param_name: str,
    original_value: str,
) -> list[dict]:
    """
    Try increasing limit/size values to coerce the server into
    returning more data per request.

    **Silent Cap detection**: if the server returns fewer items than
    requested and that item count stays constant across two
    consecutive escalation steps, we flag the lower count as the
    server's hard cap.
    """
    results: list[dict] = []
    base_length = len(base_body)

    # Track row counts across steps to detect silent caps.
    prev_row_count: int | None = None
    detected_cap: int | None   = None

    for limit_val in _LIMIT_ESCALATION:
        probe_url = _set_query_param(base_url, param_name, str(limit_val))
        probe_req = _build_combo_request(probe_url, method, variables)

        result: dict = {
            "endpoint_id":    endpoint_id,
            "combo_key":      combo_key,
            "param_name":     param_name,
            "probe_type":     "limit_escalation",
            "original_value": original_value,
            "probed_value":   str(limit_val),
            "probe_url":      probe_url,
            "http_status":    None,
            "body_length":    0,
            "row_count_est":  None,
            "bypass_held":    False,
            "is_max_reached": False,
            "hard_cap":       None,
            "error":          None,
        }

        try:
            resp = _execute_request(
                probe_req["method"], probe_req["url"],
                probe_req["headers"], probe_req["primer_methods"],
            )
        except Exception as exc:
            result["error"] = str(exc)
            _persist_pagination(result)
            results.append(result)
            continue

        if resp["error"] is not None:
            result["error"] = str(resp["error"])
            _persist_pagination(result)
            results.append(result)
            continue

        result["http_status"] = resp["status"]
        result["body_length"] = resp["length"]

        held = resp["status"] == bypass_status and resp["length"] >= 50
        result["bypass_held"] = held

        cur_rows: int | None = None
        if held:
            cur_rows = _estimate_row_count(resp["body"])
            result["row_count_est"] = cur_rows

        # ── Silent Cap detection ──────────────────────────────────
        # If the server returned a countable number of items that is
        # less than what we asked for, and the same count appeared
        # on the previous (smaller) request too, the server is
        # silently capping at that count.
        if (
            held
            and cur_rows is not None
            and cur_rows < limit_val
            and cur_rows == prev_row_count
            and detected_cap is None
        ):
            detected_cap = cur_rows
            result["hard_cap"] = detected_cap
            logger.info(
                "  [PAG]   ⚠ SILENT CAP detected: server returns "
                "exactly %d items regardless of %s=%d",
                detected_cap, param_name, limit_val,
            )
        elif detected_cap is not None:
            # Carry the cap forward to all subsequent probes.
            result["hard_cap"] = detected_cap

        prev_row_count = cur_rows

        grew = resp["length"] > base_length
        tag = "↑ MORE" if (held and grew) else ("✓ held" if held else "✗ fail")
        logger.info(
            "  [PAG]   %s=%s  HTTP %s  len %d  rows %s  %s",
            param_name, limit_val, resp["status"], resp["length"],
            cur_rows if cur_rows is not None else "?", tag,
        )

        _persist_pagination(result)
        results.append(result)

        # If the bypass fails, stop escalating.
        if not held:
            break

    # ── Back-fill the cap onto earlier results if detected later ──
    if detected_cap is not None:
        for r in results:
            if r["hard_cap"] is None and r["bypass_held"]:
                r["hard_cap"] = detected_cap
                _update_hard_cap(r, detected_cap)

    return results


# ═══════════════════════════════════════════════════════════════════════
#  Offset / page jumping
# ═══════════════════════════════════════════════════════════════════════

def _probe_offset_jump(
    base_url: str,
    method: str,
    variables: list[dict],
    bypass_status: int,
    combo_key: str,
    endpoint_id: int,
    param_name: str,
    original_value: str,
) -> list[dict]:
    """
    Jump offset/page values to find the maximum reachable segment.
    Stops when a probe returns 403, empty body, or error.
    """
    results: list[dict] = []
    last_held_value: str | None = None

    for jump_val in _OFFSET_JUMPS:
        probe_url = _set_query_param(base_url, param_name, str(jump_val))
        probe_req = _build_combo_request(probe_url, method, variables)

        result: dict = {
            "endpoint_id":    endpoint_id,
            "combo_key":      combo_key,
            "param_name":     param_name,
            "probe_type":     "offset_jump",
            "original_value": original_value,
            "probed_value":   str(jump_val),
            "probe_url":      probe_url,
            "http_status":    None,
            "body_length":    0,
            "row_count_est":  None,
            "bypass_held":    False,
            "is_max_reached": False,
            "hard_cap":       None,
            "error":          None,
        }

        try:
            resp = _execute_request(
                probe_req["method"], probe_req["url"],
                probe_req["headers"], probe_req["primer_methods"],
            )
        except Exception as exc:
            result["error"] = str(exc)
            # Mark the previous successful value as max reached.
            _mark_max_reached(results, last_held_value)
            _persist_pagination(result)
            results.append(result)
            break

        if resp["error"] is not None:
            result["error"] = str(resp["error"])
            _mark_max_reached(results, last_held_value)
            _persist_pagination(result)
            results.append(result)
            break

        result["http_status"] = resp["status"]
        result["body_length"] = resp["length"]

        held = resp["status"] == bypass_status and resp["length"] >= 50
        result["bypass_held"] = held

        if held:
            result["row_count_est"] = _estimate_row_count(resp["body"])
            last_held_value = str(jump_val)
        else:
            # This jump failed — previous value is the max.
            _mark_max_reached(results, last_held_value)

        tag = "✓ held" if held else "✗ BOUNDARY"
        logger.info(
            "  [PAG]   %s=%s  HTTP %s  len %d  %s",
            param_name, jump_val, resp["status"], resp["length"], tag,
        )

        _persist_pagination(result)
        results.append(result)

        if not held:
            break

    # If all jumps succeeded, mark the last one as max reached.
    if last_held_value is not None:
        exhausted = all(r["bypass_held"] for r in results if r["probe_type"] == "offset_jump")
        if exhausted:
            _mark_max_reached(results, last_held_value)

    return results


# ═══════════════════════════════════════════════════════════════════════
#  Internal helpers
# ═══════════════════════════════════════════════════════════════════════

def _load_variables(var_ids: list[int]) -> list[dict]:
    """Load variable details from ``policy_variables`` by ID list."""
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


def _set_query_param(url: str, key: str, value: str) -> str:
    """Return *url* with query parameter *key* set to *value*."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[key] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment,
    ))


def _estimate_row_count(body: str) -> int | None:
    """
    Cheap heuristic: if the body is a JSON array, count top-level
    elements.  Otherwise return ``None``.
    """
    if not body or not _JSON_ARRAY_LEN_RE.match(body):
        return None
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(data, list):
        return len(data)
    return None


def _mark_max_reached(
    results: list[dict], value: str | None,
) -> None:
    """
    Mark the result with ``probed_value == value`` as the max-reached
    boundary in the results list.
    """
    if value is None:
        return
    for r in results:
        if r["probed_value"] == value and r["bypass_held"]:
            r["is_max_reached"] = True
            # Also update the DB.
            conn = get_connection()
            try:
                conn.execute(
                    """
                    UPDATE pagination_reach
                       SET is_max_reached = 1
                     WHERE endpoint_id = ?
                       AND combo_key = ?
                       AND param_name = ?
                       AND probed_value = ?
                    """,
                    (
                        r["endpoint_id"],
                        r["combo_key"],
                        r["param_name"],
                        value,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
            break


def _persist_pagination(result: dict) -> None:
    """Upsert one pagination probe result into ``pagination_reach``."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO pagination_reach
                (endpoint_id, combo_key, param_name, probe_type,
                 original_value, probed_value, probe_url,
                 http_status, body_length, row_count_est,
                 bypass_held, is_max_reached, hard_cap, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(endpoint_id, combo_key, param_name, probed_value)
            DO UPDATE SET
                probe_type     = excluded.probe_type,
                original_value = excluded.original_value,
                probe_url      = excluded.probe_url,
                http_status    = excluded.http_status,
                body_length    = excluded.body_length,
                row_count_est  = excluded.row_count_est,
                bypass_held    = excluded.bypass_held,
                is_max_reached = excluded.is_max_reached,
                hard_cap       = excluded.hard_cap,
                error          = excluded.error
            """,
            (
                result["endpoint_id"],
                result["combo_key"],
                result["param_name"],
                result["probe_type"],
                result["original_value"],
                result["probed_value"],
                result["probe_url"],
                result["http_status"],
                result["body_length"],
                result["row_count_est"],
                1 if result["bypass_held"] else 0,
                1 if result["is_max_reached"] else 0,
                result.get("hard_cap"),
                result["error"],
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _update_hard_cap(result: dict, cap: int) -> None:
    """Update an existing ``pagination_reach`` row with the detected cap."""
    conn = get_connection()
    try:
        conn.execute(
            """
            UPDATE pagination_reach
               SET hard_cap = ?
             WHERE endpoint_id = ?
               AND combo_key   = ?
               AND param_name  = ?
               AND probed_value = ?
            """,
            (
                cap,
                result["endpoint_id"],
                result["combo_key"],
                result["param_name"],
                result["probed_value"],
            ),
        )
        conn.commit()
    finally:
        conn.close()
