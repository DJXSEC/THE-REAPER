"""
Identifier-structure analysis for Arbiter-403  (traversal module).

After a bypass is confirmed, this module inspects the object identifiers
present in the response body (numeric IDs, UUIDs, hashes, etc.) and
determines whether they are **predictable or enumerable**.

Key output
----------
* **id_type** — ``Sequential Integer``, ``UUID``, ``Hex Hash``,
  ``Alphanumeric Token``, or ``Opaque``.
* **predictability** — ``Highly Enumerable``, ``Partially Predictable``,
  ``Non-Predictable``, or ``Unknown``.
* **scope_test_urls** — when IDs are sequential, a short list of adjacent
  IDs (±1 … ±5) resolved to absolute URLs, ready for a scope-test.
"""

from __future__ import annotations

import json
import logging
import math
import re
from urllib.parse import urlparse

from bypasser.db import get_connection  # type: ignore
from bypasser.probing import _execute_request  # type: ignore
from bypasser.transitions import _build_combo_request  # type: ignore

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
#  Identifier regexes (ordered by specificity — checked first wins)
# ═══════════════════════════════════════════════════════════════════════

# UUIDv4 (and other UUID versions)
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
)

# Hex hash — 32 (MD5), 40 (SHA-1), 64 (SHA-256) hex chars
_HEX_HASH_RE = re.compile(r"\b[0-9a-fA-F]{32}(?:[0-9a-fA-F]{8})?(?:[0-9a-fA-F]{24})?\b")

# Pure numeric (at least 2 digits to avoid matching single-char noise)
_NUMERIC_ID_RE = re.compile(r"\b\d{2,}\b")

# Alphanumeric token (Base64-ish, 16+ chars)
_ALPHANUM_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_-]{16,}\b")

# JSON keys whose values are likely identifiers
_ID_KEY_RE = re.compile(
    r"(?:_id|Id$|_key|_token|_hash|_uuid|_ref|_code|_number|"
    r"id$|key$|token$|hash$|uuid$|ref$|code$|number$)",
    re.IGNORECASE,
)

# Numeric segment in a URL path
_PATH_NUMERIC_RE = re.compile(r"(?<=/)\d{2,}(?=/|$)")


# ═══════════════════════════════════════════════════════════════════════
#  Public API
# ═══════════════════════════════════════════════════════════════════════

def analyze_identifier_structure(endpoint_id: int) -> list[dict]:
    """
    For every verified bypass on *endpoint_id*, extract identifiers
    from the response body and the URL, classify their type and
    predictability, and produce scope-test URLs for enumerable IDs.

    Extraction sources
    ------------------
    1. **URL path** — numeric segments in the bypassed URL.
    2. **JSON body** — values of keys matching ``_ID_KEY_RE``.
    3. **Full body scan** — UUIDs, hex hashes, and numeric IDs found
       anywhere in the response text.

    Classification
    --------------
    Each extracted ID is classified into:

    * **Sequential Integer** — pure digits, typically auto-increment PKs.
    * **UUID** — matches the UUID format (any version).
    * **Hex Hash** — 32 / 40 / 64 hex characters.
    * **Alphanumeric Token** — base64-style, 16+ characters.
    * **Opaque** — none of the above.

    Predictability assessment
    -------------------------
    When multiple numeric IDs are found for the same endpoint, the
    function analyses the gaps between sorted values:

    * All gaps ≤ 10 → **Highly Enumerable** (sequential / near-sequential).
    * Mean gap ≤ 100 → **Partially Predictable**.
    * Otherwise → **Non-Predictable**.

    UUIDs (v4) and long hex hashes are always **Non-Predictable**.
    Alphanumeric tokens are **Unknown** by default.

    Scope-test preparation
    ----------------------
    For every **Highly Enumerable** integer ID, the function generates
    up to 10 adjacent probe URLs (``id ± 1 … ± 5``), resolved against
    the original endpoint URL.

    Returns
    -------
    list[dict]
        One dict per extracted identifier::

            {
                "endpoint_id":    int,
                "combo_key":      str,
                "id_value":       str,
                "id_type":        str,
                "source":         str,   # "url_path" / "json_key:…" / "body_scan"
                "is_sequential":  bool,
                "gap_size":       int | None,
                "entropy":        float,
                "predictability": str,
                "scope_test_urls": list[str],
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
            SELECT ca.id, ca.combination_id, ca.transition_type,
                   ca.new_status
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
            "[TRAV] endpoint %d: no verified candidates to analyse.",
            endpoint_id,
        )
        return []

    base_url: str = ep["url"]
    method: str   = ep["method"]

    all_results: list[dict] = []

    for cand in candidates:
        combo_info = json.loads(cand["combination_id"])
        combo_key  = combo_info["combo_key"]
        var_ids    = combo_info["variable_ids"]

        variables = _load_variables(var_ids)
        if not variables:
            continue

        # ── 1.  Re-fetch the bypass body ──────────────────────────
        req = _build_combo_request(base_url, method, variables)
        resp = _execute_request(
            req["method"], req["url"], req["headers"],
            req["primer_methods"],
        )
        if resp["error"] is not None:
            continue

        body: str = resp["body"]

        # ── 2.  Extract identifiers ───────────────────────────────
        raw_ids = _extract_identifiers(body, base_url)

        if not raw_ids:
            logger.info(
                "  [TRAV] %-28s  no identifiers found.", combo_key,
            )
            continue

        # ── 3.  Classify & assess predictability ──────────────────
        numeric_values: list[int] = []
        combo_results: list[dict] = []

        for source, id_value in raw_ids:
            id_type = _classify_id(id_value)
            entropy = _shannon_entropy(id_value)
            predictability = "Unknown"

            if id_type == "Sequential Integer":
                numeric_values.append(int(id_value))
            elif id_type == "UUID":
                predictability = "Non-Predictable"
            elif id_type == "Hex Hash":
                predictability = "Non-Predictable"

            combo_results.append({
                "endpoint_id":    endpoint_id,
                "combo_key":      combo_key,
                "id_value":       id_value,
                "id_type":        id_type,
                "source":         source,
                "is_sequential":  False,
                "gap_size":       None,
                "entropy":        int(entropy * 10000) / 10000,
                "predictability": predictability,
                "scope_test_urls": [],
            })

        # ── 4.  Sequential analysis for numeric IDs ───────────────
        if len(numeric_values) >= 2:
            sorted_nums = sorted(set(numeric_values))
            gaps = [
                sorted_nums[i + 1] - sorted_nums[i]
                for i in range(len(sorted_nums) - 1)
            ]
            max_gap  = max(gaps) if gaps else 0
            mean_gap = sum(gaps) / len(gaps) if gaps else 0

            if max_gap <= 10:
                seq_label = "Highly Enumerable"
            elif mean_gap <= 100:
                seq_label = "Partially Predictable"
            else:
                seq_label = "Non-Predictable"

            for r in combo_results:
                if r["id_type"] == "Sequential Integer":
                    r["predictability"] = seq_label
                    r["is_sequential"]  = (max_gap <= 10)
                    r["gap_size"]       = max_gap

                    if seq_label == "Highly Enumerable":
                        r["scope_test_urls"] = _build_scope_urls(
                            base_url, r["id_value"],
                        )
        elif len(numeric_values) == 1:
            # Single numeric ID — assume potentially enumerable.
            for r in combo_results:
                if r["id_type"] == "Sequential Integer":
                    r["predictability"] = "Highly Enumerable"
                    r["is_sequential"]  = True
                    r["gap_size"]       = 1
                    r["scope_test_urls"] = _build_scope_urls(
                        base_url, r["id_value"],
                    )

        # ── 5.  Persist ───────────────────────────────────────────
        for r in combo_results:
            _persist_analysis(r)

        all_results.extend(combo_results)

        enumerable = sum(1 for r in combo_results if r["is_sequential"])
        logger.info(
            "  [TRAV] %-28s  %d id(s) extracted, %d enumerable",
            combo_key, len(combo_results), enumerable,
        )

    logger.info(
        "[TRAV] endpoint %d: analysed %d identifier(s) across %d "
        "candidate(s).",
        endpoint_id, len(all_results), len(candidates),
    )

    return all_results


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


def _extract_identifiers(
    body: str, base_url: str,
) -> list[tuple[str, str]]:
    """
    Extract (source, id_value) pairs from *body* and from
    URL path segments.

    De-duplicates by id_value.
    """
    seen: set[str] = set()
    results: list[tuple[str, str]] = []

    def _add(source: str, value: str) -> None:
        value = value.strip()
        if not value or value in seen:
            return
        seen.add(value)
        results.append((source, value))

    # 1.  URL path — numeric segments
    for m in _PATH_NUMERIC_RE.findall(base_url):
        _add("url_path", m)

    # 2.  JSON body — ID-like keys
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        data = None

    if isinstance(data, (dict, list)):
        _walk_json_ids(data, _add)

    # 3.  Full body scan — UUIDs first, then hashes, then integers
    for m in _UUID_RE.findall(body):
        _add("body_scan", m)
    for m in _HEX_HASH_RE.findall(body):
        if len(m) in (32, 40, 64):
            _add("body_scan", m)
    for m in _NUMERIC_ID_RE.findall(body):
        # Filter out very short or very common numbers (years, etc.)
        if len(m) >= 3 or int(m) > 50:
            _add("body_scan", m)

    return results


def _walk_json_ids(
    obj: object,
    add_fn: object,
) -> None:
    """Recursively walk JSON and yield values of ID-like keys."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if _ID_KEY_RE.search(key) and isinstance(value, (str, int, float)):
                str_val = str(value).strip()
                if str_val and str_val not in ("", "null", "None", "0"):
                    add_fn(f"json_key:{key}", str_val)  # type: ignore[operator]
            if isinstance(value, (dict, list)):
                _walk_json_ids(value, add_fn)
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                _walk_json_ids(item, add_fn)


def _classify_id(value: str) -> str:
    """Classify an identifier string into a type category."""
    if _UUID_RE.fullmatch(value):
        return "UUID"
    if _HEX_HASH_RE.fullmatch(value) and len(value) in (32, 40, 64):
        return "Hex Hash"
    if value.isdigit():
        return "Sequential Integer"
    if _ALPHANUM_TOKEN_RE.fullmatch(value):
        return "Alphanumeric Token"
    return "Opaque"


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits per character) of *s*."""
    if not s:
        return 0.0
    length = len(s)
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)  # type: ignore
    return entropy


def _build_scope_urls(base_url: str, id_value: str) -> list[str]:
    """
    For a sequential numeric *id_value*, generate up to 10 adjacent
    probe URLs by replacing the matching segment in *base_url*.

    Probes: id - 5 … id - 1, id + 1 … id + 5  (skipping negatives).
    """
    try:
        int_id = int(id_value)
    except ValueError:
        return []

    parsed = urlparse(base_url)
    path = parsed.path

    # Find the segment matching id_value in the URL path.
    pattern = re.compile(rf"(?<=/)({re.escape(id_value)})(?=/|$)")
    if not pattern.search(path):
        # If the exact ID isn't in the path, try to find any numeric
        # segment to replace (for IDs found in the body).
        pattern = re.compile(r"(?<=/)(\d{2,})(?=/|$)")
        if not pattern.search(path):
            return []

    urls: list[str] = []
    for offset in range(-5, 6):
        if offset == 0:
            continue
        probe_id = int_id + offset
        if probe_id < 0:
            continue
        new_path = pattern.sub(str(probe_id), path, count=1)
        probe_url = (
            f"{parsed.scheme}://{parsed.netloc}{new_path}"
        )
        if parsed.query:
            probe_url += f"?{parsed.query}"
        urls.append(probe_url)

    return urls


def _persist_analysis(result: dict) -> None:
    """Upsert one identifier analysis row into ``identifier_analysis``."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO identifier_analysis
                (endpoint_id, combo_key, id_value, id_type,
                 source, is_sequential, gap_size, entropy,
                 predictability, scope_test_urls)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(endpoint_id, combo_key, id_value) DO UPDATE SET
                id_type        = excluded.id_type,
                source         = excluded.source,
                is_sequential  = excluded.is_sequential,
                gap_size       = excluded.gap_size,
                entropy        = excluded.entropy,
                predictability = excluded.predictability,
                scope_test_urls = excluded.scope_test_urls
            """,
            (
                result["endpoint_id"],
                result["combo_key"],
                result["id_value"],
                result["id_type"],
                result["source"],
                1 if result["is_sequential"] else 0,
                result["gap_size"],
                result["entropy"],
                result["predictability"],
                json.dumps(result["scope_test_urls"]),
            ),
        )
        conn.commit()
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════
#  Dataset boundary probing
# ═══════════════════════════════════════════════════════════════════════

# Offsets to probe in each direction (positive and negative).
_BOUNDARY_OFFSETS = [-10_000, -1_000, -100, -10, 10, 100, 1_000, 10_000]


def probe_dataset_boundaries(endpoint_id: int) -> list[dict]:
    """
    For every **Highly Enumerable** sequential ID found on
    *endpoint_id*, probe IDs at large offsets to test whether the
    authorisation bypass holds across the logical range of the
    underlying table / dataset.

    This is **not** a full crawl.  It sends a small, fixed number of
    requests (8 per enumerable ID) at strategically chosen distances:
    ±10, ±100, ±1 000, ±10 000.

    Probe mechanics
    ---------------
    For each offset the function:

    1. Constructs a probe URL by replacing the numeric segment in the
       original endpoint URL with ``original_id + offset``.
    2. Re-executes the same bypass combination that was already verified.
    3. Compares the response to the original bypass response to decide
       whether the bypass still holds (``bypass_held``).

    A probe is considered successful (``bypass_held = 1``) when:

    * The HTTP status matches the bypass status (e.g. 200), **and**
    * The response body is non-trivially long (≥ 50 bytes), **and**
    * The body is *not* identical to a known 403 / error page.

    An optional ``body_similarity`` (0.0 – 1.0) is computed via Jaccard
    token overlap against the original bypass body to help gauge
    whether the returned data is structurally similar.

    Persistence
    -----------
    Every probe result (success or failure) is upserted into the
    ``dataset_reach`` table.

    Parameters
    ----------
    endpoint_id : int
        The primary key of the endpoint in the ``endpoints`` table.

    Returns
    -------
    list[dict]
        One dict per probe::

            {
                "endpoint_id":     int,
                "combo_key":       str,
                "original_id":     str,
                "probed_id":       str,
                "offset":          int,
                "probe_url":       str,
                "http_status":     int | None,
                "body_length":     int,
                "bypass_held":     bool,
                "body_similarity": float,
                "error":           str | None,
            }
    """
    # ── 0.  Pull enumerable IDs from identifier_analysis ──────────
    conn = get_connection()
    try:
        ep = conn.execute(
            "SELECT id, url, method FROM endpoints WHERE id = ?",
            (endpoint_id,),
        ).fetchone()
        if ep is None:
            raise ValueError(f"endpoint_id {endpoint_id} not found.")

        enum_rows = conn.execute(
            """
            SELECT ia.combo_key, ia.id_value
              FROM identifier_analysis ia
             WHERE ia.endpoint_id   = ?
               AND ia.is_sequential = 1
               AND ia.predictability = 'Highly Enumerable'
             ORDER BY ia.id
            """,
            (endpoint_id,),
        ).fetchall()

        # We also need the bypass combo info for each combo_key.
        cand_rows = conn.execute(
            """
            SELECT ca.combination_id, ca.new_status
              FROM candidate_access ca
             WHERE ca.endpoint_id = ?
               AND ca.is_verified = 1
            """,
            (endpoint_id,),
        ).fetchall()
    finally:
        conn.close()

    if not enum_rows:
        logger.info(
            "[TRAV-REACH] endpoint %d: no enumerable IDs to probe.",
            endpoint_id,
        )
        return []

    base_url: str = ep["url"]
    method: str   = ep["method"]
    parsed        = urlparse(base_url)

    # Build a lookup: combo_key → (variable_ids, bypass_status).
    combos_by_key: dict[str, dict] = {}
    for cr in cand_rows:
        info = json.loads(cr["combination_id"])
        combos_by_key[info["combo_key"]] = {
            "variable_ids":  info["variable_ids"],
            "bypass_status": cr["new_status"],
        }

    all_results: list[dict] = []

    for er in enum_rows:
        combo_key: str = er["combo_key"]
        original_id: str = er["id_value"]

        combo_info = combos_by_key.get(combo_key)
        if combo_info is None:
            continue

        variables = _load_variables(combo_info["variable_ids"])
        if not variables:
            continue

        bypass_status: int = combo_info["bypass_status"]

        try:
            int_id = int(original_id)
        except ValueError:
            continue

        # Build the original bypass request once — we need the
        # reference body for similarity comparison.
        ref_req = _build_combo_request(base_url, method, variables)
        ref_resp = _execute_request(
            ref_req["method"], ref_req["url"], ref_req["headers"],
            ref_req["primer_methods"],
        )
        ref_body: str = ref_resp["body"] if ref_resp["error"] is None else ""

        # Locate the numeric segment in the path to replace.
        id_pattern = re.compile(
            rf"(?<=/)({re.escape(original_id)})(?=/|$)",
        )
        if not id_pattern.search(parsed.path):
            id_pattern = re.compile(r"(?<=/)(\d{2,})(?=/|$)")
            if not id_pattern.search(parsed.path):
                logger.info(
                    "  [TRAV-REACH] %-28s  cannot locate ID in path, "
                    "skipping.", combo_key,
                )
                continue

        logger.info(
            "[TRAV-REACH] %-28s  probing boundaries around ID %s",
            combo_key, original_id,
        )

        for offset in _BOUNDARY_OFFSETS:
            probed_int = int_id + offset
            if probed_int < 0:
                continue
            probed_id = str(probed_int)

            # Build probe URL.
            new_path = id_pattern.sub(probed_id, parsed.path, count=1)
            probe_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
            if parsed.query:
                probe_url += f"?{parsed.query}"

            # Execute the bypass combo against the probe URL.
            probe_req = _build_combo_request(
                probe_url, method, variables,
            )

            result: dict = {
                "endpoint_id":     endpoint_id,
                "combo_key":       combo_key,
                "original_id":     original_id,
                "probed_id":       probed_id,
                "offset":          offset,
                "probe_url":       probe_url,
                "http_status":     None,
                "body_length":     0,
                "bypass_held":     False,
                "body_similarity": 0.0,
                "error":           None,
            }

            try:
                resp = _execute_request(
                    probe_req["method"], probe_req["url"],
                    probe_req["headers"], probe_req["primer_methods"],
                )
            except Exception as exc:
                err_msg = str(exc)
                result["error"] = err_msg[:500] if len(err_msg) > 500 else err_msg  # type: ignore
                _persist_reach(result)
                all_results.append(result)
                continue

            if resp["error"] is not None:
                err_msg = str(resp["error"])
                result["error"] = err_msg[:500] if len(err_msg) > 500 else err_msg  # type: ignore
                _persist_reach(result)
                all_results.append(result)
                continue

            result["http_status"]  = resp["status"]
            result["body_length"]  = resp["length"]

            # Decide if the bypass held.
            body = resp["body"]
            held = (
                resp["status"] == bypass_status
                and resp["length"] >= 50
            )
            result["bypass_held"] = held

            # Similarity to the reference bypass body.
            if ref_body and body:
                result["body_similarity"] = _jaccard_tokens(
                    ref_body, body,
                )

            _persist_reach(result)
            all_results.append(result)

            tag = "✓ HELD" if held else "✗ fail"
            logger.info(
                "  [TRAV-REACH]   offset %+6d → ID %-10s  "
                "HTTP %s  len %d  %s",
                offset, probed_id,
                resp["status"], resp["length"], tag,
            )

    # ── Summary ───────────────────────────────────────────────────
    held_count = sum(1 for r in all_results if r["bypass_held"])
    logger.info(
        "[TRAV-REACH] endpoint %d: %d probe(s) sent, %d bypass(es) held.",
        endpoint_id, len(all_results), held_count,
    )
    return all_results


# ───────────────────────────────────────────────────────────────────────
#  Persistence helper for dataset_reach
# ───────────────────────────────────────────────────────────────────────

def _persist_reach(result: dict) -> None:
    """Upsert one boundary probe result into ``dataset_reach``."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO dataset_reach
                (endpoint_id, combo_key, original_id, probed_id,
                 offset, probe_url, http_status, body_length,
                 bypass_held, body_similarity, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(endpoint_id, combo_key, probed_id) DO UPDATE SET
                offset         = excluded.offset,
                probe_url      = excluded.probe_url,
                http_status    = excluded.http_status,
                body_length    = excluded.body_length,
                bypass_held    = excluded.bypass_held,
                body_similarity = excluded.body_similarity,
                error          = excluded.error
            """,
            (
                result["endpoint_id"],
                result["combo_key"],
                result["original_id"],
                result["probed_id"],
                result["offset"],
                result["probe_url"],
                result["http_status"],
                result["body_length"],
                1 if result["bypass_held"] else 0,
                result["body_similarity"],
                result["error"],
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _jaccard_tokens(a: str, b: str) -> float:
    """Jaccard similarity of whitespace-split token sets (0.0 – 1.0)."""
    set_a = set(a.split())
    set_b = set(b.split())
    if not set_a and not set_b:
        return 1.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    if union == 0:
        return 0.0
    return intersection / union


# ═══════════════════════════════════════════════════════════════════════
#  Total-exposure estimation  (Phase M input)
# ═══════════════════════════════════════════════════════════════════════

def estimate_total_exposure(endpoint_id: int) -> dict:
    """
    Combine identifier density, boundary probes, and pagination reach
    to compute a **Projected Reach** — the estimated number of records
    reachable through the confirmed authorisation bypass on
    *endpoint_id*.

    Data sources
    ------------
    1. **identifier_analysis** — sequential IDs give a minimum span
       (max_id − min_id + 1).  Multiple enumerable IDs widen the
       estimate.
    2. **dataset_reach** — boundary probes at ±10 000 show how far
       the bypass holds.  The largest successful offset determines the
       "confirmed radius".
    3. **pagination_reach** — limit escalation + offset jumping
       reveal how many pages / records the server exposes per request,
       and whether a silent hard-cap limits batch size.

    Estimation strategy
    -------------------
    * **ID span** — ``max(probed_id) − min(probed_id) + 1`` across
      all boundary probes that held, clamped to the sequential range
      if available.
    * **Pagination multiplier** — if offset jumping reached page N
      and the hard-cap is C items per page, the pagination layer
      alone exposes ``N × C`` records.
    * **Final estimate** — ``max(id_span, pagination_estimate)``
      with a confidence tier (High / Medium / Low / Speculative)
      based on the quality of the underlying evidence.

    Returns
    -------
    dict
        ::

            {
                "endpoint_id":          int,
                "projected_reach":      int,    # headline number
                "reach_formatted":      str,    # e.g. "~50,000"
                "confidence":           str,    # High / Medium / Low / Speculative
                "id_span":              int | None,
                "boundary_radius":      int | None,
                "boundary_held_pct":    float,  # 0.0–1.0
                "pagination_estimate":  int | None,
                "hard_cap":             int | None,
                "max_offset_reached":   int | None,
                "evidence_summary":     str,
            }
    """
    conn = get_connection()
    try:
        # ── A.  Endpoint sanity check ─────────────────────────────
        ep = conn.execute(
            "SELECT id, url FROM endpoints WHERE id = ?",
            (endpoint_id,),
        ).fetchone()
        if ep is None:
            raise ValueError(f"endpoint_id {endpoint_id} not found.")

        # ── B.  Identifier analysis ───────────────────────────────
        id_rows = conn.execute(
            """
            SELECT id_value, id_type, is_sequential, predictability
              FROM identifier_analysis
             WHERE endpoint_id = ?
             ORDER BY id
            """,
            (endpoint_id,),
        ).fetchall()

        # ── C.  Boundary probes ───────────────────────────────────
        reach_rows = conn.execute(
            """
            SELECT original_id, probed_id, offset, bypass_held
              FROM dataset_reach
             WHERE endpoint_id = ?
             ORDER BY offset
            """,
            (endpoint_id,),
        ).fetchall()

        # ── D.  Pagination probes ─────────────────────────────────
        pag_rows = conn.execute(
            """
            SELECT param_name, probe_type, probed_value,
                   row_count_est, bypass_held, is_max_reached,
                   hard_cap
              FROM pagination_reach
             WHERE endpoint_id = ?
             ORDER BY id
            """,
            (endpoint_id,),
        ).fetchall()
    finally:
        conn.close()

    # ── 1.  ID-span estimation ────────────────────────────────────
    id_span: int | None = None
    sequential_ids: list[int] = []

    for row in id_rows:
        if row["is_sequential"]:
            try:
                sequential_ids.append(int(row["id_value"]))
            except ValueError:
                pass

    # Extend with boundary probes that held.
    for row in reach_rows:
        if row["bypass_held"]:
            try:
                sequential_ids.append(int(row["probed_id"]))
            except ValueError:
                pass

    if sequential_ids:
        id_span = max(sequential_ids) - min(sequential_ids) + 1

    # ── 2.  Boundary radius ───────────────────────────────────────
    boundary_radius: int | None = None
    total_probes = len(reach_rows)
    held_probes  = sum(1 for r in reach_rows if r["bypass_held"])
    boundary_held_pct = held_probes / total_probes if total_probes else 0.0

    if reach_rows:
        held_offsets = [
            abs(r["offset"]) for r in reach_rows if r["bypass_held"]
        ]
        if held_offsets:
            boundary_radius = max(held_offsets)

    # ── 3.  Pagination estimation ─────────────────────────────────
    pagination_estimate: int | None = None
    hard_cap: int | None = None
    max_offset_reached: int | None = None

    # Find hard cap across all limit-escalation probes.
    for row in pag_rows:
        if row["hard_cap"] is not None:
            cap = int(row["hard_cap"])
            if hard_cap is None:
                hard_cap = cap
            elif cap < hard_cap:  # type: ignore
                hard_cap = cap

    # Find max offset/page that held.
    for row in pag_rows:
        if row["probe_type"] == "offset_jump" and row["bypass_held"]:
            try:
                val = int(row["probed_value"])
            except ValueError:
                continue
            if max_offset_reached is None:
                max_offset_reached = val
            elif val > max_offset_reached:  # type: ignore
                max_offset_reached = val

    # If we know both the max offset and items per page, we can
    # estimate total accessible records.
    if max_offset_reached is not None:
        items_per_page = hard_cap
        if items_per_page is None:
            # Use the largest row_count_est from successful probes.
            max_rows = 0
            for row in pag_rows:
                if row["bypass_held"] and row["row_count_est"] is not None:
                    rc = int(row["row_count_est"])
                    if rc > max_rows:
                        max_rows = rc
            items_per_page = max_rows if max_rows > 0 else None

        if items_per_page is not None and items_per_page > 0:
            ipp: int = items_per_page  # local binding for type checker
            pagination_estimate = (max_offset_reached * ipp) if max_offset_reached else 0  # type: ignore
        else:
            # Fall back to treating max_offset as a record count.
            pagination_estimate = max_offset_reached

    # ── 4.  Projected Reach (take the largest signal) ─────────────
    candidates: list[int] = []
    if id_span is not None:
        candidates.append(id_span)
    if pagination_estimate is not None:
        candidates.append(pagination_estimate)
    if boundary_radius is not None:
        # Radius covers ±N, so the span is 2 × radius + 1.
        candidates.append(2 * boundary_radius + 1)

    projected_reach = max(candidates) if candidates else 0

    # ── 5.  Confidence tier ───────────────────────────────────────
    #  High       — both boundary probes & pagination confirm reach.
    #  Medium     — at least one strong signal (ID-span or pagination).
    #  Low        — only sequential IDs with no probing confirmation.
    #  Speculative — no meaningful data at all.
    signals = sum([
        id_span is not None and id_span > 1,
        boundary_radius is not None and boundary_held_pct > 0.5,
        pagination_estimate is not None and pagination_estimate > 0,
    ])
    if signals >= 2:
        confidence = "High"
    elif signals == 1:
        confidence = "Medium"
    elif sequential_ids:
        confidence = "Low"
    else:
        confidence = "Speculative"

    # ── 6.  Evidence summary (human-readable) ─────────────────────
    parts: list[str] = []
    if id_span is not None:
        parts.append(f"ID span: {_fmt_number(id_span)} records")
    if boundary_radius is not None:
        parts.append(
            f"Boundary probes held to ±{_fmt_number(boundary_radius)} "
            f"({held_probes}/{total_probes} held)"
        )
    if pagination_estimate is not None:
        parts.append(
            f"Pagination: ~{_fmt_number(pagination_estimate)} records"
        )
    if hard_cap is not None:
        parts.append(f"Silent cap: {hard_cap} items/request")
    if not parts:
        parts.append("Insufficient data for estimation")

    evidence_summary = "; ".join(parts)

    result = {
        "endpoint_id":         endpoint_id,
        "projected_reach":     projected_reach,
        "reach_formatted":     f"~{_fmt_number(projected_reach)}"
                               if projected_reach > 0 else "Unknown",
        "confidence":          confidence,
        "id_span":             id_span,
        "boundary_radius":     boundary_radius,
        "boundary_held_pct":   boundary_held_pct,
        "pagination_estimate": pagination_estimate,
        "hard_cap":            hard_cap,
        "max_offset_reached":  max_offset_reached,
        "evidence_summary":    evidence_summary,
    }

    logger.info(
        "[TRAV-EXPOSURE] endpoint %d: Projected Reach = %s  "
        "(%s confidence)  |  %s",
        endpoint_id,
        result["reach_formatted"],
        confidence,
        evidence_summary,
    )

    return result


def _fmt_number(n: int) -> str:
    """Format an integer with comma separators (e.g. ``50,000``)."""
    return f"{n:,}"
