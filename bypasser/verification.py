"""
Content profiling for Arbiter-403  (Section F).

After a candidate bypass is identified (a transition from 403 to a
different status or to a richer body), this module re-fetches the
response and analyses what was exposed compared to the baseline 403.

Exposed-content profile
-----------------------
* **Content type detection** — JSON, HTML, XML, or Plain Text.
* **Content Richness Score** — ratio of unique structural elements
  (keys, tags, or lines) in the bypass response versus the baseline
  403 body.  A score of ``1.0`` means identical richness; ``> 1.0``
  means the bypass revealed new content.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

from bypasser.baseline import calculate_entropy, USER_AGENT
from bypasser.db import get_connection
from bypasser.probing import _execute_request
from bypasser.transitions import _build_combo_request

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
#  Public API
# ═══════════════════════════════════════════════════════════════════════

def profile_exposed_content(endpoint_id: int) -> list[dict]:
    """
    For every candidate bypass on *endpoint_id*, re-fetch the
    response and produce a content profile.

    Steps per candidate
    -------------------
    1. Look up the variable combo from ``candidate_access`` →
       ``policy_variables``.
    2. Rebuild and execute the bypass request.
    3. Detect the content type of the response body.
    4. Count unique structural elements (keys / tags / lines).
    5. Do the same for the baseline 403 body.
    6. Compute the **Content Richness Score**::

           richness = bypass_unique_elements / baseline_unique_elements

       (capped at ``0.0`` when the baseline has zero elements).

    Returns
    -------
    list[dict]
        One profile dict per candidate::

            {
                "endpoint_id":          int,
                "combo_key":            str,
                "content_type":         str,   # "JSON" / "HTML" / "XML" / "Plain Text"
                "bypass_status":        int,
                "bypass_length":        int,
                "bypass_entropy":       float,
                "bypass_unique_count":  int,
                "baseline_unique_count": int,
                "richness_score":       float,
                "sample_elements":      list[str],  # first 10 unique elements
            }
    """
    # ── 0.  Fetch endpoint + baseline body ─────────────────────────
    conn = get_connection()
    try:
        ep = conn.execute(
            """
            SELECT id, url, method, status_code, body_length,
                   fingerprint_group_id
              FROM endpoints WHERE id = ?
            """,
            (endpoint_id,),
        ).fetchone()

        if ep is None:
            raise ValueError(f"endpoint_id {endpoint_id} not found.")

        baseline_body = ""
        fp_gid = ep["fingerprint_group_id"]
        if fp_gid:
            body_row = conn.execute(
                "SELECT canonical_body FROM fingerprint_groups "
                "WHERE group_id = ?",
                (fp_gid,),
            ).fetchone()
            if body_row and body_row["canonical_body"]:
                baseline_body = body_row["canonical_body"]

        # ── 1.  Fetch candidates for this endpoint ─────────────────
        candidates = conn.execute(
            """
            SELECT ca.id, ca.combination_id, ca.transition_type,
                   ca.new_status, ca.new_length
              FROM candidate_access ca
             WHERE ca.endpoint_id = ?
             ORDER BY ca.id
            """,
            (endpoint_id,),
        ).fetchall()
    finally:
        conn.close()

    if not candidates:
        logger.info(
            "[F] endpoint %d: no candidates to profile.", endpoint_id,
        )
        return []

    url: str    = ep["url"]
    method: str = ep["method"]

    profiles: list[dict] = []

    for cand in candidates:
        combo_info = json.loads(cand["combination_id"])
        combo_key  = combo_info["combo_key"]
        var_ids    = combo_info["variable_ids"]

        # ── 2.  Load the variable details ──────────────────────────
        variables = _load_variables(var_ids)
        if not variables:
            logger.warning(
                "[F] combo '%s': could not load variables %s — skipping.",
                combo_key, var_ids,
            )
            continue

        # ── 3.  Execute the bypass request ─────────────────────────
        req = _build_combo_request(url, method, variables)
        resp = _execute_request(
            req["method"], req["url"], req["headers"],
            req["primer_methods"],
        )

        if resp["error"] is not None:
            logger.warning(
                "[F] combo '%s': request failed (%s) — skipping.",
                combo_key, resp["error"],
            )
            continue

        bypass_body = resp["body"]

        # ── 4.  Content-type detection ─────────────────────────────
        content_type = _detect_content_type(bypass_body)

        # ── 5.  Unique element extraction ──────────────────────────
        bypass_elements   = _extract_unique_elements(bypass_body, content_type)
        baseline_elements = _extract_unique_elements(baseline_body, content_type)

        # ── 6.  Content Richness Score ─────────────────────────────
        bypass_count   = len(bypass_elements)
        baseline_count = len(baseline_elements)

        if baseline_count > 0:
            richness = round(bypass_count / baseline_count, 2)
        elif bypass_count > 0:
            richness = float(bypass_count)  # baseline had nothing
        else:
            richness = 0.0

        sample = sorted(bypass_elements - baseline_elements)[:10]

        profile = {
            "endpoint_id":          endpoint_id,
            "combo_key":            combo_key,
            "content_type":         content_type,
            "bypass_status":        resp["status"],
            "bypass_length":        resp["length"],
            "bypass_entropy":       round(resp["entropy"], 4),
            "bypass_unique_count":  bypass_count,
            "baseline_unique_count": baseline_count,
            "richness_score":       richness,
            "sample_elements":      sample,
        }
        profiles.append(profile)

        logger.info(
            "  [PROFILE] %-28s  type=%-10s  richness=%.2f  "
            "(%d vs %d unique elements)",
            combo_key, content_type, richness,
            bypass_count, baseline_count,
        )

    logger.info(
        "[F] endpoint %d: profiled %d candidate(s).",
        endpoint_id, len(profiles),
    )

    return profiles


# ═══════════════════════════════════════════════════════════════════════
#  Internal helpers
# ═══════════════════════════════════════════════════════════════════════

def _detect_content_type(body: str) -> str:
    """
    Heuristically detect whether *body* is JSON, HTML, XML, or
    Plain Text.

    The checks are intentionally simple and ordered by specificity:
    1. Try ``json.loads`` — if it succeeds, it's JSON.
    2. Look for ``<!DOCTYPE html`` or ``<html`` — HTML.
    3. Look for ``<?xml`` or a root-level ``<tag>`` — XML.
    4. Fallback — Plain Text.
    """
    stripped = body.strip()

    # JSON
    if stripped and stripped[0] in ('{', '['):
        try:
            json.loads(stripped)
            return "JSON"
        except (json.JSONDecodeError, ValueError):
            pass

    lowered = stripped.lower()

    # HTML
    if "<!doctype html" in lowered or "<html" in lowered:
        return "HTML"

    # XML
    if stripped.startswith("<?xml") or re.match(r"^\s*<[a-zA-Z]", stripped):
        return "XML"

    return "Plain Text"


# Regex to capture HTML/XML tag names (opening and self-closing).
_TAG_NAME_RE = re.compile(r"</?([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>")


def _extract_unique_elements(body: str, content_type: str) -> set[str]:
    """
    Extract the set of unique structural elements from *body*
    according to *content_type*.

    * **JSON** — unique key names (recursively).
    * **HTML / XML** — unique tag names.
    * **Plain Text** — unique non-empty stripped lines.
    """
    if not body or not body.strip():
        return set()

    if content_type == "JSON":
        return _json_unique_keys(body)
    elif content_type in ("HTML", "XML"):
        return _tag_unique_names(body)
    else:
        # Plain Text — unique non-blank lines
        return {
            line.strip()
            for line in body.splitlines()
            if line.strip()
        }


def _json_unique_keys(body: str) -> set[str]:
    """Recursively collect all unique key names from a JSON body."""
    keys: set[str] = set()
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return keys

    def _walk(obj: object, prefix: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                full = f"{prefix}.{k}" if prefix else k
                keys.add(full)
                _walk(v, full)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item, prefix)

    _walk(data)
    return keys


def _tag_unique_names(body: str) -> set[str]:
    """Extract unique HTML/XML tag names from *body*."""
    return {m.lower() for m in _TAG_NAME_RE.findall(body)}


def _load_variables(var_ids: list[int]) -> list[dict]:
    """
    Load variable details from ``policy_variables`` by ID list.

    Returns a list of dicts compatible with
    :func:`transitions._build_combo_request`.
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


# ═══════════════════════════════════════════════════════════════════════
#  Sensitive-pattern scanner
# ═══════════════════════════════════════════════════════════════════════

# Each entry:  category → list of (pattern_name, compiled_regex)
_SENSITIVE_PATTERNS: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    # ── PII ────────────────────────────────────────────────────────
    "PII": [
        (
            "Email",
            re.compile(
                r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}",
            ),
        ),
        (
            "Phone Number",
            re.compile(
                r"(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}",
            ),
        ),
        (
            "Physical Address",
            re.compile(
                r"\d{1,5}\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*"
                r"\s+(?:St|Street|Ave|Avenue|Blvd|Boulevard|Dr|Drive"
                r"|Rd|Road|Ln|Lane|Ct|Court|Way|Pl|Place)\b",
            ),
        ),
    ],

    # ── Technical Data ─────────────────────────────────────────────
    "Technical Data": [
        (
            "Internal IPv4",
            re.compile(
                r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
                r"|192\.168\.\d{1,3}\.\d{1,3})\b",
            ),
        ),
        (
            "Unix File Path",
            re.compile(r"(?:/(?:etc|var|usr|home|tmp|opt)/[^\s<>\"']{2,})"),
        ),
        (
            "Windows File Path",
            re.compile(r"[A-Z]:\\(?:[^\s<>\"'\\]+\\){1,}[^\s<>\"'\\]*"),
        ),
        (
            "Stack Trace (Python)",
            re.compile(r'File\s+"[^"]+",\s+line\s+\d+'),
        ),
        (
            "Stack Trace (Java/.NET)",
            re.compile(r"\bat\s+[\w$.]+\([\w]+\.\w+:\d+\)"),
        ),
    ],

    # ── Credentials ────────────────────────────────────────────────
    "Credentials": [
        (
            "Generic API Key",
            re.compile(
                r"(?:api[_-]?key|apikey|api_secret)"
                r"[\s:=]+['\"]?[A-Za-z0-9_\-]{20,}['\"]?",
                re.IGNORECASE,
            ),
        ),
        (
            "JWT",
            re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
        ),
        (
            "AWS Access Key",
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        ),
        (
            "Database Connection String",
            re.compile(
                r"(?:mysql|postgres|postgresql|mongodb|redis|mssql)"
                r"://[^\s<>\"']{8,}",
                re.IGNORECASE,
            ),
        ),
        (
            "Bearer Token",
            re.compile(r"Bearer\s+[A-Za-z0-9_\-.]{20,}"),
        ),
    ],

    # ── Business Logic ─────────────────────────────────────────────
    "Business Logic": [
        (
            "UUID",
            re.compile(
                r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            ),
        ),
        (
            "Order / Invoice Number",
            re.compile(
                r"\b(?:ORD|INV|ORDER|INVOICE)[#\-_]?\d{4,}\b",
                re.IGNORECASE,
            ),
        ),
        (
            "Internal Username",
            re.compile(
                r"(?:username|user_name|login|uid)"
                r"[\s:=]+['\"]?[a-zA-Z0-9_.@-]{3,}['\"]?",
                re.IGNORECASE,
            ),
        ),
    ],
}


def scan_sensitive_patterns(endpoint_id: int) -> list[dict]:
    """
    Scan every candidate bypass body for *endpoint_id* against a
    library of sensitive-data regexes and persist matches to
    ``leaked_evidence``.

    Parameters
    ----------
    endpoint_id : int

    Returns
    -------
    list[dict]
        One dict per match::

            {
                "endpoint_id":  int,
                "combo_key":    str,
                "category":     str,   # PII / Technical Data / …
                "pattern_name": str,   # Email / JWT / …
                "matched_text": str,   # the raw match (truncated to 200 chars)
                "context":      str,   # ±40 chars around the match
            }
    """
    # ── 0.  Fetch endpoint metadata ────────────────────────────────
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
             ORDER BY ca.id
            """,
            (endpoint_id,),
        ).fetchall()
    finally:
        conn.close()

    if not candidates:
        logger.info(
            "[F-scan] endpoint %d: no candidates to scan.", endpoint_id,
        )
        return []

    url: str    = ep["url"]
    method: str = ep["method"]

    all_matches: list[dict] = []

    for cand in candidates:
        combo_info = json.loads(cand["combination_id"])
        combo_key  = combo_info["combo_key"]
        var_ids    = combo_info["variable_ids"]

        variables = _load_variables(var_ids)
        if not variables:
            continue

        # ── Re-fetch the bypass body ───────────────────────────────
        req = _build_combo_request(url, method, variables)
        resp = _execute_request(
            req["method"], req["url"], req["headers"],
            req["primer_methods"],
        )
        if resp["error"] is not None:
            continue

        body: str = resp["body"]
        if not body:
            continue

        # ── Run every pattern ──────────────────────────────────────
        for category, patterns in _SENSITIVE_PATTERNS.items():
            for pattern_name, regex in patterns:
                for m in regex.finditer(body):
                    matched_text = m.group()[:200]

                    # Build a ±40-char context snippet
                    start = max(0, m.start() - 40)
                    end   = min(len(body), m.end() + 40)
                    context = body[start:end].replace("\n", " ").strip()

                    hit = {
                        "endpoint_id":  endpoint_id,
                        "combo_key":    combo_key,
                        "category":     category,
                        "pattern_name": pattern_name,
                        "matched_text": matched_text,
                        "context":      context,
                    }
                    all_matches.append(hit)
                    _persist_evidence(hit)

        if any(h["combo_key"] == combo_key for h in all_matches):
            logger.info(
                "  [EVIDENCE] %-28s  %d pattern hit(s)",
                combo_key,
                sum(1 for h in all_matches if h["combo_key"] == combo_key),
            )

    logger.info(
        "[F-scan] endpoint %d: %d total evidence hit(s) across %d "
        "candidate(s).",
        endpoint_id, len(all_matches), len(candidates),
    )

    return all_matches


def _persist_evidence(hit: dict) -> None:
    """Insert a single evidence row into ``leaked_evidence``."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO leaked_evidence
                (endpoint_id, combo_key, category, pattern_name,
                 matched_text, context)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(endpoint_id, combo_key, pattern_name, matched_text)
                DO NOTHING
            """,
            (
                hit["endpoint_id"],
                hit["combo_key"],
                hit["category"],
                hit["pattern_name"],
                hit["matched_text"],
                hit["context"],
            ),
        )
        conn.commit()
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════
#  Data-variability checker
# ═══════════════════════════════════════════════════════════════════════

# Regex to find numeric segments in a URL path  (e.g. /user/100/profile)
_NUMERIC_SEGMENT_RE = re.compile(r"(?<=/)\d+(?=/|$)")

# How many variant requests to send (including the original).
_VARIABILITY_PROBES = 3

# Classification thresholds for the variability index.
_HIGH_THRESHOLD   = 0.40   # ≥ 40 % divergence → dynamic data
_MEDIUM_THRESHOLD = 0.15   # 15-39 % → some variability


def check_data_variability(endpoint_id: int) -> list[dict]:
    """
    For every candidate bypass on *endpoint_id*, re-execute the
    bypass with slight URL variations and measure how much the
    response body changes.

    Variation strategy
    ------------------
    If the bypass URL contains numeric path segments (e.g.
    ``/user/100``), the function generates ``_VARIABILITY_PROBES``
    variants by incrementing the **last** numeric segment
    (``/user/101``, ``/user/102``).  If no numeric segment exists,
    the original URL is used for all three probes — any body
    differences then come purely from server-side non-determinism.

    Variability index
    -----------------
    For each pair of response bodies the **Jaccard distance** of
    unique non-empty lines is computed::

        jaccard_distance = 1 - |A ∩ B| / |A ∪ B|

    The ``variability_index`` is the **mean** pairwise distance
    across all probe pairs, yielding a float in ``[0.0, 1.0]``:

    * ``0.0`` — every probe returned the exact same body (static).
    * ``1.0`` — every probe returned completely different content.

    Classification
    --------------
    * **High** (≥ 0.40) — dynamic, object-level data confirmed.
    * **Medium** (0.15 – 0.39) — partial variability (timestamps,
      CSRF tokens, etc.).
    * **Low** (0.01 – 0.14) — minor cosmetic differences.
    * **Static** (< 0.01) — identical or near-identical.

    Returns
    -------
    list[dict]
        One dict per candidate::

            {
                "endpoint_id":      int,
                "combo_key":        str,
                "variability_index": float,
                "classification":   str,
                "url_variations":   list[str],
                "body_lengths":     list[int],
                "body_hashes":      list[str],
            }
    """
    import hashlib

    # ── 0.  Fetch endpoint + candidates ────────────────────────────
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
             ORDER BY ca.id
            """,
            (endpoint_id,),
        ).fetchall()
    finally:
        conn.close()

    if not candidates:
        logger.info(
            "[F-var] endpoint %d: no candidates to test variability.",
            endpoint_id,
        )
        return []

    base_url: str = ep["url"]
    method: str   = ep["method"]

    results: list[dict] = []

    for cand in candidates:
        combo_info = json.loads(cand["combination_id"])
        combo_key  = combo_info["combo_key"]
        var_ids    = combo_info["variable_ids"]

        variables = _load_variables(var_ids)
        if not variables:
            continue

        # ── 1.  Generate URL variations ────────────────────────────
        url_variants = _generate_url_variations(
            base_url, _VARIABILITY_PROBES,
        )

        # ── 2.  Execute each variant ───────────────────────────────
        bodies: list[str]  = []
        lengths: list[int] = []
        hashes: list[str]  = []

        for variant_url in url_variants:
            req = _build_combo_request(variant_url, method, variables)
            resp = _execute_request(
                req["method"], req["url"], req["headers"],
                req["primer_methods"],
            )
            if resp["error"] is not None:
                continue

            body_text = resp["body"]
            bodies.append(body_text)
            lengths.append(resp["length"])
            hashes.append(
                hashlib.sha256(body_text.encode("utf-8")).hexdigest()[:16]
            )

        if len(bodies) < 2:
            logger.info(
                "  [VAR] %-28s  — too few successful probes (%d)",
                combo_key, len(bodies),
            )
            continue

        # ── 3.  Pairwise Jaccard distance ──────────────────────────
        variability = _pairwise_jaccard(bodies)

        # ── 4.  Classify ───────────────────────────────────────────
        if variability >= _HIGH_THRESHOLD:
            classification = "High"
        elif variability >= _MEDIUM_THRESHOLD:
            classification = "Medium"
        elif variability >= 0.01:
            classification = "Low"
        else:
            classification = "Static"

        logger.info(
            "  [VAR] %-28s  index=%.3f  %s  "
            "(lengths=%s  hashes=%s)",
            combo_key, variability, classification,
            lengths, hashes,
        )

        result = {
            "endpoint_id":       endpoint_id,
            "combo_key":         combo_key,
            "variability_index": round(variability, 4),
            "classification":    classification,
            "url_variations":    url_variants,
            "body_lengths":      lengths,
            "body_hashes":       hashes,
        }
        results.append(result)
        _persist_variability(result)

    logger.info(
        "[F-var] endpoint %d: variability checked for %d candidate(s).",
        endpoint_id, len(results),
    )

    return results


def _generate_url_variations(url: str, count: int) -> list[str]:
    """
    Produce *count* URL variants by incrementing the **last** numeric
    path segment.

    If no numeric segment exists, returns ``[url] * count`` so the
    caller still gets multiple probes (useful for detecting
    server-side non-determinism like timestamps or CSRF tokens).

    Examples
    --------
    >>> _generate_url_variations("https://x.com/user/100/profile", 3)
    ['https://x.com/user/100/profile',
     'https://x.com/user/101/profile',
     'https://x.com/user/102/profile']
    """
    matches = list(_NUMERIC_SEGMENT_RE.finditer(url))

    if not matches:
        return [url] * count

    # Target the last numeric segment.
    last = matches[-1]
    base_num = int(last.group())
    prefix   = url[:last.start()]
    suffix   = url[last.end():]

    variants: list[str] = []
    for i in range(count):
        variants.append(f"{prefix}{base_num + i}{suffix}")

    return variants


def _pairwise_jaccard(bodies: list[str]) -> float:
    """
    Compute the mean pairwise **Jaccard distance** across all body
    pairs.

    Each body is represented as a set of unique non-empty stripped
    lines.  The Jaccard distance for a pair is::

        1 - |A ∩ B| / |A ∪ B|

    Returns ``0.0`` when all bodies are identical and ``1.0`` when
    no two bodies share a single line.
    """
    line_sets = [
        {line.strip() for line in b.splitlines() if line.strip()}
        for b in bodies
    ]

    distances: list[float] = []
    for i in range(len(line_sets)):
        for j in range(i + 1, len(line_sets)):
            a, b = line_sets[i], line_sets[j]
            union = a | b
            if not union:
                distances.append(0.0)
                continue
            intersection = a & b
            distances.append(1.0 - len(intersection) / len(union))

    return sum(distances) / len(distances) if distances else 0.0


def _persist_variability(result: dict) -> None:
    """Upsert a variability result into ``variability_results``."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO variability_results
                (endpoint_id, combo_key, variability_index,
                 classification, url_variations,
                 body_lengths, body_hashes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(endpoint_id, combo_key) DO UPDATE SET
                variability_index = excluded.variability_index,
                classification    = excluded.classification,
                url_variations    = excluded.url_variations,
                body_lengths      = excluded.body_lengths,
                body_hashes       = excluded.body_hashes
            """,
            (
                result["endpoint_id"],
                result["combo_key"],
                result["variability_index"],
                result["classification"],
                json.dumps(result["url_variations"]),
                json.dumps(result["body_lengths"]),
                json.dumps(result["body_hashes"]),
            ),
        )
        conn.commit()
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════
#  Data-impact classifier  (Mock / Test vs Production)
# ═══════════════════════════════════════════════════════════════════════

# ── Mock / test data signals ───────────────────────────────────────────
# Each entry: (label, compiled regex, weight).
# Higher weight = stronger indicator of mock/test data.
_MOCK_SIGNALS: list[tuple[str, re.Pattern[str], int]] = [
    # Explicit keywords
    ("keyword:test",
     re.compile(r"\b(?:test|testing)\b", re.IGNORECASE), 2),
    ("keyword:example",
     re.compile(r"\b(?:example|sample)\b", re.IGNORECASE), 2),
    ("keyword:dummy",
     re.compile(r"\b(?:dummy|fake|mock)\b", re.IGNORECASE), 3),
    ("keyword:placeholder",
     re.compile(r"\b(?:placeholder|lorem\s+ipsum|todo|fixme)\b",
                re.IGNORECASE), 3),
    ("keyword:foo_bar",
     re.compile(r"\b(?:foo|bar|baz|qux)\b", re.IGNORECASE), 2),

    # Common test domains / emails
    ("domain:example",
     re.compile(r"@example\.(?:com|org|net)\b", re.IGNORECASE), 3),
    ("domain:test",
     re.compile(r"@(?:test|localhost|mailinator)\.\w+", re.IGNORECASE), 3),

    # Obvious placeholder values
    ("value:sequential_id",
     re.compile(r"\b(?:id|user_id|userId)[\"']?\s*[:=]\s*[\"']?[12345]\b",
                re.IGNORECASE), 1),
    ("value:john_doe",
     re.compile(r"\b(?:john\s+doe|jane\s+doe|test\s+user)\b",
                re.IGNORECASE), 3),
    ("value:555_phone",
     re.compile(r"\b555[-.\s]?\d{3}[-.\s]?\d{4}\b"), 2),

    # Dev-environment markers
    ("env:localhost",
     re.compile(r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?",
                re.IGNORECASE), 2),
    ("env:debug",
     re.compile(r"\b(?:debug|staging|development|dev[-_]?mode)\b",
                re.IGNORECASE), 2),
]

# ── Production data signals ────────────────────────────────────────────
_PRODUCTION_SIGNALS: list[tuple[str, re.Pattern[str], int]] = [
    # ISO-8601 timestamps (real data typically has recent dates)
    ("temporal:iso_timestamp",
     re.compile(r"20[2-3]\d-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
                r"T\d{2}:\d{2}"), 3),

    # Unix epoch (13-digit ms timestamps common in production APIs)
    ("temporal:epoch_ms",
     re.compile(r"\b1[6-9]\d{11}\b"), 2),

    # Real-looking email domains (not example/test/localhost)
    ("email:real_domain",
     re.compile(
         r"[a-zA-Z0-9_.+-]+@(?!example\.|test\.|localhost)"
         r"[a-zA-Z0-9-]+\.(?:com|org|net|io|co)\b",
         re.IGNORECASE,
     ), 3),

    # Long numeric IDs (> 6 digits, typical of database PKs)
    ("id:long_numeric",
     re.compile(r"\b\d{7,}\b"), 2),

    # Currency values
    ("finance:currency",
     re.compile(r"[$€£¥]\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b"), 3),

    # Realistic phone numbers (non-555)
    ("pii:real_phone",
     re.compile(
         r"(?:\+?1[-.\s]?)?(?:\(?[2-9]\d{2}\)?[-.\s]?)"
         r"(?!555)[2-9]\d{2}[-.\s]?\d{4}"
     ), 2),

    # UUIDs (v4 – random, commonly generated by production systems)
    ("id:uuid_v4",
     re.compile(
         r"\b[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}"
         r"-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
         re.IGNORECASE,
     ), 2),

    # JWTs (real tokens tend to be long)
    ("cred:jwt",
     re.compile(r"eyJ[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{30,}"), 3),

    # Full-name patterns (Title Case first + last name)
    ("pii:full_name",
     re.compile(
         r"\b(?!John\s+Doe|Jane\s+Doe|Test\s+User)"
         r"[A-Z][a-z]{2,}\s+[A-Z][a-z]{2,}\b"
     ), 1),
]


def classify_data_impact(endpoint_id: int) -> list[dict]:
    """
    For every candidate bypass on *endpoint_id*, analyse the response
    body to distinguish **mock / test data** from **production data**.

    Scoring
    -------
    Each body is scanned against two signal dictionaries:

    * ``_MOCK_SIGNALS`` — keywords (``test``, ``example``, ``dummy``,
      ``placeholder``, ``foo/bar``), test domains
      (``@example.com``), dev markers (``localhost``, ``debug``),
      and obviously fake values (``John Doe``, ``555-…``).
    * ``_PRODUCTION_SIGNALS`` — ISO-8601 timestamps, long numeric
      IDs, real email domains, currency values, UUIDs, JWTs, and
      real phone numbers.

    Each signal has a weight (1–3).  The **mock_score** and
    **production_score** are the weighted sums of all matches.

    Classification
    --------------
    * **Low Impact** — ``mock_score > production_score`` (test /
      development data).
    * **High Impact** — ``production_score > mock_score`` (live
      data).
    * **Medium Impact** — scores are equal or both are zero
      (inconclusive).

    Returns
    -------
    list[dict]
        One dict per candidate::

            {
                "endpoint_id":      int,
                "combo_key":        str,
                "impact_label":     str,
                "mock_score":       float,
                "production_score": float,
                "mock_hits":        list[str],
                "production_hits":  list[str],
            }
    """
    # ── 0.  Fetch endpoint + candidates ────────────────────────────
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
             ORDER BY ca.id
            """,
            (endpoint_id,),
        ).fetchall()
    finally:
        conn.close()

    if not candidates:
        logger.info(
            "[F-impact] endpoint %d: no candidates to classify.",
            endpoint_id,
        )
        return []

    url: str    = ep["url"]
    method: str = ep["method"]

    results: list[dict] = []

    for cand in candidates:
        combo_info = json.loads(cand["combination_id"])
        combo_key  = combo_info["combo_key"]
        var_ids    = combo_info["variable_ids"]

        variables = _load_variables(var_ids)
        if not variables:
            continue

        # ── 1.  Re-fetch the bypass body ───────────────────────────
        req = _build_combo_request(url, method, variables)
        resp = _execute_request(
            req["method"], req["url"], req["headers"],
            req["primer_methods"],
        )
        if resp["error"] is not None:
            continue

        body: str = resp["body"]
        if not body:
            continue

        # ── 2.  Score mock signals ─────────────────────────────────
        mock_score = 0.0
        mock_hits: list[str] = []

        for label, regex, weight in _MOCK_SIGNALS:
            matches = regex.findall(body)
            if matches:
                mock_score += weight * len(matches)
                mock_hits.append(f"{label}(×{len(matches)})")

        # ── 3.  Score production signals ───────────────────────────
        prod_score = 0.0
        prod_hits: list[str] = []

        for label, regex, weight in _PRODUCTION_SIGNALS:
            matches = regex.findall(body)
            if matches:
                prod_score += weight * len(matches)
                prod_hits.append(f"{label}(×{len(matches)})")

        # ── 4.  Classify ───────────────────────────────────────────
        if mock_score > prod_score:
            impact_label = "Low Impact"
        elif prod_score > mock_score:
            impact_label = "High Impact"
        else:
            impact_label = "Medium Impact"

        logger.info(
            "  [IMPACT] %-28s  %s  mock=%.0f  prod=%.0f  "
            "(%s | %s)",
            combo_key, impact_label, mock_score, prod_score,
            ", ".join(mock_hits[:3]) or "—",
            ", ".join(prod_hits[:3]) or "—",
        )

        result = {
            "endpoint_id":      endpoint_id,
            "combo_key":        combo_key,
            "impact_label":     impact_label,
            "mock_score":       int(mock_score * 10) / 10,
            "production_score": int(prod_score * 10) / 10,
            "mock_hits":        mock_hits,
            "production_hits":  prod_hits,
        }
        results.append(result)
        _persist_classification(result)

    logger.info(
        "[F-impact] endpoint %d: classified %d candidate(s).",
        endpoint_id, len(results),
    )

    return results


def _persist_classification(result: dict) -> None:
    """Upsert an impact classification into ``data_classification``."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO data_classification
                (endpoint_id, combo_key, impact_label,
                 mock_score, production_score,
                 mock_hits, production_hits)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(endpoint_id, combo_key) DO UPDATE SET
                impact_label     = excluded.impact_label,
                mock_score       = excluded.mock_score,
                production_score = excluded.production_score,
                mock_hits        = excluded.mock_hits,
                production_hits  = excluded.production_hits
            """,
            (
                result["endpoint_id"],
                result["combo_key"],
                result["impact_label"],
                result["mock_score"],
                result["production_score"],
                json.dumps(result["mock_hits"]),
                json.dumps(result["production_hits"]),
            ),
        )
        conn.commit()
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════
#  Referential-integrity verifier  (Shadow Requests)
# ═══════════════════════════════════════════════════════════════════════

# Keys in JSON whose values are likely references to other objects.
_REF_KEY_RE = re.compile(
    r"(?:_id|_url|_link|_href|_path|_uri|Id$|Url$|Link$|"
    r"image|avatar|thumbnail|profile|href|src)",
    re.IGNORECASE,
)

# Embedded absolute URLs anywhere in the body.
_INLINE_URL_RE = re.compile(
    r"https?://[^\s\"'<>\]){},]{8,}",
)

# HTML href / src attribute values.
_HTML_ATTR_RE = re.compile(
    r"""(?:href|src)\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

# Maximum number of shadow requests per candidate (safety cap).
_MAX_SHADOW_REQUESTS = 15


def verify_referential_integrity(endpoint_id: int) -> list[dict]:
    """
    For every candidate bypass on *endpoint_id*, extract internal
    references (URLs, IDs, links) from the response body and issue
    **shadow requests** to those referenced items using the same
    bypass headers.

    Reference extraction
    --------------------
    Three extractors run in parallel:

    1. **HTML attributes** — ``href`` and ``src`` values.
    2. **Inline URLs** — any ``https?://…`` found in the body text.
    3. **JSON reference keys** — values of JSON keys matching
       patterns like ``*_id``, ``*_url``, ``image``, ``avatar``,
       ``href``, etc.  Numeric IDs are appended to the base URL
       path; string paths / URLs are resolved against it.

    Shadow requests
    ---------------
    Each extracted reference is resolved to an absolute URL and
    fetched with the **same bypass headers** that succeeded on the
    original endpoint.  A reference is **reachable** when the
    shadow response returns a non-403 status.

    Exposure classification
    -----------------------
    * **Systemic** — at least one referenced item is also reachable
      through the same bypass technique, confirming a broader
      access-control gap.
    * **Single** — no referenced items were reachable; the leak is
      limited to this endpoint alone.

    Returns
    -------
    list[dict]
        One dict per shadow request::

            {
                "endpoint_id":    int,
                "combo_key":      str,
                "ref_type":       str,   # "html_attr" / "inline_url" / "json_ref"
                "ref_value":      str,   # raw extracted value
                "shadow_url":     str,   # resolved absolute URL
                "shadow_status":  int,
                "shadow_length":  int,
                "is_reachable":   bool,
                "exposure_class": str,   # "Systemic" or "Single"
            }
    """
    # ── 0.  Fetch endpoint + candidates ────────────────────────────
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
             ORDER BY ca.id
            """,
            (endpoint_id,),
        ).fetchall()
    finally:
        conn.close()

    if not candidates:
        logger.info(
            "[F-ref] endpoint %d: no candidates to verify.", endpoint_id,
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

        # ── 1.  Re-fetch the bypass body ───────────────────────────
        req = _build_combo_request(base_url, method, variables)
        resp = _execute_request(
            req["method"], req["url"], req["headers"],
            req["primer_methods"],
        )
        if resp["error"] is not None:
            continue

        body: str = resp["body"]
        if not body:
            continue

        bypass_headers = req["headers"]

        # ── 2.  Extract references ─────────────────────────────────
        refs = _extract_references(body, base_url)

        if not refs:
            logger.info(
                "  [REF] %-28s  no references found in body.",
                combo_key,
            )
            continue

        # ── 3.  Shadow requests ────────────────────────────────────
        reachable_count = 0
        combo_results: list[dict] = []

        for ref_type, ref_value, shadow_url in refs[:_MAX_SHADOW_REQUESTS]:
            shadow_resp = _execute_request(
                "GET", shadow_url, bypass_headers, [],
            )

            if shadow_resp["error"] is not None:
                continue

            is_reachable = shadow_resp["status"] != 403
            if is_reachable:
                reachable_count += 1

            hit = {
                "endpoint_id":    endpoint_id,
                "combo_key":      combo_key,
                "ref_type":       ref_type,
                "ref_value":      ref_value[:200],
                "shadow_url":     shadow_url,
                "shadow_status":  shadow_resp["status"],
                "shadow_length":  shadow_resp["length"],
                "is_reachable":   is_reachable,
                "exposure_class": "",  # set below
            }
            combo_results.append(hit)

        # ── 4.  Classify exposure ──────────────────────────────────
        exposure = "Systemic" if reachable_count > 0 else "Single"

        for hit in combo_results:
            hit["exposure_class"] = exposure
            _persist_integrity(hit)

        all_results.extend(combo_results)

        logger.info(
            "  [REF] %-28s  %d ref(s), %d reachable → %s",
            combo_key, len(combo_results), reachable_count, exposure,
        )

    logger.info(
        "[F-ref] endpoint %d: %d shadow request(s) across %d candidate(s).",
        endpoint_id, len(all_results), len(candidates),
    )

    return all_results


# ── Reference extraction helpers ───────────────────────────────────────

def _extract_references(
    body: str,
    base_url: str,
) -> list[tuple[str, str, str]]:
    """
    Extract references from *body* and resolve them to absolute URLs.

    Returns a de-duplicated list of ``(ref_type, raw_value,
    resolved_url)`` tuples.
    """
    seen_urls: set[str] = set()
    refs: list[tuple[str, str, str]] = []

    def _add(ref_type: str, raw: str, resolved: str) -> None:
        if resolved in seen_urls:
            return
        parsed = urlparse(resolved)
        if not parsed.scheme or not parsed.netloc:
            return
        seen_urls.add(resolved)
        refs.append((ref_type, raw, resolved))

    # 1.  HTML href / src attributes
    for match in _HTML_ATTR_RE.findall(body):
        resolved = _resolve_url(match, base_url)
        if resolved:
            _add("html_attr", match, resolved)

    # 2.  Inline absolute URLs
    for match in _INLINE_URL_RE.findall(body):
        # Strip trailing punctuation that regex may have captured
        cleaned = match.rstrip(".,;:!?)")
        _add("inline_url", cleaned, cleaned)

    # 3.  JSON reference keys
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        data = None

    if isinstance(data, (dict, list)):
        _walk_json_refs(data, base_url, _add)

    return refs


def _walk_json_refs(
    obj: object,
    base_url: str,
    add_fn: object,
) -> None:
    """Recursively walk a JSON structure and yield reference values."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if _REF_KEY_RE.search(key) and isinstance(value, (str, int)):
                str_val = str(value)
                resolved = _resolve_url(str_val, base_url)
                if resolved:
                    add_fn("json_ref", f"{key}={str_val}", resolved)
            # Recurse
            if isinstance(value, (dict, list)):
                _walk_json_refs(value, base_url, add_fn)
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                _walk_json_refs(item, base_url, add_fn)


def _resolve_url(value: str, base_url: str) -> str:
    """
    Resolve *value* to an absolute URL against *base_url*.

    Handles:
    * Absolute URLs (``https://…``) — returned as-is.
    * Relative paths (``/api/v1/…``) — joined with base origin.
    * Bare numeric IDs (``12345``) — appended to base path.
    * Empty or whitespace — returns ``""``.
    """
    value = value.strip()
    if not value:
        return ""

    # Already absolute
    if value.startswith(("http://", "https://")):
        return value

    # Relative path
    if value.startswith("/"):
        return urljoin(base_url, value)

    # Bare numeric ID → append to base URL path
    if value.isdigit() and len(value) >= 2:
        # e.g. base = https://api.io/user/100 → https://api.io/user/12345
        parsed = urlparse(base_url)
        base_path = parsed.path.rstrip("/")
        parent = base_path.rsplit("/", 1)[0] if "/" in base_path else base_path
        new_path = f"{parent}/{value}"
        return f"{parsed.scheme}://{parsed.netloc}{new_path}"

    # Path-like string without leading slash (e.g. "images/avatar.jpg")
    if "/" in value and not value.startswith("#"):
        return urljoin(base_url, "/" + value)

    return ""


def _persist_integrity(hit: dict) -> None:
    """Insert a shadow-request result into ``referential_integrity``."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO referential_integrity
                (endpoint_id, combo_key, ref_type, ref_value,
                 shadow_url, shadow_status, shadow_length,
                 is_reachable, exposure_class)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(endpoint_id, combo_key, shadow_url) DO UPDATE SET
                shadow_status  = excluded.shadow_status,
                shadow_length  = excluded.shadow_length,
                is_reachable   = excluded.is_reachable,
                exposure_class = excluded.exposure_class
            """,
            (
                hit["endpoint_id"],
                hit["combo_key"],
                hit["ref_type"],
                hit["ref_value"],
                hit["shadow_url"],
                hit["shadow_status"],
                hit["shadow_length"],
                1 if hit["is_reachable"] else 0,
                hit["exposure_class"],
            ),
        )
        conn.commit()
    finally:
        conn.close()
