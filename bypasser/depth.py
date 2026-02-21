"""
Processing depth probe for the 403 bypass scanner.

Determines whether a 403 denial is enforced at the edge (WAF / CDN)
or reaches the origin server by sending deliberately malformed and
oversized headers and comparing the responses to the known baseline.
"""

from __future__ import annotations

import hashlib
import logging

import requests

from bypasser.db import get_connection

logger = logging.getLogger(__name__)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def _hash_response_headers(response: requests.Response) -> str:
    """Return the same deterministic SHA-256 header hash used by baseline.py."""
    sorted_headers = sorted(response.headers.items(), key=lambda h: h[0].lower())
    header_string = "\n".join(f"{name}: {value}" for name, value in sorted_headers)
    return hashlib.sha256(header_string.encode("utf-8")).hexdigest()


def test_processing_depth(
    url: str,
    baseline_hash: str,
    method: str = "GET",
) -> str:
    """
    Probe whether a 403 is terminated at the edge or the origin.

    Sends two deliberately invalid requests and compares the responses
    to the baseline fingerprint:

    1. **Malformed header** — ``X-Invalid-Char`` set to ``\\x01\\x02``.
    2. **Oversized header** — ``X-Overflow`` set to 8 KB of junk.

    Decision logic
    --------------
    * If either probe returns a **400** or **431**, the request
      reached the origin server → **Level 2: Origin**.
    * If both probes return a response whose header hash matches
      ``baseline_hash`` (i.e. the same 403), the WAF is dropping
      requests before they reach the origin → **Level 1: Edge**.
    * Otherwise fall back to **Level 1: Edge** (conservative).

    Parameters
    ----------
    url : str
        Target endpoint URL.
    baseline_hash : str
        The ``header_hash`` from the clean baseline 403 response.
    method : str
        HTTP method to use (default ``GET``).

    Returns
    -------
    str
        ``'Level 1: Edge'`` or ``'Level 2: Origin'``.
    """

    probes: list[dict] = [
        {
            "label": "malformed-header",
            "headers": {
                "User-Agent": USER_AGENT,
                "X-Invalid-Char": "\x01\x02",
            },
        },
        {
            "label": "oversized-header",
            "headers": {
                "User-Agent": USER_AGENT,
                "X-Overflow": "A" * 8192,      # 8 KB of junk
            },
        },
    ]

    for probe in probes:
        try:
            resp = requests.request(method, url, headers=probe["headers"])
        except requests.RequestException as exc:
            logger.warning(
                "[depth] %s probe failed for %s: %s",
                probe["label"], url, exc,
            )
            continue

        # ── Origin-reach signals ────────────────────────────────────
        if resp.status_code in (400, 431):
            logger.info(
                "[depth] %s → %d — Request is reaching the origin server. (%s)",
                url, resp.status_code, probe["label"],
            )
            depth = "Level 2: Origin"
            _update_processing_depth(url, method, depth)
            return depth

        # ── Edge-drop signal ────────────────────────────────────────
        probe_hash = _hash_response_headers(resp)
        if probe_hash == baseline_hash:
            logger.info(
                "[depth] %s — WAF is dropping requests early. (%s)",
                url, probe["label"],
            )
            # Don't return yet — check both probes before deciding.

    # If we reach here, neither probe triggered a 400/431, so the WAF
    # is intercepting everything at the edge.
    depth = "Level 1: Edge"
    logger.info("[depth] %s — classified as %s", url, depth)
    _update_processing_depth(url, method, depth)
    return depth


def _update_processing_depth(
    url: str, method: str, depth: str
) -> None:
    """Persist the processing depth result to the endpoints table."""
    conn = get_connection()
    try:
        conn.execute(
            """
            UPDATE endpoints
               SET processing_depth = ?
             WHERE url = ? AND method = ?
            """,
            (depth, url, method),
        )
        conn.commit()
    finally:
        conn.close()
