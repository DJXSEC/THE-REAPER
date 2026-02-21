"""
Baseline request executor for the 403 bypass scanner.

Sends a clean, controlled HTTP request and returns a fingerprint
dictionary (status code, body length, header hash, entropy score)
that downstream phases use to detect behavioural drift.
"""

import hashlib
import math
import time
from collections import Counter

import requests

from bypasser.clustering import get_fingerprint_group
from bypasser.denial import classify_denial_layer, identify_denial_source

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def calculate_entropy(text: str) -> float:
    """
    Calculate the Shannon entropy of *text*.

    Shannon entropy measures the average information content per
    character.  High entropy (≈ 4–6 for English prose / JSON) signals
    meaningful data, while low entropy (< 2) suggests error pages,
    redirects, or empty responses — key for identifying Soft 403s.

    Parameters
    ----------
    text : str
        The response body as a decoded string.

    Returns
    -------
    float
        Entropy in bits.  Returns ``0.0`` for empty strings.
    """
    if not text:
        return 0.0

    length = len(text)
    frequencies = Counter(text)

    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in frequencies.values()
    )

    # Avoid returning -0.0 for single-character-class inputs.
    return entropy if entropy else 0.0


def fingerprint_headers(header_dict: dict) -> str:
    """
    Identify WAFs and infrastructure from HTTP response headers.

    Checks for signatures of common WAFs and CDNs by inspecting
    header names and values (case-insensitive).  Returns the *first*
    match found in priority order, or ``'Unknown'`` if nothing matches.

    Parameters
    ----------
    header_dict : dict
        A mapping of response header names to values
        (e.g. ``response.headers``).

    Returns
    -------
    str
        One of: ``'Cloudflare'``, ``'Akamai'``, ``'AWS CloudFront'``,
        ``'Generic Nginx'``, ``'Generic Apache'``, or ``'Unknown'``.
    """
    # Normalise header names to lowercase for reliable matching.
    lower_headers = {k.lower(): v for k, v in header_dict.items()}
    server = lower_headers.get("server", "").lower()
    cookies = lower_headers.get("set-cookie", "").lower()

    # ── Cloudflare ──────────────────────────────────────────────────
    if (
        "cf-ray" in lower_headers
        or "__cfduid" in cookies
        or server == "cloudflare"
    ):
        return "Cloudflare"

    # ── Akamai ──────────────────────────────────────────────────────
    if "_abck" in cookies or server == "akamaighost":
        return "Akamai"

    # ── AWS / CloudFront ────────────────────────────────────────────
    if "x-amz-cf-id" in lower_headers or server == "cloudfront":
        return "AWS CloudFront"

    # ── Generic web servers ─────────────────────────────────────────
    if "nginx" in server:
        return "Generic Nginx"
    if "apache" in server:
        return "Generic Apache"

    return "Unknown"


def execute_baseline_request(url: str, method: str = "GET") -> dict:
    """
    Send a single HTTP request with a fixed User-Agent and return a
    response fingerprint.

    Parameters
    ----------
    url : str
        The target endpoint URL.
    method : str
        HTTP method to use (GET, POST, PUT, DELETE, …).

    Returns
    -------
    dict
        {
            "status_code":    int   – HTTP response status code,
            "body_length":    int   – exact length of the response body in bytes,
            "header_hash":    str   – SHA-256 hex digest of the sorted response headers,
            "entropy_score":    float     – Shannon entropy of the response body,
            "waf_type":         str       – detected WAF / infrastructure label,
            "denial_source":    str|None  – enforcer from 403 body (None if N/A),
            "denial_layer":          str|None  – 'Edge-Layer' or 'Application-Layer',
            "response_time_ms":      float     – round-trip time in milliseconds,
            "fingerprint_group_id":  str|None  – cluster ID for 403 body dedup,
        }
    """
    headers = {"User-Agent": USER_AGENT}

    t0 = time.perf_counter()
    response = requests.request(method, url, headers=headers)
    response_time_ms = (time.perf_counter() - t0) * 1000

    # Build a deterministic hash of all response headers:
    #   1. Sort header names alphabetically (case-insensitive).
    #   2. Concatenate each "name: value" pair with a newline.
    #   3. SHA-256 the resulting string.
    sorted_headers = sorted(response.headers.items(), key=lambda h: h[0].lower())
    header_string = "\n".join(f"{name}: {value}" for name, value in sorted_headers)
    header_hash = hashlib.sha256(header_string.encode("utf-8")).hexdigest()

    raw_headers = dict(response.headers)

    return {
        "status_code": response.status_code,
        "body_length": len(response.content),
        "header_hash": header_hash,
        "entropy_score": calculate_entropy(response.text),
        "waf_type": fingerprint_headers(raw_headers),
        "denial_source": identify_denial_source(
            response.text, response.status_code
        ),
        "denial_layer": classify_denial_layer(
            response.status_code, response_time_ms,
            raw_headers, response.text,
        ),
        "response_time_ms": round(response_time_ms, 2),
        "fingerprint_group_id": (
            get_fingerprint_group(response.text)
            if response.status_code == 403 else None
        ),
    }
