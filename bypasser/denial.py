"""
403 response body and layer analysis for the 403 bypass scanner.

Complements header-based WAF fingerprinting by inspecting the *body*
of denial responses for text signatures unique to specific enforcers,
and classifying the denial as Edge-Layer or Application-Layer.
"""

from __future__ import annotations

import re


# ── Signature rules ─────────────────────────────────────────────────
# Each rule is (compiled_regex, label).  Evaluated top-to-bottom;
# the first match wins.
_BODY_SIGNATURES: list[tuple[re.Pattern, str]] = [
    # Akamai – classic "Pardon Our Interruption" block page
    (re.compile(r"Pardon Our Interruption", re.IGNORECASE), "Akamai"),

    # Cloudflare – block page always contains a Ray ID
    (re.compile(r"Cloudflare Ray ID", re.IGNORECASE), "Cloudflare"),

    # AWS WAF – "Access Denied" followed by a reference like 18.xxxx
    (re.compile(
        r"Access Denied.*?(?:Reference|ref)[^A-Za-z0-9]*#?\s*18\.\S+",
        re.IGNORECASE | re.DOTALL,
    ), "AWS WAF"),
]

# Cookie names that indicate an application-layer origin server.
_APP_SESSION_COOKIES = (
    "jsessionid", "phpsessid", "asp.net_sessionid",
    "laravel_session", "rack.session", "connect.sid",
)

# WAF / CDN providers whose "Server" header marks an edge layer.
_EDGE_SERVER_KEYWORDS = (
    "cloudflare", "akamaighost", "cloudfront",
    "fastly", "varnish", "cdn",
)


def identify_denial_source(body: str, status_code: int) -> str | None:
    """
    Scan a response body for WAF / enforcer signatures.

    Only inspects responses with a **403** status code.  For all other
    status codes the function returns ``None`` immediately (no denial
    detected).

    Parameters
    ----------
    body : str
        The decoded response body.
    status_code : int
        The HTTP status code of the response.

    Returns
    -------
    str | None
        The enforcer label (``'Akamai'``, ``'Cloudflare'``,
        ``'AWS WAF'``) if a known signature is found, or ``None``
        if the status code is not 403 or no signature matches.
    """
    if status_code != 403:
        return None

    for pattern, label in _BODY_SIGNATURES:
        if pattern.search(body):
            return label

    return None


def classify_denial_layer(
    status_code: int,
    response_time_ms: float,
    header_dict: dict,
    body: str,
) -> str | None:
    """
    Classify a 403 denial as **Edge-Layer** or **Application-Layer**.

    Heuristics
    ----------
    **Edge-Layer** (CDN / WAF terminated the request):
        * Response time < 100 ms, **and**
        * ``Server`` header matches a known CDN / WAF keyword.

    **Application-Layer** (origin server denied the request):
        * Response time > 300 ms, **or**
        * Application-specific session cookies present
          (``JSESSIONID``, ``PHPSESSID``, etc.), **or**
        * Body contains custom HTML (a ``<title>`` tag that is *not*
          a generic CDN error page title).

    Parameters
    ----------
    status_code : int
        HTTP status code of the response.
    response_time_ms : float
        Round-trip time of the request in milliseconds.
    header_dict : dict
        Response headers (name → value mapping).
    body : str
        Decoded response body.

    Returns
    -------
    str | None
        ``'Edge-Layer'``, ``'Application-Layer'``, or ``None`` if the
        response is not a 403.
    """
    if status_code != 403:
        return None

    lower_headers = {k.lower(): v for k, v in header_dict.items()}
    server = lower_headers.get("server", "").lower()
    cookies = lower_headers.get("set-cookie", "").lower()

    # ── Check for application-layer signals ─────────────────────────
    has_app_cookie = any(name in cookies for name in _APP_SESSION_COOKIES)

    # Custom HTML template detection: look for a <title> that isn't a
    # generic CDN/WAF page title.
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    has_custom_html = False
    if title_match:
        title_text = title_match.group(1).strip().lower()
        generic_titles = {"403 forbidden", "access denied", "error", "blocked"}
        has_custom_html = title_text not in generic_titles and len(title_text) > 0

    if has_app_cookie or has_custom_html or response_time_ms > 300:
        return "Application-Layer"

    # ── Check for edge-layer signals ────────────────────────────────
    is_edge_server = any(kw in server for kw in _EDGE_SERVER_KEYWORDS)

    if response_time_ms < 100 and is_edge_server:
        return "Edge-Layer"

    # ── Ambiguous — fall back based on response time ────────────────
    if response_time_ms < 100:
        return "Edge-Layer"

    return "Application-Layer"
