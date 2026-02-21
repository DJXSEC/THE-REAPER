"""
URL ingestion for the 403 bypass scanner.

Reads a newline-delimited ``.txt`` file of target URLs, skips any
that are already marked *stable* in the database, and runs the
stability-verification pipeline on every new entry.
"""

from __future__ import annotations

from tqdm import tqdm  # type: ignore

from bypasser.db import get_connection, init_db  # type: ignore
from bypasser.stability import verify_endpoint_stability  # type: ignore


def ingest_urls(filepath: str, method: str = "GET") -> list[dict]:
    """
    Read *filepath* and baseline every URL that is not yet stable.

    Parameters
    ----------
    filepath : str
        Path to a newline-delimited ``.txt`` file of URLs.
    method : str
        HTTP method to use for all requests (default ``GET``).

    Returns
    -------
    list[dict]
        A result dict for each URL that was actually processed
        (i.e. not skipped).  Each dict is the output of
        :func:`verify_endpoint_stability`.
    """
    init_db()

    # ── Load and deduplicate URLs ───────────────────────────────────
    with open(filepath, "r", encoding="utf-8") as fh:
        urls = [
            line.strip()
            for line in fh
            if line.strip() and not line.strip().startswith("#")
        ]
    urls = list(dict.fromkeys(urls))          # preserve order, drop dupes

    # ── Identify which URLs are already stable ──────────────────────
    stable_urls = _get_stable_urls()

    # ── Baseline new / non-stable URLs ──────────────────────────────
    results: list[dict] = []
    skipped = 0

    for url in tqdm(urls, desc="Baselining Endpoints", unit="url"):
        if url in stable_urls:
            skipped += 1  # type: ignore
            continue

        result = verify_endpoint_stability(url, method)
        results.append(result)

    # ── Summary line ────────────────────────────────────────────────
    stable_count = sum(1 for r in results if r["is_stable"])
    unstable_count = len(results) - stable_count
    print(
        f"\n[+] Done — {len(urls)} URLs loaded, {skipped} skipped (already stable), "
        f"{stable_count} new stable, {unstable_count} unstable."
    )

    return results


def _get_stable_urls() -> set[str]:
    """Return the set of URLs currently marked stable in the database."""
    conn = get_connection()
    urls: set[str] = set()
    try:
        rows = conn.execute(
            "SELECT url FROM endpoints WHERE is_stable = 1"
        ).fetchall()
        urls = {row["url"] for row in rows}
    finally:
        conn.close()
    return urls
