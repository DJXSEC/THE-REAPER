"""
403 body clustering for the 403 bypass scanner.

Groups endpoints that return near-identical 403 bodies so that
expensive bypass mutations need only run once per unique denial
template rather than once per URL.
"""

from __future__ import annotations

import difflib
import uuid

from bypasser.db import get_connection

# Two bodies are considered the same denial template when their
# SequenceMatcher ratio exceeds this threshold.
_SIMILARITY_THRESHOLD = 0.95


def get_fingerprint_group(body_text: str) -> str:
    """
    Return the fingerprint group ID for *body_text*.

    Compares *body_text* against every canonical body already stored in
    the ``fingerprint_groups`` table using
    :class:`difflib.SequenceMatcher`.  If a match with ≥ 95 %
    similarity is found, the existing ``group_id`` is returned.
    Otherwise a new UUID-based group is created and persisted.

    Parameters
    ----------
    body_text : str
        The decoded 403 response body to classify.

    Returns
    -------
    str
        A unique group identifier (UUID4 hex string).
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT group_id, canonical_body FROM fingerprint_groups"
        ).fetchall()

        for row in rows:
            ratio = difflib.SequenceMatcher(
                None, body_text, row["canonical_body"]
            ).ratio()
            if ratio >= _SIMILARITY_THRESHOLD:
                return row["group_id"]

        # No match — create a new group.
        new_id = uuid.uuid4().hex
        conn.execute(
            """
            INSERT INTO fingerprint_groups (group_id, canonical_body)
            VALUES (?, ?)
            """,
            (new_id, body_text),
        )
        conn.commit()
        return new_id
    finally:
        conn.close()
