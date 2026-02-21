"""
Final-report metrics aggregation.

Section M consolidates evidence collected across the entire pipeline
into a single, triager-ready intelligence package per endpoint.

Public API
----------
``aggregate_final_metrics(endpoint_id)``
    Pull the 'Greatest Hits' for *endpoint_id* from the database and
    return a structured dict covering:

    * **The Exploit** — minimal bypass combination (Section E).
    * **The Scale**  — total reachable records (Section H).
    * **The Evidence** — redacted PII / sensitive data samples (Section I).
    * **The Scope** — lateral endpoints compromised (Section J).
    * **The Proof** — contrast results and stability scores (Sections K & L).
    * **The Severity** — projected CVSS v3.1 score.

``calculate_projected_cvss(metrics)``
    Compute a projected CVSS v3.1 base score from the aggregated
    metrics.  Returns the numeric score (0.0–10.0), a severity label
    (None/Low/Medium/High/Critical), and the full vector string.

``generate_markdown_report(endpoint_id, output_dir)``
    Produce a single ``.md`` file for one verified vulnerability,
    covering Summary, Steps to Reproduce (with curl), Impact Analysis,
    and Mitigation Suggestion.

``bundle_report_archive(endpoint_id, output_dir)``
    Package the Markdown report, poc_evidence JSON files, and
    stability logs into a single ``Arbiter_Report_[target]_[date].zip``.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import textwrap
import zipfile
from datetime import datetime, timezone
from urllib.parse import urlparse

from bypasser.db import get_connection  # type: ignore

logger = logging.getLogger(__name__)

# ─── Redaction helpers ────────────────────────────────────────────────

_EMAIL_RE   = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}")
_PHONE_RE   = re.compile(r"\b\d{3}[\-.\s]?\d{3}[\-.\s]?\d{4}\b")
_SSN_RE     = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_RE      = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_TOKEN_RE   = re.compile(
    r"(?:eyJ[A-Za-z0-9_-]+\.){2}[A-Za-z0-9_-]+",  # JWT
)


def _redact(text: str) -> str:
    """
    Apply consistent redaction to a raw text sample.

    Replaces emails, phone numbers, SSNs, credit-card numbers, and
    JWT tokens with placeholder tags so the evidence is safe for a
    triager report without leaking real user data.
    """
    text = _EMAIL_RE.sub("[REDACTED-EMAIL]", text)
    text = _PHONE_RE.sub("[REDACTED-PHONE]", text)
    text = _SSN_RE.sub("[REDACTED-SSN]", text)
    text = _CC_RE.sub("[REDACTED-CC]", text)
    text = _TOKEN_RE.sub("[REDACTED-JWT]", text)
    return text


# ═════════════════════════════════════════════════════════════════════
#  Public API
# ═════════════════════════════════════════════════════════════════════

def aggregate_final_metrics(endpoint_id: int) -> dict:
    """
    Pull the *Greatest Hits* for a single endpoint and return a
    unified metrics package.

    Returns
    -------
    dict
        ::

            {
                "endpoint_id": int,
                "url":         str,
                "method":      str,

                "exploit": {                        # Section E
                    "combo_key":        str,
                    "transition_type":  str,
                    "bypassed_status":  int,
                    "stability_score":  int,
                    "impact_score":     int | None,
                    "variables":        list[dict],
                },

                "scale": {                          # Section H
                    "total_reachable_records": int,
                    "id_span_confirmed":      int,
                    "pagination_pages":       int,
                    "reach_summary":          dict | None,
                },

                "evidence": {                       # Section I
                    "extracted_records": int,
                    "sensitive_samples": list[dict],
                },

                "scope": {                         # Section J
                    "lateral_endpoints":         int,
                    "systemic_bypasses":         int,
                    "unique_resources_exposed":  int,
                    "severity_label":            str,
                },

                "proof": {                         # Sections K & L
                    "contrast": {
                        "profiles_tested": int,
                        "bypass_verdict":  str | None,
                        "info_gain_pct":   float | None,
                        "privilege_parity": str | None,
                        "failure_class":   str | None,
                    },
                    "stability": {
                        "persistence_score":  str | None,
                        "survival_score":     float | None,
                        "survival_rating":    str | None,
                        "max_drift_pct":      float | None,
                        "triager_summary":    str | None,
                    },
                },
            }

    Raises
    ------
    ValueError
        If *endpoint_id* does not exist or has no verified bypass.
    """
    conn = get_connection()
    try:
        metrics = _build_metrics(conn, endpoint_id)
    finally:
        conn.close()

    # Attach projected CVSS score to the metrics package.
    metrics["cvss"] = calculate_projected_cvss(metrics)

    logger.info(
        "[M] aggregate_final_metrics: ep=%d  combo=%s  "
        "rating=%s  cvss=%.1f (%s)",
        endpoint_id,
        metrics["exploit"]["combo_key"],
        metrics["proof"]["stability"].get("survival_rating", "—"),
        metrics["cvss"]["score"],
        metrics["cvss"]["severity"],
    )
    return metrics


# ═════════════════════════════════════════════════════════════════════
#  Internal builders
# ═════════════════════════════════════════════════════════════════════

def _build_metrics(conn, endpoint_id: int) -> dict:
    """Assemble every sub-dict inside a single connection."""

    # ── Endpoint metadata ─────────────────────────────────────────
    ep = conn.execute(
        "SELECT url, method FROM endpoints WHERE id = ?",
        (endpoint_id,),
    ).fetchone()

    if ep is None:
        raise ValueError(f"Endpoint {endpoint_id} not found.")

    url    = ep["url"]
    method = ep["method"]

    return {
        "endpoint_id": endpoint_id,
        "url":         url,
        "method":      method,
        "exploit":     _exploit(conn, endpoint_id),
        "scale":       _scale(conn, endpoint_id),
        "evidence":    _evidence(conn, endpoint_id),
        "scope":       _scope(conn, endpoint_id),
        "proof":       _proof(conn, endpoint_id),
    }


# ── Section E: The Exploit ────────────────────────────────────────

def _exploit(conn, endpoint_id: int) -> dict:
    """
    Minimal bypass combination — the *single best* verified combo
    for this endpoint, selected by highest stability score.
    """
    row = conn.execute(
        """
        SELECT combination_id, transition_type,
               new_status, stability_score, impact_score
          FROM candidate_access
         WHERE endpoint_id = ?
           AND is_verified  = 1
         ORDER BY stability_score DESC, id ASC
         LIMIT 1
        """,
        (endpoint_id,),
    ).fetchone()

    if row is None:
        raise ValueError(
            f"No verified bypass for endpoint_id {endpoint_id}."
        )

    combo_key = row["combination_id"]

    # Resolve variable names from the combo JSON.
    variables: list[dict] = []
    try:
        combo = json.loads(combo_key)
        var_ids: list[int] = combo.get("variable_ids", [])
        if var_ids:
            ph = ",".join("?" * len(var_ids))
            var_rows = conn.execute(
                f"SELECT id, name, category, test_value "
                f"  FROM policy_variables WHERE id IN ({ph})",
                var_ids,
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
    except (json.JSONDecodeError, TypeError):
        pass

    return {
        "combo_key":       combo_key,
        "transition_type": row["transition_type"],
        "bypassed_status": row["new_status"],
        "stability_score": row["stability_score"],
        "impact_score":    row["impact_score"],
        "variables":       variables,
    }


# ── Section H: The Scale ──────────────────────────────────────────

def _scale(conn, endpoint_id: int) -> dict:
    """
    Total reachable records from ID-span probing plus pagination
    reach, capped with reach_summary if available.
    """
    # ID-span probing (dataset_reach).
    dr = conn.execute(
        """
        SELECT count(*) AS cnt,
               sum(CASE WHEN bypass_held = 1 THEN 1 ELSE 0 END) AS held
          FROM dataset_reach
         WHERE endpoint_id = ?
        """,
        (endpoint_id,),
    ).fetchone()
    id_span_confirmed = dr["held"] if dr and dr["held"] else 0

    # Pagination reach.
    pr = conn.execute(
        """
        SELECT count(*) AS pages,
               sum(row_count_est) AS total_rows
          FROM pagination_reach
         WHERE endpoint_id = ?
           AND bypass_held  = 1
        """,
        (endpoint_id,),
    ).fetchone()
    pagination_pages = pr["pages"] if pr and pr["pages"] else 0
    pagination_rows  = pr["total_rows"] if pr and pr["total_rows"] else 0

    total_reachable = id_span_confirmed + pagination_rows

    # reach_summary JSON from candidate_access (persisted by Section H).
    ca = conn.execute(
        """
        SELECT reach_summary
          FROM candidate_access
         WHERE endpoint_id = ?
           AND is_verified  = 1
           AND reach_summary IS NOT NULL
         LIMIT 1
        """,
        (endpoint_id,),
    ).fetchone()

    reach_summary = None
    if ca and ca["reach_summary"]:
        try:
            reach_summary = json.loads(ca["reach_summary"])
        except (json.JSONDecodeError, TypeError):
            pass

    return {
        "total_reachable_records": total_reachable,
        "id_span_confirmed":      id_span_confirmed,
        "pagination_pages":       pagination_pages,
        "reach_summary":          reach_summary,
    }


# ── Section I: The Evidence ───────────────────────────────────────

def _evidence(conn, endpoint_id: int) -> dict:
    """
    Redacted PII / sensitive data samples from extraction_results
    and leaked_evidence.
    """
    # Total extracted records.
    er = conn.execute(
        "SELECT count(*) AS cnt FROM extraction_results "
        "WHERE endpoint_id = ?",
        (endpoint_id,),
    ).fetchone()
    extracted_records = er["cnt"] if er else 0

    # Sensitive data hits from leaked_evidence (top 10, redacted).
    le_rows = conn.execute(
        """
        SELECT category, pattern_name, matched_text, context
          FROM leaked_evidence
         WHERE endpoint_id = ?
         ORDER BY id ASC
         LIMIT 10
        """,
        (endpoint_id,),
    ).fetchall()

    sensitive_samples: list[dict] = []
    for r in le_rows:
        sensitive_samples.append({
            "category":     r["category"],
            "pattern_name": r["pattern_name"],
            "matched_text": _redact(r["matched_text"]),
            "context":      _redact(r["context"]) if r["context"] else "",
        })

    return {
        "extracted_records": extracted_records,
        "sensitive_samples": sensitive_samples,
    }


# ── Section J: The Scope ──────────────────────────────────────────

def _scope(conn, endpoint_id: int) -> dict:
    """
    Lateral endpoints compromised and systemic exposure.
    """
    # Candidate endpoints generated from this source.
    ce = conn.execute(
        "SELECT count(*) AS cnt FROM candidate_endpoints "
        "WHERE source_endpoint_id = ?",
        (endpoint_id,),
    ).fetchone()
    lateral_endpoints = ce["cnt"] if ce else 0

    # Systemic vulnerabilities confirmed via lateral probe.
    sv = conn.execute(
        "SELECT count(*) AS cnt FROM systemic_vulnerabilities "
        "WHERE source_endpoint_id = ?",
        (endpoint_id,),
    ).fetchone()
    systemic_bypasses = sv["cnt"] if sv else 0

    # Impact report (if Section J computed it).
    sir = conn.execute(
        """
        SELECT unique_resources_exposed, severity_label
          FROM systemic_impact_report
         WHERE source_endpoint_id = ?
         LIMIT 1
        """,
        (endpoint_id,),
    ).fetchone()

    unique_resources = sir["unique_resources_exposed"] if sir else 0
    severity_label   = sir["severity_label"] if sir else "Not assessed"

    return {
        "lateral_endpoints":        lateral_endpoints,
        "systemic_bypasses":        systemic_bypasses,
        "unique_resources_exposed": unique_resources,
        "severity_label":           severity_label,
    }


# ── Sections K & L: The Proof ─────────────────────────────────────

def _proof(conn, endpoint_id: int) -> dict:
    """
    Contrast results (Section K) and temporal stability scores
    (Section L).
    """
    return {
        "contrast":  _contrast(conn, endpoint_id),
        "stability": _stability(conn, endpoint_id),
    }


def _contrast(conn, endpoint_id: int) -> dict:
    """
    Pull contrast-test profiles and derive verdict, info gain,
    and privilege parity from context_contrast_results.
    """
    rows = conn.execute(
        """
        SELECT profile_key, label, status_code,
               body_length, expected_status, status_match
          FROM context_contrast_results
         WHERE endpoint_id = ?
        """,
        (endpoint_id,),
    ).fetchall()

    profiles_tested = len(rows)

    # Derive bypass verdict from the 'bypass' profile.
    bypass_verdict  = None
    info_gain_pct   = None
    privilege_parity = None
    failure_class   = None

    bypass_row = None
    auth_row   = None
    control_row = None

    for r in rows:
        key = r["profile_key"].lower()  # type: ignore
        if "bypass" in key:
            bypass_row = r
        elif "auth" in key:
            auth_row = r
        elif "control" in key:
            control_row = r

    if bypass_row is not None:
        if bypass_row["status_match"]:  # type: ignore
            bypass_verdict = "CONFIRMED"
        else:
            bypass_verdict = "MISMATCH"

    # Information gain: bypass body vs control body.
    if bypass_row and control_row:
        bp_len  = bypass_row["body_length"] or 0
        ctl_len = control_row["body_length"] or 0
        if ctl_len > 0:
            info_gain_pct = round(  # type: ignore
                (float(bp_len - ctl_len) / float(ctl_len)) * 100.0, 1
            )
        elif bp_len > 0:
            info_gain_pct = 100.0

    # Privilege parity: bypass body ≈ auth body.
    if bypass_row and auth_row:
        bp_len   = bypass_row["body_length"] or 0
        auth_len = auth_row["body_length"] or 0
        if auth_len > 0:
            similarity = 1.0 - abs(bp_len - auth_len) / auth_len
            if similarity >= 0.95:
                privilege_parity = "Full"
            elif similarity >= 0.70:
                privilege_parity = "Partial"
            else:
                privilege_parity = "None"
        else:
            privilege_parity = "Indeterminate"

    # Failure class inference (simplified).
    if bypass_row:
        if control_row and control_row["status_code"] == 403:
            failure_class = "Edge-Enforcement"
        elif control_row and control_row["status_code"] in (401, 302):
            failure_class = "Incomplete-Check"
        elif bypass_row["status_match"]:
            failure_class = "Trust-Failure"

    return {
        "profiles_tested":  profiles_tested,
        "bypass_verdict":   bypass_verdict,
        "info_gain_pct":    info_gain_pct,
        "privilege_parity": privilege_parity,
        "failure_class":    failure_class,
    }


def _stability(conn, endpoint_id: int) -> dict:
    """
    Temporal persistence and survival index from temporal_checks.
    """
    tc = conn.execute(
        """
        SELECT persistence_score, combo_key
          FROM temporal_checks
         WHERE endpoint_id = ?
         LIMIT 1
        """,
        (endpoint_id,),
    ).fetchone()

    persistence_score = tc["persistence_score"] if tc else None

    # Survival index is computed live (not stored), so we
    # recalculate from available data.
    survival_score  = None
    survival_rating = None
    max_drift_pct   = None
    triager_summary = None

    if tc:
        try:
            from bypasser.stability_temporal import (  # type: ignore
                calculate_survival_index,
            )
            si = calculate_survival_index(endpoint_id)
            survival_score  = si.get("survival_score")
            survival_rating = si.get("rating")
            max_drift_pct   = si.get("max_drift_pct")
            triager_summary = si.get("triager_summary")
        except (ValueError, Exception) as exc:
            logger.debug(
                "[M] survival index unavailable for ep %d: %s",
                endpoint_id, exc,
            )

    return {
        "persistence_score": persistence_score,
        "survival_score":    survival_score,
        "survival_rating":   survival_rating,
        "max_drift_pct":     max_drift_pct,
        "triager_summary":   triager_summary,
    }


# ═════════════════════════════════════════════════════════════════════
#  CVSS v3.1 Scoring Engine
# ═════════════════════════════════════════════════════════════════════

# PII / sensitive-data categories from Section G (leaked_evidence).
_PII_CATEGORIES = frozenset({
    "PII", "Credentials", "Financial", "Healthcare",
    "SSN", "Email", "Phone", "Address", "CreditCard",
    "Token", "Secret", "Password", "SessionToken",
})

_TECHNICAL_CATEGORIES = frozenset({
    "TechnicalMetadata", "InternalPath", "StackTrace",
    "ServerVersion", "DebugInfo", "ConfigKey",
})


def calculate_projected_cvss(metrics: dict) -> dict:
    """
    Compute a projected **CVSS v3.1 Base Score** from evidence
    gathered across the entire pipeline.

    The engine maps pipeline findings to the eight CVSS base
    metrics and then applies the official CVSS v3.1 formulae.

    Mapping heuristics
    ------------------
    ===============  ====================================================
    CVSS Metric       Pipeline Signal
    ===============  ====================================================
    Attack Vector    Always **Network** (AV:N) — 403 bypass is remote.
    Attack Complex.  **Low** if bypass ≤ 3 variables, else **High**.
    Priv. Required   **None** — bypass does not need valid credentials.
    User Interaction **None** — fully automated.
    Scope            **Changed** if lateral bypasses ≥ 1, else
                     **Unchanged**.
    Confidentiality  **High** if PII + ≥ 10 000 records, else **Low**
                     if only technical metadata, else **None**.
    Integrity        **Low** if info gain > 0, else **None**.
    Availability     **None** (read-only bypass).
    ===============  ====================================================

    Severity thresholds (official CVSS v3.1):

    * **Critical**  9.0 – 10.0
    * **High**      7.0 – 8.9
    * **Medium**    4.0 – 6.9
    * **Low**       0.1 – 3.9
    * **None**      0.0

    Parameters
    ----------
    metrics : dict
        The output of :func:`aggregate_final_metrics` (without the
        ``cvss`` key — it is added by the caller).

    Returns
    -------
    dict
        ::

            {
                "score":          float,   # 0.0 – 10.0
                "severity":       str,     # Critical|High|Medium|Low|None
                "vector_string":  str,     # e.g. CVSS:3.1/AV:N/...
                "components": {
                    "AV": str, "AC": str, "PR": str, "UI": str,
                    "S":  str, "C":  str, "I":  str, "A":  str,
                },
                "rationale": list[str],    # human-readable justifications
            }
    """
    rationale: list[str] = []

    # ── 1. Attack Vector (AV) ────────────────────────────────────
    av = "N"  # Network — 403 bypass is always remote.
    rationale.append("AV:N — bypass is exploitable over the network.")

    # ── 2. Attack Complexity (AC) ────────────────────────────────
    num_vars = len(metrics.get("exploit", {}).get("variables", []))
    if num_vars <= 3:
        ac = "L"
        rationale.append(
            f"AC:L — exploit requires only {num_vars} variable(s); "
            f"trivially reproducible."
        )
    else:
        ac = "H"
        rationale.append(
            f"AC:H — exploit requires {num_vars} variables; "
            f"non-trivial to reproduce."
        )

    # ── 3. Privileges Required (PR) ──────────────────────────────
    pr = "N"  # The bypass itself IS the privilege escalation.
    rationale.append(
        "PR:N — no valid credentials needed; bypass is the "
        "authentication substitute."
    )

    # ── 4. User Interaction (UI) ─────────────────────────────────
    ui = "N"  # Fully automated.
    rationale.append("UI:N — exploit is fully automated, no user action.")

    # ── 5. Scope (S) ─────────────────────────────────────────────
    lateral = metrics.get("scope", {}).get("systemic_bypasses", 0)
    if lateral >= 1:
        s = "C"  # Changed — bypass affects resources beyond its scope.
        rationale.append(
            f"S:C — bypass impacts {lateral} lateral endpoint(s) "
            f"beyond the original target."
        )
    else:
        s = "U"  # Unchanged.
        rationale.append(
            "S:U — impact is confined to the targeted endpoint."
        )

    # ── 6. Confidentiality Impact (C) ────────────────────────────
    evidence   = metrics.get("evidence", {})
    samples    = evidence.get("sensitive_samples", [])
    scale      = metrics.get("scale", {})
    total_recs = scale.get("total_reachable_records", 0)

    # Classify evidence categories.
    found_pii       = False
    found_technical  = False
    evidence_cats: set[str] = set()

    for sample in samples:
        cat = sample.get("category", "")
        evidence_cats.add(cat)
        if cat in _PII_CATEGORIES:
            found_pii = True
        if cat in _TECHNICAL_CATEGORIES:
            found_technical = True

    # Also check data_classification impact_label if available.
    impact_score = metrics.get("exploit", {}).get("impact_score")
    if impact_score is not None and impact_score >= 8:
        found_pii = True

    if found_pii and total_recs >= 10_000:
        c = "H"
        rationale.append(
            f"C:H — PII categories detected ({', '.join(sorted(evidence_cats))}) "
            f"with {total_recs:,} reachable records → Critical data exposure."
        )
    elif found_pii:
        c = "H"
        rationale.append(
            f"C:H — PII detected ({', '.join(sorted(evidence_cats))}) "
            f"but record count ({total_recs:,}) below 10 000."
        )
    elif found_technical or len(samples) > 0:
        c = "L"
        rationale.append(
            f"C:L — only technical metadata found "
            f"({', '.join(sorted(evidence_cats)) or 'misc'})."
        )
    else:
        c = "N"
        rationale.append("C:N — no sensitive data leaked.")

    # ── 7. Integrity Impact (I) ──────────────────────────────────
    info_gain = (
        metrics.get("proof", {})
        .get("contrast", {})
        .get("info_gain_pct")
    )
    if info_gain is not None and info_gain > 0:
        i = "L"
        rationale.append(
            f"I:L — information gain of {info_gain:.1f}% indicates "
            f"the bypass returns data the control profile cannot."
        )
    else:
        i = "N"
        rationale.append("I:N — no integrity impact; read-only bypass.")

    # ── 8. Availability Impact (A) ───────────────────────────────
    a = "N"  # Read-only bypass does not affect availability.
    rationale.append("A:N — bypass is read-only; no denial of service.")

    # ── 9. Calculate CVSS v3.1 Base Score ────────────────────────
    components = {
        "AV": av, "AC": ac, "PR": pr, "UI": ui,
        "S": s,   "C": c,  "I": i,   "A": a,
    }
    vector_str = (
        f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}"
        f"/S:{s}/C:{c}/I:{i}/A:{a}"
    )

    score = _cvss31_base_score(components)
    severity = _cvss31_severity(score)

    # ── 10. Override: PII + massive scale → floor at 9.0 ────────
    if found_pii and total_recs >= 10_000 and score < 9.0:
        rationale.append(
            f"Override: PII with {total_recs:,} records forces "
            f"minimum Critical floor (9.0). "
            f"Original calculated score: {score:.1f}."
        )
        score = 9.0
        severity = "Critical"

    # ── 11. Override: technical-only → cap at 7.0 ───────────────
    if not found_pii and found_technical and score > 7.0:
        rationale.append(
            f"Cap: only technical metadata detected; capping "
            f"score at 7.0 (original: {score:.1f})."
        )
        score = 7.0
        severity = _cvss31_severity(score)

    logger.info(
        "[M] CVSS: %.1f %s  vector=%s",
        score, severity, vector_str,
    )

    return {
        "score":         score,
        "severity":      severity,
        "vector_string": vector_str,
        "components":    components,
        "rationale":     rationale,
    }


# ── CVSS v3.1 formulae (official spec) ────────────────────────────

# Lookup tables from the CVSS v3.1 specification.
_AV_VALS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC_VALS = {"L": 0.77, "H": 0.44}
_PR_VALS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_VALS_CHANGED   = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI_VALS = {"N": 0.85, "R": 0.62}
_CIA_VALS = {"H": 0.56, "L": 0.22, "N": 0.0}


def _cvss31_base_score(comp: dict[str, str]) -> float:
    """
    Calculate the CVSS v3.1 base score from component values.

    Implements the official CVSS v3.1 equations from
    https://www.first.org/cvss/v3.1/specification-document.
    """
    av_v = _AV_VALS[comp["AV"]]
    ac_v = _AC_VALS[comp["AC"]]
    ui_v = _UI_VALS[comp["UI"]]

    scope_changed = comp["S"] == "C"
    if scope_changed:
        pr_v = _PR_VALS_CHANGED[comp["PR"]]
    else:
        pr_v = _PR_VALS_UNCHANGED[comp["PR"]]

    c_v = _CIA_VALS[comp["C"]]
    i_v = _CIA_VALS[comp["I"]]
    a_v = _CIA_VALS[comp["A"]]

    # Exploitability sub-score.
    exploitability = 8.22 * av_v * ac_v * pr_v * ui_v

    # Impact sub-score.
    iss = 1.0 - ((1.0 - c_v) * (1.0 - i_v) * (1.0 - a_v))

    if iss <= 0:
        return 0.0

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    if scope_changed:
        raw = min(1.08 * (impact + exploitability), 10.0)
    else:
        raw = min(impact + exploitability, 10.0)

    # CVSS v3.1: round up to one decimal place.
    return _roundup(raw)


def _roundup(value: float) -> float:
    """CVSS v3.1 'roundup' — ceiling to nearest 0.1."""
    return math.ceil(value * 10) / 10


def _cvss31_severity(score: float) -> str:
    """Map a CVSS score to its qualitative severity label."""
    if score == 0.0:
        return "None"
    elif score <= 3.9:
        return "Low"
    elif score <= 6.9:
        return "Medium"
    elif score <= 8.9:
        return "High"
    else:
        return "Critical"


# ═════════════════════════════════════════════════════════════════════
#  Markdown Report Generator
# ═════════════════════════════════════════════════════════════════════

# Header-category set reproduced from stability_temporal to avoid a
# cross-module import solely for curl generation.
_HEADER_CATEGORIES = {"Header", "Internal-Only", "Proxy", "Identity"}

# Mitigation templates keyed on the contrast failure_class.
_MITIGATION_TEMPLATES: dict[str, str] = {
    "Edge-Enforcement": textwrap.dedent("""\
        ### Root Cause — Edge-Only Enforcement

        The 403 restriction is enforced **exclusively at the WAF / CDN
        edge** and is **not replicated at the origin server**.  Any
        request that bypasses the edge layer (via header injection,
        direct-IP access, or protocol downgrade) reaches an
        unprotected origin.

        ### Recommended Fix

        1. **Enforce at origin**: Add an equivalent deny rule in the
           application’s own middleware or gateway (e.g. a Spring
           Security filter, Express middleware, NGINX `location`
           block).
        2. **Restrict origin ingress**: Configure the origin server to
           accept connections **only** from the edge / CDN IP ranges.
        3. **Add a shared secret**: Require a secret header between
           edge and origin (e.g. `X-Edge-Secret`) and reject any
           request that lacks it.
    """),
    "Incomplete-Check": textwrap.dedent("""\
        ### Root Cause — Incomplete Authentication Check

        The application returns a login redirect (302) or
        authentication challenge (401) for the baseline request, but
        the bypass combination produces a fully authenticated response
        without valid credentials.

        ### Recommended Fix

        1. **Validate session server-side**: Ensure every data-
           returning endpoint validates the session token (cookie /
           bearer) **before** rendering any response body.
        2. **Remove implicit trust headers**: Do not honour
           `X-Forwarded-For`, `X-Real-IP`, or
           `X-Original-URL` as authentication signals unless they
           originate from a verified upstream proxy.
        3. **Defence in depth**: Apply role-based access control (RBAC)
           at the data-access layer, not only at the HTTP layer.
    """),
    "Trust-Failure": textwrap.dedent("""\
        ### Root Cause — Misplaced Trust in Client Headers

        The server trusts client-supplied headers (e.g.
        `X-Forwarded-For`, `X-Custom-IP-Authorization`) as proof of
        identity or network location.  An attacker can forge these
        headers to impersonate a trusted IP or internal user.

        ### Recommended Fix

        1. **Strip untrusted headers**: Configure the reverse proxy /
           load balancer to **overwrite** (not append to)
           `X-Forwarded-For` and similar headers with the actual
           client IP.
        2. **Allowlist upstream proxies**: Only accept forwarded
           headers from known proxy IPs.
        3. **Authenticate by token, not IP**: Replace IP-based
           allowlisting with proper token authentication.
    """),
}

_MITIGATION_GENERIC = textwrap.dedent("""\
    ### General Recommendations

    1. **Enforce access control at the origin**, not only at the
       edge / WAF / CDN.
    2. **Strip or overwrite** client-supplied proxy headers
       (`X-Forwarded-For`, `X-Real-IP`, `X-Original-URL`) at the
       reverse-proxy layer.
    3. **Validate sessions server-side** for every endpoint that
       returns sensitive data.
    4. **Deploy monitoring**: Alert on successful requests to
       previously-blocked paths, especially from novel User-Agents.
""")


def generate_markdown_report(
    endpoint_id: int,
    output_dir: str = "reports",
) -> str:
    """
    Produce an industry-standard Markdown vulnerability report for
    one verified bypass.

    The file is written to ``<output_dir>/vuln_ep<endpoint_id>.md``.

    Sections
    --------
    1. **Summary** — one-sentence impact with CVSS badge.
    2. **Steps to Reproduce** — copy-paste ``curl`` command.
    3. **Impact Analysis** — leaked data categories, dataset reach,
       lateral scope, and contrast results.
    4. **Mitigation Suggestion** — tailored to the detected
       WAF / Origin failure class.

    Parameters
    ----------
    endpoint_id : int
        ID of the endpoint with a verified bypass.
    output_dir : str
        Directory to write the ``.md`` file into.  Created if absent.

    Returns
    -------
    str
        Absolute path to the generated ``.md`` file.
    """
    # Gather all metrics (including CVSS).
    metrics = aggregate_final_metrics(endpoint_id)

    lines: list[str] = []
    _w = lines.append  # shorthand

    # ── Title ─────────────────────────────────────────────────────
    url    = metrics["url"]
    method = metrics["method"]
    cvss   = metrics.get("cvss", {})
    score  = cvss.get("score", 0.0)
    sev    = cvss.get("severity", "Unknown")
    vector = cvss.get("vector_string", "")

    parsed = urlparse(url)
    host   = parsed.hostname or parsed.netloc or "unknown"

    _w(f"# 403 Bypass — {method} {url}")
    _w("")
    _w(f"**CVSS {score:.1f} ({sev})** &nbsp; `{vector}`")
    _w("")
    _w(f"> Generated: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}")
    _w("")
    _w("---")
    _w("")

    # ── 1. Summary ────────────────────────────────────────────────
    _w("## 1. Summary")
    _w("")
    _w(_build_summary_sentence(metrics))
    _w("")

    # ── 2. Steps to Reproduce ─────────────────────────────────────
    _w("## 2. Steps to Reproduce")
    _w("")
    _w("Copy-paste the following command to verify the bypass:")
    _w("")
    _w("```bash")
    _w(_build_curl_command(metrics))
    _w("```")
    _w("")
    _w(_explain_curl(metrics))
    _w("")

    # ── 3. Impact Analysis ────────────────────────────────────────
    _w("## 3. Impact Analysis")
    _w("")
    _write_impact_analysis(lines, metrics)
    _w("")

    # ── 4. Mitigation Suggestion ──────────────────────────────────
    _w("## 4. Mitigation Suggestion")
    _w("")
    failure_class = (
        metrics.get("proof", {})
        .get("contrast", {})
        .get("failure_class")
    )
    mitigation = _MITIGATION_TEMPLATES.get(
        failure_class or "", _MITIGATION_GENERIC,
    )
    _w(mitigation.rstrip())
    _w("")

    # ── 5. CVSS Rationale (appendix) ──────────────────────────────
    rationale = cvss.get("rationale", [])
    if rationale:
        _w("## Appendix — CVSS Rationale")
        _w("")
        for r in rationale:
            _w(f"- {r}")
        _w("")

    # ── Write to disk ─────────────────────────────────────────────
    os.makedirs(output_dir, exist_ok=True)
    filename = f"vuln_ep{endpoint_id}.md"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    abs_path = os.path.abspath(filepath)
    logger.info(
        "[M] report written: %s  (%d bytes)",
        abs_path, os.path.getsize(abs_path),
    )
    return abs_path


# ── Report-section builders ───────────────────────────────────────

def _build_summary_sentence(m: dict) -> str:
    """
    One-sentence impact statement for the Summary section.
    """
    url       = m["url"]
    method    = m["method"]
    sev       = m.get("cvss", {}).get("severity", "Unknown")
    total     = m.get("scale", {}).get("total_reachable_records", 0)
    lateral   = m.get("scope", {}).get("systemic_bypasses", 0)
    evidence  = m.get("evidence", {})
    samples   = evidence.get("sensitive_samples", [])
    combo     = m.get("exploit", {}).get("combo_key", "unknown combo")
    parity    = (
        m.get("proof", {}).get("contrast", {}).get("privilege_parity")
    )

    # Determine data type descriptor.
    cats = {s.get("category", "") for s in samples}
    if cats & _PII_CATEGORIES:
        data_desc = "PII / sensitive user data"
    elif cats & _TECHNICAL_CATEGORIES:
        data_desc = "internal technical metadata"
    elif samples:
        data_desc = "authenticated-level data"
    else:
        data_desc = "restricted content"

    parts = [
        f"A **{sev}**-severity 403 bypass on `{method} {url}` "
        f"exposes {data_desc}"
    ]
    if total > 0:
        parts.append(f" across **{total:,}** reachable records")
    if lateral > 0:
        parts.append(
            f", with the flaw replicating to **{lateral}** "
            f"additional endpoint(s)"
        )
    if parity == "Full":
        parts.append(
            ", achieving **full privilege parity** with an "
            "authenticated admin session"
        )
    parts.append(".")
    return "".join(parts)


def _build_curl_command(m: dict) -> str:
    """
    Generate a copy-paste ``curl`` command that reproduces the
    bypass.
    """
    url     = m["url"]
    method  = m["method"]
    exploit = m.get("exploit", {})
    variables = exploit.get("variables", [])

    parts = ["curl -ik"]

    if method != "GET":
        parts.append(f" -X {method}")

    # Build bypass headers from variables.
    for var in variables:
        cat = var.get("category", "")
        if cat in _HEADER_CATEGORIES:
            name  = var.get("name", "")
            value = var.get("test_value", "")
            if name and value:
                # Shell-escape single quotes in values.
                safe_val = value.replace("'", "'\\''")
                parts.append(f" \\\n  -H '{name}: {safe_val}'")

    parts.append(f" \\\n  '{url}'")
    return "".join(parts)


def _explain_curl(m: dict) -> str:
    """
    Short prose explanation of what each curl header achieves.
    """
    variables = m.get("exploit", {}).get("variables", [])
    if not variables:
        return "No special headers required."

    lines = ["**Header breakdown:**"]
    lines.append("")
    for var in variables:
        cat = var.get("category", "")
        if cat in _HEADER_CATEGORIES:
            name  = var.get("name", "")
            value = var.get("test_value", "")
            lines.append(
                f"| `{name}` | `{value}` | "
                f"Category: *{cat}* — tricks the server into "
                f"treating the request as originating from a "
                f"trusted source. |"
            )

    if len(lines) > 2:  # Has table rows.
        # Inject table header.
        lines.insert(1, "| Header | Value | Purpose |")
        lines.insert(2, "|--------|-------|---------|")

    return "\n".join(lines)


def _write_impact_analysis(lines: list[str], m: dict) -> None:
    """
    Write the Impact Analysis section covering leaked data,
    dataset reach, lateral scope, and contrast proof.
    """
    evidence = m.get("evidence", {})
    scale    = m.get("scale", {})
    scope    = m.get("scope", {})
    proof    = m.get("proof", {})
    contrast = proof.get("contrast", {})
    stability = proof.get("stability", {})

    _w = lines.append

    # ── 3a. Leaked Data ───────────────────────────────────────────
    _w("### 3a. Leaked Data")
    _w("")

    samples = evidence.get("sensitive_samples", [])
    extracted = evidence.get("extracted_records", 0)

    if samples:
        _w(f"**{len(samples)}** sensitive data sample(s) detected "
           f"out of **{extracted}** extracted records:")
        _w("")
        _w("| # | Category | Pattern | Redacted Match |")
        _w("|---|----------|---------|----------------|")
        for idx, s in enumerate(samples, 1):
            cat  = s.get("category", "")
            pat  = s.get("pattern_name", "")
            text = s.get("matched_text", "")
            _w(f"| {idx} | {cat} | {pat} | `{text}` |")
        _w("")
    else:
        _w("No PII or sensitive data patterns matched in the "
           "extracted response bodies.")
        _w("")

    # ── 3b. Dataset Reach ─────────────────────────────────────────
    _w("### 3b. Dataset Reach")
    _w("")
    total    = scale.get("total_reachable_records", 0)
    id_span  = scale.get("id_span_confirmed", 0)
    pages    = scale.get("pagination_pages", 0)

    _w(f"| Metric | Value |")
    _w(f"|--------|-------|")
    _w(f"| Total reachable records | **{total:,}** |")
    _w(f"| ID-span records confirmed | {id_span:,} |")
    _w(f"| Pagination pages with bypass | {pages:,} |")
    _w("")

    # ── 3c. Lateral Scope ─────────────────────────────────────────
    _w("### 3c. Lateral Scope")
    _w("")
    lateral  = scope.get("lateral_endpoints", 0)
    systemic = scope.get("systemic_bypasses", 0)
    exposed  = scope.get("unique_resources_exposed", 0)
    sev_lbl  = scope.get("severity_label", "Not assessed")

    _w(f"| Metric | Value |")
    _w(f"|--------|-------|")
    _w(f"| Candidate endpoints tested | {lateral:,} |")
    _w(f"| Systemic bypasses confirmed | {systemic:,} |")
    _w(f"| Unique resources exposed | {exposed:,} |")
    _w(f"| Severity label | **{sev_lbl}** |")
    _w("")

    # ── 3d. Contrast Proof ────────────────────────────────────────
    _w("### 3d. Contrast Proof")
    _w("")

    verdict   = contrast.get("bypass_verdict", "—")
    gain      = contrast.get("info_gain_pct")
    parity    = contrast.get("privilege_parity", "—")
    fc        = contrast.get("failure_class", "—")
    profiles  = contrast.get("profiles_tested", 0)

    _w(f"| Metric | Value |")
    _w(f"|--------|-------|")
    _w(f"| Profiles tested | {profiles} |")
    _w(f"| Bypass verdict | **{verdict}** |")
    _w(f"| Information gain | "
       f"{f'{gain:.1f}%' if gain is not None else '—'} |")
    _w(f"| Privilege parity | {parity} |")
    _w(f"| Failure class | {fc} |")
    _w("")

    # ── 3e. Stability ─────────────────────────────────────────────
    _w("### 3e. Temporal Stability")
    _w("")

    persistence = stability.get("persistence_score", "—")
    surv_score  = stability.get("survival_score")
    surv_rating = stability.get("survival_rating", "—")
    drift       = stability.get("max_drift_pct")
    triager     = stability.get("triager_summary")

    _w(f"| Metric | Value |")
    _w(f"|--------|-------|")
    _w(f"| Persistence score | {persistence} |")
    _w(f"| Survival index | "
       f"{f'{surv_score:.0f}/100' if surv_score is not None else '—'} |")
    _w(f"| Survival rating | **{surv_rating}** |")
    _w(f"| Max body drift | "
       f"{f'{drift:.1f}%' if drift is not None else '—'} |")
    _w("")

    if triager:
        _w(f"> **Triager note:** {triager}")
        _w("")


# ═════════════════════════════════════════════════════════════════════
#  Report Archive Bundler
# ═════════════════════════════════════════════════════════════════════

def bundle_report_archive(
    endpoint_id: int,
    output_dir: str = "reports",
) -> str:
    """
    Package all artefacts for a single verified bypass into
    a submission-ready ZIP archive.

    Archive name::

        Arbiter_Report_<hostname>_<YYYY-MM-DD>.zip

    Contents
    --------
    ``report/``
        The Markdown vulnerability report (``vuln_ep<id>.md``).
    ``evidence/``
        All ``poc_evidence_<id>.json`` files found in the working
        directory.
    ``stability/``
        ``stability_logs.json``  — Section F stability check results.
        ``temporal_checks.json`` — Section L temporal check anchors.
        ``persistence_log.json`` — Section L persistence re-tests.
    ``metrics/``
        ``aggregate_metrics.json`` — the full metrics package
        (including CVSS) as JSON.

    Parameters
    ----------
    endpoint_id : int
        ID of the endpoint with a verified bypass.
    output_dir : str
        Directory to write the ``.zip`` file into.  Created if absent.

    Returns
    -------
    str
        Absolute path to the generated ``.zip`` file.
    """
    # 1. Generate the Markdown report (idempotent).
    md_path = generate_markdown_report(endpoint_id, output_dir)

    # 2. Gather the aggregated metrics (already computed by the
    #    Markdown generator, but we re-fetch to get the dict).
    metrics = aggregate_final_metrics(endpoint_id)

    # 3. Derive archive name from the URL.
    parsed = urlparse(metrics["url"])
    host   = (parsed.hostname or "unknown").replace(".", "_")
    today  = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    zip_name = f"Arbiter_Report_{host}_{today}.zip"

    os.makedirs(output_dir, exist_ok=True)
    zip_path = os.path.join(output_dir, zip_name)

    with zipfile.ZipFile(
        zip_path, "w", compression=zipfile.ZIP_DEFLATED,
    ) as zf:

        # ── report/ ─────────────────────────────────────────────
        if os.path.isfile(md_path):
            zf.write(md_path, f"report/{os.path.basename(md_path)}")
            logger.info("[ZIP]  + report/%s", os.path.basename(md_path))

        # ── evidence/ ───────────────────────────────────────────
        #   Collect all poc_evidence_*.json from the CWD.
        evidence_added = 0
        for fname in sorted(os.listdir(".")):
            if (
                fname.startswith("poc_evidence_")
                and fname.endswith(".json")
            ):
                zf.write(fname, f"evidence/{fname}")
                evidence_added += 1  # type: ignore
                logger.info("[ZIP]  + evidence/%s", fname)

        #   Also include the endpoint-specific one from the
        #   output_dir if it was written there instead.
        poc_in_out = os.path.join(
            output_dir, f"poc_evidence_{endpoint_id}.json",
        )
        if os.path.isfile(poc_in_out):
            arc = f"evidence/poc_evidence_{endpoint_id}.json"
            if arc not in zf.namelist():
                zf.write(poc_in_out, arc)
                evidence_added += 1  # type: ignore
                logger.info("[ZIP]  + %s", arc)

        # ── stability/ ──────────────────────────────────────────
        #   Export stability-related tables as JSON.
        _export_stability_data(zf, endpoint_id)

        # ── metrics/ ────────────────────────────────────────────
        metrics_json = json.dumps(
            metrics, indent=2, ensure_ascii=False, default=str,
        )
        zf.writestr(
            "metrics/aggregate_metrics.json", metrics_json,
        )
        logger.info("[ZIP]  + metrics/aggregate_metrics.json")

    abs_path = os.path.abspath(zip_path)
    size_kb  = os.path.getsize(abs_path) / 1024

    logger.info(
        "[M] archive created: %s  (%.1f KB, %d files)",
        abs_path, size_kb, len(zipfile.ZipFile(abs_path).namelist()),
    )
    print(
        f"\n[+] Report archive ready: {abs_path}  "
        f"({size_kb:.1f} KB)"
    )
    return abs_path


def _export_stability_data(
    zf: zipfile.ZipFile, endpoint_id: int,
) -> None:
    """
    Export stability-related database tables for *endpoint_id*
    as JSON files inside the ``stability/`` archive directory.
    """
    conn = get_connection()
    try:
        # ── stability_logs (Section F) ───────────────────────────
        rows = conn.execute(
            "SELECT * FROM stability_logs WHERE endpoint_id = ? "
            "ORDER BY id ASC",
            (endpoint_id,),
        ).fetchall()
        _write_rows_json(zf, "stability/stability_logs.json", rows)

        # ── temporal_checks (Section L anchor) ───────────────────
        try:
            tc_rows = conn.execute(
                "SELECT * FROM temporal_checks WHERE endpoint_id = ? "
                "ORDER BY id ASC",
                (endpoint_id,),
            ).fetchall()
            _write_rows_json(
                zf, "stability/temporal_checks.json", tc_rows,
            )
        except Exception:
            # Table may not exist if Section L was never run.
            logger.debug(
                "[ZIP] temporal_checks table not found, skipping."
            )

        # ── persistence_log (Section L re-tests) ─────────────────
        try:
            pl_rows = conn.execute(
                "SELECT * FROM persistence_log WHERE endpoint_id = ? "
                "ORDER BY id ASC",
                (endpoint_id,),
            ).fetchall()
            _write_rows_json(
                zf, "stability/persistence_log.json", pl_rows,
            )
        except Exception:
            logger.debug(
                "[ZIP] persistence_log table not found, skipping."
            )
    finally:
        conn.close()


def _write_rows_json(
    zf: zipfile.ZipFile, arc_name: str, rows: list,
) -> None:
    """
    Convert ``sqlite3.Row`` objects to dicts and write them
    as a JSON array into the archive.
    """
    data = [dict(r) for r in rows]
    payload = json.dumps(
        data, indent=2, ensure_ascii=False, default=str,
    )
    zf.writestr(arc_name, payload)
    logger.info("[ZIP]  + %s  (%d rows)", arc_name, len(data))
