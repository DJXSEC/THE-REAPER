"""
Persistent state layer for the 403 bypass scanner.

Initializes and manages the pipeline_state.db SQLite database,
which tracks endpoint behaviour across scan phases.
"""

import sqlite3
import os

DB_NAME = "pipeline_state.db"
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", DB_NAME)


def get_connection() -> sqlite3.Connection:
    """Return a connection to the pipeline state database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db() -> None:
    """
    Create the `endpoints` table if it does not already exist.

    Columns
    -------
    id            : INTEGER PRIMARY KEY – auto-incrementing row id.
    url           : TEXT    – full endpoint URL.
    method        : TEXT    – HTTP method (GET, POST, PUT, …).
    status_code   : INTEGER – HTTP response status code.
    body_length   : INTEGER – length of the response body in bytes.
    header_hash   : TEXT    – deterministic hash of selected response headers.
    entropy_score : REAL    – Shannon entropy of the response body.
    waf_type          : TEXT    – detected WAF / infrastructure (e.g. 'Cloudflare').
    denial_source     : TEXT    – enforcer identified from 403 body text.
    denial_layer      : TEXT    – 'Edge-Layer' or 'Application-Layer'.
    response_time_ms  : REAL    – round-trip time of the baseline request in ms.
    fingerprint_group_id : TEXT – UUID linking to a denial body cluster.
    processing_depth  : TEXT    – 'Level 1: Edge' or 'Level 2: Origin'.
    is_stable         : INTEGER – boolean flag (0/1) indicating response stability.
    created_at        : TEXT    – ISO-8601 timestamp, defaults to current UTC time.
    """
    conn = get_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS endpoints (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                url            TEXT    NOT NULL,
                method         TEXT    NOT NULL DEFAULT 'GET',
                status_code    INTEGER,
                body_length    INTEGER,
                header_hash    TEXT,
                entropy_score  REAL,
                waf_type       TEXT    DEFAULT 'Unknown',
                denial_source    TEXT,
                denial_layer     TEXT,
                response_time_ms REAL,
                fingerprint_group_id TEXT,
                processing_depth TEXT,
                is_stable        INTEGER DEFAULT 0,
                created_at     TEXT    DEFAULT (datetime('now'))
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fingerprint_groups (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id       TEXT    NOT NULL UNIQUE,
                canonical_body TEXT    NOT NULL,
                created_at     TEXT    DEFAULT (datetime('now'))
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS policy_variables (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL UNIQUE,
                category    TEXT    NOT NULL,
                test_value  TEXT    NOT NULL,
                description TEXT,
                is_active   INTEGER NOT NULL DEFAULT 1,
                created_at  TEXT    DEFAULT (datetime('now'))
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sensitivity_results (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id       INTEGER NOT NULL,
                variable_id       INTEGER NOT NULL,
                is_policy_relevant INTEGER NOT NULL DEFAULT 0,
                status_diff       INTEGER NOT NULL DEFAULT 0,
                length_delta      INTEGER NOT NULL DEFAULT 0,
                headers_diff      INTEGER NOT NULL DEFAULT 0,
                structure_diff    REAL    NOT NULL DEFAULT 0.0,
                reproducible      INTEGER NOT NULL DEFAULT 0,
                created_at        TEXT    DEFAULT (datetime('now')),
                UNIQUE(endpoint_id, variable_id)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS combination_results (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id       INTEGER NOT NULL,
                combo_key         TEXT    NOT NULL,
                combo_depth       INTEGER NOT NULL,
                transition_type   TEXT    NOT NULL,
                baseline_status   INTEGER NOT NULL,
                combo_status      INTEGER NOT NULL,
                baseline_length   INTEGER NOT NULL DEFAULT 0,
                combo_length      INTEGER NOT NULL DEFAULT 0,
                baseline_entropy  REAL    NOT NULL DEFAULT 0.0,
                combo_entropy     REAL    NOT NULL DEFAULT 0.0,
                detail            TEXT    NOT NULL DEFAULT '',
                reproducible      INTEGER NOT NULL DEFAULT 0,
                created_at        TEXT    DEFAULT (datetime('now')),
                UNIQUE(endpoint_id, combo_key)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS candidate_access (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id       INTEGER NOT NULL,
                combination_id    TEXT    NOT NULL,
                transition_type   TEXT    NOT NULL,
                new_status        INTEGER NOT NULL,
                new_length        INTEGER NOT NULL DEFAULT 0,
                is_verified       INTEGER NOT NULL DEFAULT 0,
                stability_score   INTEGER NOT NULL DEFAULT 0,
                created_at        TEXT    DEFAULT (datetime('now')),
                UNIQUE(endpoint_id, combination_id)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS failed_candidates (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                candidate_id    INTEGER NOT NULL,
                endpoint_id     INTEGER NOT NULL,
                combo_key       TEXT    NOT NULL,
                expected_status INTEGER NOT NULL,
                check_results   TEXT    NOT NULL,
                failure_reason  TEXT    NOT NULL,
                created_at      TEXT    DEFAULT (datetime('now'))
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS stability_logs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                candidate_id    INTEGER NOT NULL,
                endpoint_id     INTEGER NOT NULL,
                combo_key       TEXT    NOT NULL,
                phase           TEXT    NOT NULL,
                outcome         TEXT    NOT NULL,
                stability_score INTEGER NOT NULL DEFAULT 0,
                detail          TEXT    NOT NULL DEFAULT '',
                created_at      TEXT    DEFAULT (datetime('now'))
            );
            """
        )
        # Migration: add stability_score to candidate_access for databases
        # that were created before this column existed.  ALTER TABLE is
        # idempotent here — if the column is already present SQLite raises
        # an OperationalError which we silently swallow.
        try:
            conn.execute(
                "ALTER TABLE candidate_access "
                "ADD COLUMN stability_score INTEGER NOT NULL DEFAULT 0"
            )
        except Exception:
            pass  # column already exists

        # Migration: add impact_score (Section G composite 1–10) to
        # candidate_access for databases created before this column.
        try:
            conn.execute(
                "ALTER TABLE candidate_access "
                "ADD COLUMN impact_score INTEGER NOT NULL DEFAULT 0"
            )
        except Exception:
            pass  # column already exists

        # Migration: add reach_summary (Section H JSON blob) to
        # candidate_access for databases created before this column.
        try:
            conn.execute(
                "ALTER TABLE candidate_access "
                "ADD COLUMN reach_summary TEXT NOT NULL DEFAULT '{}'"
            )
        except Exception:
            pass  # column already exists

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS leaked_evidence (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id     INTEGER NOT NULL,
                combo_key       TEXT    NOT NULL,
                category        TEXT    NOT NULL,
                pattern_name    TEXT    NOT NULL,
                matched_text    TEXT    NOT NULL,
                context         TEXT    NOT NULL DEFAULT '',
                created_at      TEXT    DEFAULT (datetime('now')),
                UNIQUE(endpoint_id, combo_key, pattern_name, matched_text)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS variability_results (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id       INTEGER NOT NULL,
                combo_key         TEXT    NOT NULL,
                variability_index REAL    NOT NULL DEFAULT 0.0,
                classification    TEXT    NOT NULL DEFAULT 'Static',
                url_variations    TEXT    NOT NULL DEFAULT '[]',
                body_lengths      TEXT    NOT NULL DEFAULT '[]',
                body_hashes       TEXT    NOT NULL DEFAULT '[]',
                created_at        TEXT    DEFAULT (datetime('now')),
                UNIQUE(endpoint_id, combo_key)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS data_classification (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id       INTEGER NOT NULL,
                combo_key         TEXT    NOT NULL,
                impact_label      TEXT    NOT NULL DEFAULT 'Unknown',
                mock_score        REAL    NOT NULL DEFAULT 0.0,
                production_score  REAL    NOT NULL DEFAULT 0.0,
                mock_hits         TEXT    NOT NULL DEFAULT '[]',
                production_hits   TEXT    NOT NULL DEFAULT '[]',
                created_at        TEXT    DEFAULT (datetime('now')),
                UNIQUE(endpoint_id, combo_key)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS referential_integrity (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id       INTEGER NOT NULL,
                combo_key         TEXT    NOT NULL,
                ref_type          TEXT    NOT NULL,
                ref_value         TEXT    NOT NULL,
                shadow_url        TEXT    NOT NULL,
                shadow_status     INTEGER NOT NULL DEFAULT 0,
                shadow_length     INTEGER NOT NULL DEFAULT 0,
                is_reachable      INTEGER NOT NULL DEFAULT 0,
                exposure_class    TEXT    NOT NULL DEFAULT 'Single',
                created_at        TEXT    DEFAULT (datetime('now')),
                UNIQUE(endpoint_id, combo_key, shadow_url)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS identifier_analysis (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id       INTEGER NOT NULL,
                combo_key         TEXT    NOT NULL,
                id_value          TEXT    NOT NULL,
                id_type           TEXT    NOT NULL DEFAULT 'Unknown',
                source            TEXT    NOT NULL DEFAULT '',
                is_sequential     INTEGER NOT NULL DEFAULT 0,
                gap_size          INTEGER,
                entropy           REAL    NOT NULL DEFAULT 0.0,
                predictability    TEXT    NOT NULL DEFAULT 'Unknown',
                scope_test_urls   TEXT    NOT NULL DEFAULT '[]',
                created_at        TEXT    DEFAULT (datetime('now')),
                UNIQUE(endpoint_id, combo_key, id_value)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dataset_reach (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id       INTEGER NOT NULL,
                combo_key         TEXT    NOT NULL,
                original_id       TEXT    NOT NULL,
                probed_id         TEXT    NOT NULL,
                offset            INTEGER NOT NULL,
                probe_url         TEXT    NOT NULL,
                http_status       INTEGER,
                body_length       INTEGER NOT NULL DEFAULT 0,
                bypass_held       INTEGER NOT NULL DEFAULT 0,
                body_similarity   REAL    NOT NULL DEFAULT 0.0,
                error             TEXT,
                created_at        TEXT    DEFAULT (datetime('now')),
                UNIQUE(endpoint_id, combo_key, probed_id)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pagination_reach (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id       INTEGER NOT NULL,
                combo_key         TEXT    NOT NULL,
                param_name        TEXT    NOT NULL,
                probe_type        TEXT    NOT NULL DEFAULT '',
                original_value    TEXT    NOT NULL DEFAULT '',
                probed_value      TEXT    NOT NULL,
                probe_url         TEXT    NOT NULL,
                http_status       INTEGER,
                body_length       INTEGER NOT NULL DEFAULT 0,
                row_count_est     INTEGER,
                bypass_held       INTEGER NOT NULL DEFAULT 0,
                is_max_reached    INTEGER NOT NULL DEFAULT 0,
                hard_cap          INTEGER,
                error             TEXT,
                created_at        TEXT    DEFAULT (datetime('now')),
                UNIQUE(endpoint_id, combo_key, param_name, probed_value)
            );
            """
        )
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reference_keys (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id        INTEGER NOT NULL,
                combo_key          TEXT    NOT NULL,
                key_name           TEXT    NOT NULL,
                key_value          TEXT    NOT NULL,
                key_type           TEXT    NOT NULL DEFAULT 'Unknown',
                source_evidence_id INTEGER,
                created_at         TEXT    DEFAULT (datetime('now')),
                UNIQUE(endpoint_id, combo_key, key_name, key_value)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS candidate_endpoints (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                source_endpoint_id   INTEGER NOT NULL,
                fingerprint_group_id TEXT,
                url                  TEXT    NOT NULL,
                resource_segment     TEXT    NOT NULL DEFAULT '',
                neighbor_segment     TEXT    NOT NULL DEFAULT '',
                generation_strategy  TEXT    NOT NULL DEFAULT '',
                status               TEXT    NOT NULL DEFAULT 'pending',
                created_at           TEXT    DEFAULT (datetime('now')),
                UNIQUE(source_endpoint_id, url)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS systemic_vulnerabilities (
                id                     INTEGER PRIMARY KEY AUTOINCREMENT,
                source_endpoint_id     INTEGER NOT NULL,
                candidate_endpoint_id  INTEGER NOT NULL,
                source_url             TEXT    NOT NULL,
                candidate_url          TEXT    NOT NULL,
                combo_key              TEXT    NOT NULL,
                probe_status           INTEGER NOT NULL DEFAULT 0,
                baseline_status        INTEGER NOT NULL DEFAULT 0,
                transition_type        TEXT    NOT NULL DEFAULT '',
                finding_label          TEXT    NOT NULL DEFAULT 'Systemic Vulnerability',
                created_at             TEXT    DEFAULT (datetime('now')),
                UNIQUE(candidate_endpoint_id, combo_key)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnerability_graph (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                source_endpoint_id   INTEGER NOT NULL,
                source_key_id        INTEGER NOT NULL,
                source_key_name      TEXT    NOT NULL DEFAULT '',
                source_key_value     TEXT    NOT NULL DEFAULT '',
                target_url           TEXT    NOT NULL,
                target_status        INTEGER NOT NULL DEFAULT 0,
                baseline_status      INTEGER NOT NULL DEFAULT 0,
                combo_key            TEXT    NOT NULL DEFAULT '',
                relationship_type    TEXT    NOT NULL DEFAULT '',
                transition_type      TEXT    NOT NULL DEFAULT '',
                finding_label        TEXT    NOT NULL DEFAULT '',
                created_at           TEXT    DEFAULT (datetime('now')),
                UNIQUE(source_key_id, target_url, combo_key)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS systemic_impact_report (
                id                       INTEGER PRIMARY KEY AUTOINCREMENT,
                source_endpoint_id       INTEGER NOT NULL UNIQUE,
                source_url               TEXT    NOT NULL,
                candidates_generated     INTEGER NOT NULL DEFAULT 0,
                candidates_probed        INTEGER NOT NULL DEFAULT 0,
                candidates_bypassed      INTEGER NOT NULL DEFAULT 0,
                bypass_rate              REAL    NOT NULL DEFAULT 0.0,
                hvlm_findings            INTEGER NOT NULL DEFAULT 0,
                unique_resources_exposed INTEGER NOT NULL DEFAULT 0,
                total_systemic_exposure  INTEGER NOT NULL DEFAULT 0,
                severity_label           TEXT    NOT NULL DEFAULT '',
                collapse_flag            INTEGER NOT NULL DEFAULT 0,
                created_at               TEXT    DEFAULT (datetime('now'))
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS context_contrast_results (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id     INTEGER NOT NULL,
                profile_key     TEXT    NOT NULL,
                label           TEXT    NOT NULL DEFAULT '',
                method          TEXT    NOT NULL DEFAULT 'GET',
                url             TEXT    NOT NULL DEFAULT '',
                request_headers TEXT    NOT NULL DEFAULT '{}',
                status_code     INTEGER NOT NULL DEFAULT 0,
                response_headers TEXT   NOT NULL DEFAULT '{}',
                body_text       TEXT    NOT NULL DEFAULT '',
                body_length     INTEGER NOT NULL DEFAULT 0,
                response_time_ms REAL   NOT NULL DEFAULT 0.0,
                expected_status INTEGER NOT NULL DEFAULT 0,
                status_match    INTEGER NOT NULL DEFAULT 0,
                executed_at     TEXT    NOT NULL DEFAULT (datetime('now')),
                created_at      TEXT    DEFAULT (datetime('now')),
                UNIQUE(endpoint_id, profile_key)
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print(f"[+] Database initialized at: {os.path.abspath(DB_PATH)}")
