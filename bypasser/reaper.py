"""
Pipeline entry point for The Reaper (403 bypass scanner).

Orchestrates database initialisation, URL ingestion, stability
verification, WAF fingerprinting, body clustering, processing-
depth probing, and a final intelligence report.

Usage
-----
    python -m bypasser.reaper            # default: targets.txt
    python -m bypasser.reaper urls.txt   # custom file
"""

from __future__ import annotations

import json
import logging
import sys
import time

import os
from urllib.parse import urlparse

from tqdm import tqdm  # type: ignore

from bypasser.db import get_connection, init_db  # type: ignore
from bypasser.depth import test_processing_depth  # type: ignore
from bypasser.ingest import ingest_urls  # type: ignore
from bypasser.probing import collapse_variables  # type: ignore
from bypasser.stability import verify_stability, wait_and_see  # type: ignore
from bypasser.transitions import test_combinations, reduce_to_minimal_combinations  # type: ignore
from bypasser.verification import (  # type: ignore
    profile_exposed_content,
    scan_sensitive_patterns,
    check_data_variability,
    classify_data_impact,
    verify_referential_integrity,
)
from bypasser.traversal import (  # type: ignore
    analyze_identifier_structure,
    probe_dataset_boundaries,
    estimate_total_exposure,
)
from bypasser.pagination import probe_pagination_limits  # type: ignore
from bypasser.extraction import (  # type: ignore
    initialize_extraction_job,
    build_extraction_queue,
    traverse_dataset_segments,
    audit_extraction_completeness,
    format_poc_evidence,
)
from bypasser.variables import (  # type: ignore
    enumerate_identity_stubs,
    enumerate_method_sequences,
    enumerate_transport_variables,
    extract_object_ids,
)
from bypasser.expansion import (  # type: ignore
    extract_referential_keys,
    map_related_endpoints,
    probe_lateral_access,
    probe_cross_object_keys,
    calculate_systemic_impact,
)
from bypasser.contrast import (  # type: ignore
    execute_contrast_test,
    generate_logic_diff,
    infer_auth_failure_point,
    format_contrast_proof,
)
from bypasser.stability_temporal import (  # type: ignore
    initialize_stability_check,
    run_persistence_tests,
    verify_without_artifacts,
    audit_response_consistency,
    calculate_survival_index,
)
from bypasser.reporting import (  # type: ignore
    bundle_report_archive,
    calculate_projected_cvss,
    aggregate_final_metrics,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
)
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
#  Main entry point
# ═══════════════════════════════════════════════════════════════════════

def main() -> None:
    """
    Run the full baseline + fingerprinting pipeline.

    ... (rest of docstring maintained conceptually)
    """
    import argparse
    
    parser = argparse.ArgumentParser(description="The Reaper (403 bypass scanner)")
    parser.add_argument("-u", "--url", help="Target URL to scan (mandatory)")
    parser.add_argument("-c", "--cookies", help="Optional session cookies")
    
    args, unknown = parser.parse_known_args()
    
    if not args.url:
        parser.print_help()
        sys.exit(1)
        
    if args.cookies:
        os.environ["REAPER_COOKIES"] = args.cookies

    # Target ingestion expects a file, so we write the provided URL
    filepath = "targets.txt"
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(args.url.strip() + "\n")

    conn = None
    t_start = time.monotonic()
    interrupted = False
    try:
        # ── Section A ──────────────────────────────────────────────
        init_db()
        print("\033[92mTHE REAPER\033[0m")
        print("[*] Database initialised.\n")

        results = ingest_urls(filepath)

        # ── Section A summary ──────────────────────────────────────
        conn = get_connection()
        total = conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0]
        stable = conn.execute(
            "SELECT COUNT(*) FROM endpoints WHERE is_stable = 1"
        ).fetchone()[0]
        unstable_skipped = total - stable

        print(
            f"\n{'=' * 60}\n"
            f"  Section A — Stability Results\n"
            f"{'=' * 60}\n"
            f"  Total Targets:      {total}\n"
            f"  Stable:             {stable}\n"
            f"  Unstable / Skipped: {unstable_skipped}\n"
        )

        # ── Section B ──────────────────────────────────────────────
        #    Only probe stable endpoints that returned a 403.
        stable_403s = conn.execute(
            """
            SELECT url, method, header_hash
              FROM endpoints
             WHERE is_stable = 1 AND status_code = 403
            """
        ).fetchall()

        if stable_403s:
            print(
                f"[*] Section B — Processing-depth probe "
                f"for {len(stable_403s)} stable 403(s)…\n"
            )
            for row in tqdm(
                stable_403s,
                desc="Depth Probing",
                unit="url",
            ):
                test_processing_depth(
                    row["url"],
                    row["header_hash"],
                    row["method"],
                )
        else:
            print("[*] Section B — No stable 403s to probe.\n")

        # ── Fingerprint Intelligence Report ────────────────────────
        _print_intelligence_report(conn)

        # ── Section C ──────────────────────────────────────────────
        #    Populate the policy_variables table with every variable
        #    dimension relevant to the targets we just fingerprinted.
        print(f"[*] Section C — Enumerating policy variables…\n")

        # 1. Transport context:  protocol, UA, referer
        transport = enumerate_transport_variables()

        # 2. Identity stubs:  Bearer, Cookie, custom headers
        identity = enumerate_identity_stubs()

        # 3. Method sequences:  POST→GET, OPTIONS→GET, etc.
        sequences = enumerate_method_sequences()

        # 4. Object IDs:  extract numeric path segments from
        #    every stable-403 URL and create adjacency probes.
        target_urls = [
            row["url"] for row in conn.execute(
                "SELECT url FROM endpoints WHERE is_stable = 1 AND status_code = 403"
            ).fetchall()
        ]
        object_ids = extract_object_ids(target_urls) if target_urls else []

        # ── Section C summary ──────────────────────────────────────
        total_vars = conn.execute(
            "SELECT COUNT(*) FROM policy_variables WHERE is_active = 1"
        ).fetchone()[0]
        dimensions = conn.execute(
            "SELECT COUNT(DISTINCT category) FROM policy_variables WHERE is_active = 1"
        ).fetchone()[0]

        print(
            f"\n{'=' * 60}\n"
            f"  Section C Complete: {total_vars} Variables identified "
            f"across {dimensions} Policy Dimensions.\n"
            f"{'=' * 60}\n"
        )

        # Breakdown by dimension
        dim_rows = conn.execute(
            """
            SELECT category, COUNT(*) AS cnt
              FROM policy_variables
             WHERE is_active = 1
             GROUP BY category
             ORDER BY cnt DESC
            """
        ).fetchall()
        for dr in dim_rows:
            print(f"    {dr['category']:20s}  {dr['cnt']:>3} variable(s)")
        print()

        # ── Section D ──────────────────────────────────────────────
        #    Probe every active variable against each stable-403
        #    endpoint.  The collapsing loop freezes non-responsive
        #    variables and the re-verification gate filters noise.
        # Scope to the current target's host so stale DB rows from
        # previous runs on different domains don't bleed into this scan.
        _parsed = urlparse(args.url)
        _target_netloc = _parsed.netloc
        stable_ep_rows = conn.execute(
            """
            SELECT id, url
              FROM endpoints
             WHERE is_stable = 1 AND status_code = 403
               AND (url LIKE ? OR url LIKE ?)
            """,
            (
                f"http://{_target_netloc}%",
                f"https://{_target_netloc}%",
            ),
        ).fetchall()

        if stable_ep_rows:
            print(
                f"[*] Section D — Probing {total_vars} variables "
                f"across {len(stable_ep_rows)} endpoint(s)…\n"
            )

            all_live: list[dict] = []   # accumulate reproducible diffs

            for ep_row in tqdm(
                stable_ep_rows,
                desc="Variable Probing",
                unit="ep",
            ):
                try:
                    result = collapse_variables(ep_row["id"])
                except Exception as _exc:
                    logger.warning(
                        "[Section D] endpoint_id=%d (%s) failed: %s — skipping.",
                        ep_row["id"], ep_row["url"], _exc,
                    )
                    continue
                # Keep only reproducible (verified) diffs
                for diff in result["live_diffs"]:
                    if diff.get("reproducible"):
                        all_live.append(diff)

            # ── Sensitivity Map ────────────────────────────────────
            _print_sensitivity_map(conn, all_live)
        else:
            print("[*] Section D — No stable 403s to probe.\n")

        # ── Section E ──────────────────────────────────────────────
        #    E1 + E2: generate and test all minimal variable combos.
        #    E5 (validate_content_payload) is called inside E2 for
        #    any combo that returns 200 OK, so no extra call needed.
        #    E4: reduce the verified set to only minimal combos.
        if stable_ep_rows:
            print(
                f"[*] Section E — Combinatorial engine across "
                f"{len(stable_ep_rows)} endpoint(s)…\n"
            )

            all_transitions: list[dict] = []

            for ep_row in tqdm(
                stable_ep_rows,
                desc="Combination Testing",
                unit="ep",
            ):
                ep_transitions = test_combinations(ep_row["id"])
                all_transitions.extend(ep_transitions)

            # E4 — Reduction: keep only minimal combinations.
            minimal_transitions = reduce_to_minimal_combinations(
                all_transitions
            )

            # Print the Candidate Access Report.
            _print_candidate_report(conn, minimal_transitions)
        else:
            print("[*] Section E — No stable 403s to run combinations on.\n")

        # ── Section F ──────────────────────────────────────────────
        #    F1: verify_stability — 3-check schedule + interference
        #        + cache-bust.  Stable → is_verified = 1.
        #    F2: wait_and_see — 5-minute temporal re-run → stability_score.
        #    All outcomes written to stability_logs.
        candidate_rows = conn.execute(
            """
            SELECT ca.id, ca.endpoint_id, ca.combination_id
              FROM candidate_access ca
             WHERE ca.is_verified = 0
             ORDER BY ca.endpoint_id, ca.id
            """
        ).fetchall()

        if candidate_rows:
            print(
                f"[*] Section F — Stability verification "
                f"for {len(candidate_rows)} candidate(s)…\n"
            )

            verified_ids: list[int] = []

            for ca_row in tqdm(
                candidate_rows,
                desc="Stability Checks",
                unit="candidate",
            ):
                candidate_id = ca_row["id"]
                try:
                    result = verify_stability(candidate_id)
                except Exception as exc:
                    logger.warning(
                        "[F] verify_stability error for candidate %d: %s",
                        candidate_id, exc,
                    )
                    _log_stability(
                        conn,
                        candidate_id,
                        ca_row["endpoint_id"],
                        str(ca_row["combination_id"]),
                        "verify_stability",
                        "error",
                        0,
                        {"error": str(exc)},
                    )
                    continue

                outcome = "stable" if result["is_stable"] else "fluke"
                _log_stability(
                    conn,
                    candidate_id,
                    result["endpoint_id"],
                    result["combo_key"],
                    "verify_stability",
                    outcome,
                    0,
                    result,
                )

                if result["is_stable"]:
                    verified_ids.append(candidate_id)

            # F2 — Temporal re-run for candidates that passed F1.
            if verified_ids:
                print(
                    f"\n[*] Section F — Wait-and-See temporal re-run "
                    f"for {len(verified_ids)} stable candidate(s)…\n"
                )
                for candidate_id in tqdm(
                    verified_ids,
                    desc="Wait & See",
                    unit="candidate",
                ):
                    try:
                        ws_result = wait_and_see(candidate_id)
                    except Exception as exc:
                        logger.warning(
                            "[F2] wait_and_see error for candidate %d: %s",
                            candidate_id, exc,
                        )
                        ep_row = conn.execute(
                            "SELECT endpoint_id, combination_id "
                            "  FROM candidate_access WHERE id = ?",
                            (candidate_id,),
                        ).fetchone()
                        _log_stability(
                            conn,
                            candidate_id,  # type: ignore
                            ep_row["endpoint_id"] if ep_row else 0,
                            str(ep_row["combination_id"]) if ep_row else "",
                            "wait_and_see",
                            "error",
                            0,
                            {"error": str(exc)},
                        )
                        continue

                    outcome = (
                        "temporal_pass"
                        if ws_result["status_matched"]
                        else "temporal_fail"
                    )
                    _log_stability(
                        conn,
                        candidate_id,  # type: ignore
                        ws_result["endpoint_id"],
                        ws_result["combo_key"],
                        "wait_and_see",
                        outcome,
                        ws_result["stability_score"],
                        ws_result,
                    )

            _print_verified_access_summary(conn)

            # ── Section G ──────────────────────────────────────────
            #    Data profiling & verification for every endpoint
            #    that has at least one verified bypass.
            verified_ep_ids = [
                row[0] for row in conn.execute(
                    """
                    SELECT DISTINCT endpoint_id
                      FROM candidate_access
                     WHERE is_verified = 1
                    """
                ).fetchall()
            ]

            if verified_ep_ids:
                print(
                    f"[*] Section G — Data profiling & verification "
                    f"for {len(verified_ep_ids)} endpoint(s)…\n"
                )

                for ep_id in tqdm(
                    verified_ep_ids,
                    desc="Data Profiling",
                    unit="ep",
                ):
                    try:
                        profiles    = profile_exposed_content(ep_id)
                        evidence    = scan_sensitive_patterns(ep_id)
                        variability = check_data_variability(ep_id)
                        impact_cls  = classify_data_impact(ep_id)
                        ref_checks  = verify_referential_integrity(ep_id)
                    except Exception as exc:
                        logger.warning(
                            "[G] profiling error for endpoint %d: %s",
                            ep_id, exc,
                        )
                        continue

                    # Compute and persist impact_score per combo_key.
                    _apply_impact_scores(
                        conn, ep_id,  # type: ignore
                        evidence, variability, impact_cls, ref_checks,
                    )

                _print_data_exposure_summary(conn)

                # ── Section H ───────────────────────────────────────
                print("\n[*] Section H — Dataset Reach Analysis...")
                for ep_id in tqdm(
                    verified_ep_ids,
                    desc="Reach Analysis",
                    unit="ep",
                ):
                    try:
                        analyze_identifier_structure(ep_id)
                        probe_dataset_boundaries(ep_id)
                        probe_pagination_limits(ep_id)
                        exposure = estimate_total_exposure(ep_id)
                    except Exception as exc:
                        logger.warning(
                            "[H] reach analysis error for endpoint %d: %s",
                            ep_id, exc,
                        )
                        continue

                    # Persist reach_summary JSON to every verified
                    # combo_key on this endpoint.
                    _persist_reach_summary(conn, ep_id, exposure)  # type: ignore

                _print_dataset_reach_map(conn)

                # ── Section I ───────────────────────────────────────
                print("\n[*] Section I — Controlled Extraction "
                      "& PoC Formatting...")

                section_i_results: list[dict] = []

                for ep_id in tqdm(
                    verified_ep_ids,
                    desc="Extraction",
                    unit="ep",
                ):
                    ep_result = {
                        "endpoint_id":    ep_id,
                        "records":        0,
                        "segments_proven": 0,
                        "segments_total":  0,
                        "logically_complete": False,
                        "poc_file":       "",
                        "error":          None,
                    }

                    try:
                        # I-1: Initialise the extraction job.
                        job = initialize_extraction_job(ep_id)
                        if not job.get("combos"):
                            logger.info(
                                "[I] endpoint %d: no combos — skipped.",
                                ep_id,
                            )
                            section_i_results.append(ep_result)
                            continue

                        # I-2: Build the PoC extraction queue.
                        build_extraction_queue(ep_id)

                        # I-3: Traverse dataset segments for
                        #      cross-segment proof.
                        seg_report = traverse_dataset_segments(ep_id)
                        seg_results = seg_report  # returns list[dict] directly
                        segs_extracted = sum(
                            1 for s in seg_results if s.get("extracted")
                        )
                        ep_result["segments_proven"] = segs_extracted
                        ep_result["segments_total"]  = len(seg_results)

                        # I-4: Count total extracted records.
                        rec_rows = conn.execute(
                            "SELECT count(*) FROM extraction_results "
                            "WHERE endpoint_id = ?",
                            (ep_id,),
                        ).fetchone()
                        ep_result["records"] = (
                            rec_rows[0] if rec_rows else 0
                        )

                        # I-5: Run the Completeness Auditor.
                        audit = audit_extraction_completeness(ep_id)
                        ep_result["logically_complete"] = audit.get(
                            "logically_complete", False,
                        )

                        # I-6: Format PoC evidence (write JSON file).
                        poc = format_poc_evidence(ep_id)
                        ep_result["poc_file"] = poc.get(
                            "evidence_file", "",
                        )

                    except Exception as exc:
                        logger.warning(
                            "[I] extraction error for endpoint %d: %s",
                            ep_id, exc,
                        )
                        ep_result["error"] = str(exc)

                    section_i_results.append(ep_result)

                _print_evidence_acquisition_summary(
                    section_i_results,
                )

                # ── Section J ───────────────────────────────────────
                print("\n[*] Section J — Lateral Movement Mapping...")

                # J1: Mine referential keys from each bypass response.
                for ep_id in tqdm(
                    verified_ep_ids,
                    desc="J1  Key Mining",
                    unit="ep",
                ):
                    try:
                        ref_keys = extract_referential_keys(ep_id)
                        logger.info(
                            "[J] endpoint %d: %d referential keys",
                            ep_id, len(ref_keys),
                        )
                    except Exception as exc:
                        logger.warning(
                            "[J] key mining error for endpoint %d: %s",
                            ep_id, exc,
                        )

                # J2: Map neighbor endpoints from each bypass URL.
                for ep_id in tqdm(
                    verified_ep_ids,
                    desc="J2  Neighbor Mapping",
                    unit="ep",
                ):
                    ep_url_row = conn.execute(
                        "SELECT url FROM endpoints WHERE id = ?",
                        (ep_id,),
                    ).fetchone()
                    if not ep_url_row:
                        continue
                    try:
                        related = map_related_endpoints(ep_url_row["url"])
                        logger.info(
                            "[J] endpoint %d: %d neighbor endpoints mapped",
                            ep_id, len(related),
                        )
                    except Exception as exc:
                        logger.warning(
                            "[J] neighbor mapping error for endpoint %d: %s",
                            ep_id, exc,
                        )

                # J3: Probe lateral access + cross-object keys.
                for ep_id in tqdm(
                    verified_ep_ids,
                    desc="J3  Lateral Probing",
                    unit="ep",
                ):
                    try:
                        lateral = probe_lateral_access(ep_id)
                        logger.info(
                            "[J] endpoint %d: %d lateral findings",
                            ep_id, len(lateral),
                        )
                    except Exception as exc:
                        logger.warning(
                            "[J] lateral error for endpoint %d: %s",
                            ep_id, exc,
                        )
                    try:
                        cross_obj = probe_cross_object_keys(ep_id)
                        logger.info(
                            "[J] endpoint %d: %d cross-object findings",
                            ep_id, len(cross_obj),
                        )
                    except Exception as exc:
                        logger.warning(
                            "[J] cross-object error for endpoint %d: %s",
                            ep_id, exc,
                        )

                # J4: Aggregate systemic impact per source endpoint.
                for ep_id in tqdm(
                    verified_ep_ids,
                    desc="J4  Impact",
                    unit="ep",
                ):
                    try:
                        impact = calculate_systemic_impact(ep_id)
                        logger.info(
                            "[J] endpoint %d: systemic impact (%d records)",
                            ep_id, len(impact),
                        )
                    except Exception as exc:
                        logger.warning(
                            "[J] systemic impact error for endpoint %d: %s",
                            ep_id, exc,
                        )

                _print_systemic_vulnerability_report(conn)  # type: ignore
                print(
                    f"[+] Section J complete — "
                    f"mapped {len(verified_ep_ids)} endpoints.\n"
                )

                # ── Section K ───────────────────────────────────────
                print(
                    "\n[*] Section K — Cross-Context Contrast "
                    "Testing..."
                )

                # K-1: Filter to High Impact findings.
                high_impact_rows = conn.execute(
                    """
                    SELECT DISTINCT endpoint_id
                      FROM candidate_access
                     WHERE is_verified  = 1
                       AND impact_score >= 7
                    """,
                ).fetchall()
                high_impact_ids = [
                    r["endpoint_id"] for r in high_impact_rows
                ]

                if not high_impact_ids:
                    print(
                        "[*] Section K — No high-impact findings "
                        "(impact_score >= 7) to contrast-test.\n"
                    )
                else:
                    print(
                        f"    → {len(high_impact_ids)} high-impact "
                        f"endpoint(s) queued for contrast testing.\n"
                    )

                    section_k_results: list[dict] = []

                    for ep_id in tqdm(
                        high_impact_ids,
                        desc="Contrast",
                        unit="ep",
                    ):
                        k_result: dict = {
                            "endpoint_id": ep_id,
                            "contrast":    None,
                            "diff":        None,
                            "inference":   None,
                            "proof_file":  None,
                            "error":       None,
                        }
                        try:
                            # K-2: Execute contrast test.
                            contrast = execute_contrast_test(
                                ep_id,
                            )
                            k_result["contrast"] = contrast
                            logger.info(
                                "[K] endpoint %d: verdict=%s  "
                                "wall=%.0fms",
                                ep_id,
                                contrast.get("verdict", "?"),
                                contrast.get("wall_clock_ms", 0),
                            )

                            # K-3: Generate logic diff.
                            diff = generate_logic_diff(ep_id)
                            k_result["diff"] = diff
                            logger.info(
                                "[K] endpoint %d: gain=%.1f%%  "
                                "parity=%s",
                                ep_id,
                                diff.get(
                                    "information_gain_pct", 0,
                                ),
                                diff.get(
                                    "privilege_parity", "?",
                                ),
                            )

                            # K-4: Infer auth failure point.
                            inference = (
                                infer_auth_failure_point(ep_id)
                            )
                            k_result["inference"] = inference
                            logger.info(
                                "[K] endpoint %d: class=%s  "
                                "confidence=%s",
                                ep_id,
                                inference.get(
                                    "failure_class", "?",
                                ),
                                inference.get(
                                    "confidence", "?",
                                ),
                            )

                            # K-5: Format proof.
                            proof = format_contrast_proof(
                                ep_id,
                            )
                            k_result["proof_file"] = proof.get(
                                "file_path", "",
                            )

                        except Exception as exc:
                            logger.warning(
                                "[K] contrast error for "
                                "endpoint %d: %s",
                                ep_id, exc,
                            )
                            k_result["error"] = str(exc)

                        section_k_results.append(k_result)

                    # K-6: Print Cross-Context Logic Report.
                    _print_cross_context_report(
                        section_k_results,
                    )

                # ── Section L ───────────────────────────────────────
                print(
                    "\n[*] Section L — Temporal Persistence Sweep..."
                )
                print(
                    "    ⏱  This section re-fires bypasses at "
                    "increasing intervals (1 min → 10 min → 1 hour)"
                    " to measure persistence.\n"
                )

                section_l_results: list[dict] = []

                for ep_id in tqdm(
                    verified_ep_ids,
                    desc="Temporal",
                    unit="ep",
                ):
                    l_result: dict = {
                        "endpoint_id": ep_id,
                        "init":        None,
                        "persistence": None,
                        "cache_check": None,
                        "consistency": None,
                        "survival":    None,
                        "error":       None,
                    }
                    try:
                        # L-1: Capture reference response.
                        init = initialize_stability_check(ep_id)
                        l_result["init"] = init
                        logger.info(
                            "[L] endpoint %d: ref captured "
                            "status=%s  hash=%s",
                            ep_id,
                            init.get("ref_status", "?"),
                            str(
                                init.get(
                                    "ref_structure_hash", "",
                                )
                            )[:12],  # type: ignore
                        )

                        # L-2: Run persistence tests.
                        persistence = run_persistence_tests(
                            ep_id,
                        )
                        l_result["persistence"] = persistence
                        logger.info(
                            "[L] endpoint %d: persistence=%s  "
                            "passed=%d/3",
                            ep_id,
                            persistence.get(
                                "persistence_score", "?",
                            ),
                            persistence.get(
                                "stages_passed", 0,
                            ),
                        )

                        # L-3: Cache-artifact verification.
                        cache_check = verify_without_artifacts(
                            ep_id,
                        )
                        l_result["cache_check"] = cache_check
                        logger.info(
                            "[L] endpoint %d: verdict=%s",
                            ep_id,
                            cache_check.get("verdict", "?"),
                        )

                        # L-4: Response consistency audit.
                        consistency = audit_response_consistency(
                            ep_id,
                        )
                        l_result["consistency"] = consistency
                        logger.info(
                            "[L] endpoint %d: conclusion=%s",
                            ep_id,
                            consistency.get(
                                "conclusion", "?",
                            ).split(" — ")[0],
                        )

                        # L-5: Survival index.
                        survival = calculate_survival_index(
                            ep_id,
                        )
                        l_result["survival"] = survival
                        logger.info(
                            "[L] endpoint %d: score=%.0f  "
                            "rating=%s",
                            ep_id,
                            survival.get(
                                "survival_score", 0,
                            ),
                            survival.get("rating", "?"),
                        )

                    except Exception as exc:
                        logger.warning(
                            "[L] temporal error for "
                            "endpoint %d: %s",
                            ep_id, exc,
                        )
                        l_result["error"] = str(exc)

                    section_l_results.append(l_result)

                # L-6: Print the Temporal Persistence Report.
                _print_temporal_persistence_report(
                    section_l_results,
                )

                # ── Section M ───────────────────────────────────────
                # Finalize: generate reports, ZIP archives, mark
                # endpoints COMPLETED, and print the summary.
                print(
                    "\n[*] Section M — Finalizing reports "
                    f"for {len(verified_ep_ids)} endpoint(s)…\n"
                )
                finalize_pipeline(
                    verified_ep_ids,
                    output_dir="reports",
                )

            else:
                print(
                    "[*] Section G — No verified bypasses to profile.\n"
                )
        else:
            print("[*] Section F — No unverified candidates to verify.\n")

    except KeyboardInterrupt:
        interrupted = True
        print("\n\n[!] Interrupted — shutting down gracefully.")
    except Exception as exc:
        logger.exception("[!] Unhandled error: %s", exc)
    finally:
        elapsed = time.monotonic() - t_start
        try:
            db = conn or get_connection()
            _print_final_dashboard(db, elapsed, interrupted)
            db.close()
        except Exception:
            # If even the dashboard fails, still close cleanly.
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
        logger.info("[*] All connections closed. Exiting.")


# ═══════════════════════════════════════════════════════════════════════
#  Final Dashboard
# ═══════════════════════════════════════════════════════════════════════

def _safe_count(conn, sql: str) -> int:
    """Execute a COUNT query, returning 0 on any error."""
    try:
        row = conn.execute(sql).fetchone()
        return int(row[0]) if row else 0
    except Exception:
        return 0


def _fmt_elapsed(secs: float) -> str:
    """Format seconds into a human-readable duration."""
    m, s = divmod(int(secs), 60)
    h, m = divmod(m, 60)
    if h > 0:
        return f"{h}h {m}m {s}s"
    elif m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


def _print_final_dashboard(
    conn, elapsed: float, interrupted: bool = False,
) -> None:
    """
    Display a clean ASCII dashboard summarising the entire
    A → M pipeline run.  This is the **last thing** the user
    sees before the program exits.
    """
    W = 66   # box width
    H = "═"  # horizontal
    V = "║"  # vertical (unused but for conceptual clarity)
    TL, TR = "╔", "╗"
    BL, BR = "╚", "╝"
    MID_L, MID_R = "╠", "╣"
    DIV = "─"  # thin divider

    def bar(label: str, value, width: int = W) -> str:
        text = f"  {label:<40s}{str(value):>20s}"
        return text

    # ── Query every phase ─────────────────────────────────────────
    # A: Endpoints
    ep_total = _safe_count(
        conn, "SELECT COUNT(*) FROM endpoints",
    )
    ep_stable = _safe_count(
        conn, "SELECT COUNT(*) FROM endpoints WHERE is_stable = 1",
    )

    # B: Sensitivity
    sens_vars = _safe_count(
        conn,
        "SELECT COUNT(DISTINCT variable_id) FROM sensitivity_results "
        "WHERE is_policy_relevant = 1",
    )

    # C/D: Combinations
    combos_tested = _safe_count(
        conn, "SELECT COUNT(*) FROM combination_results",
    )
    combos_bypass = _safe_count(
        conn,
        "SELECT COUNT(*) FROM combination_results "
        "WHERE transition_type != 'None'",
    )

    # E: Candidate access (verified bypasses)
    verified = _safe_count(
        conn,
        "SELECT COUNT(*) FROM candidate_access "
        "WHERE bypassed = 1",
    )

    # F: Stability logs
    stability_checks = _safe_count(
        conn, "SELECT COUNT(*) FROM stability_logs",
    )

    # G: Data classification
    classified = _safe_count(
        conn, "SELECT COUNT(*) FROM data_classification",
    )

    # H: Dataset reach
    total_reach = 0
    try:
        row = conn.execute(
            "SELECT SUM(COALESCE(id_span_confirmed, 0)) "
            "FROM dataset_reach"
        ).fetchone()
        total_reach = int(row[0]) if row and row[0] else 0
    except Exception:
        pass
    pagination_pages = _safe_count(
        conn,
        "SELECT COALESCE(SUM(pagination_rows), 0) "
        "FROM pagination_reach",
    )
    total_records = total_reach + pagination_pages

    # I: Extraction
    extracted = _safe_count(
        conn, "SELECT COUNT(*) FROM extraction_results",
    )
    evidence_items = _safe_count(
        conn, "SELECT COUNT(*) FROM leaked_evidence",
    )

    # J: Lateral
    lateral_eps = _safe_count(
        conn, "SELECT COUNT(*) FROM candidate_endpoints",
    )
    systemic = _safe_count(
        conn, "SELECT COUNT(*) FROM systemic_vulnerabilities",
    )

    # K: Contrast
    contrast_runs = _safe_count(
        conn, "SELECT COUNT(*) FROM context_contrast_results",
    )

    # L: Temporal
    temporal_checks = 0
    try:
        temporal_checks = _safe_count(
            conn, "SELECT COUNT(*) FROM temporal_checks",
        )
    except Exception:
        pass

    # M: Completed
    completed = _safe_count(
        conn,
        "SELECT COUNT(*) FROM endpoints "
        "WHERE pipeline_status = 'COMPLETED'",
    )

    # CVSS severity distribution
    _sev_list: list[str] = []
    try:
        for row in conn.execute(
            "SELECT id FROM endpoints "
            "WHERE pipeline_status = 'COMPLETED'"
        ).fetchall():
            ep_id = row[0]
            m = aggregate_final_metrics(ep_id)
            _sev_list.append(m.get("cvss", {}).get("severity", ""))
    except Exception:
        pass
    crit = _sev_list.count("Critical")
    high = _sev_list.count("High")
    med  = _sev_list.count("Medium")
    low  = _sev_list.count("Low")

    reports_dir = os.path.abspath("reports")

    # ── Render ───────────────────────────────────────────────────
    p = print
    p("")
    p(f"{TL}{H * W}{TR}")
    title = "ARBITER — Pipeline Run Summary"
    status = "INTERRUPTED" if interrupted else "COMPLETE"
    p(f"{V}  {title:<{W - 4}s}{V}")
    p(f"{V}  Status: {status:<{W - 12}s}{V}")
    p(f"{V}  Elapsed: {_fmt_elapsed(elapsed):<{W - 13}s}{V}")
    p(f"{MID_L}{DIV * W}{MID_R}")

    # Phase A
    p(f"{V}  {'[A] Baseline & Fingerprinting':<{W - 4}s}{V}")
    p(f"{V}{bar('Targets ingested', ep_total)}{V}")
    p(f"{V}{bar('Stable endpoints', ep_stable)}{V}")
    p(f"{V}{bar('Unstable / skipped', ep_total - ep_stable)}{V}")
    p(f"{MID_L}{DIV * W}{MID_R}")

    # Phase B/C/D
    p(f"{V}  {'[B] Sensitivity  [C/D] Combinations':<{W - 4}s}{V}")
    p(f"{V}{bar('Policy-relevant variables', sens_vars)}{V}")
    p(f"{V}{bar('Combinations tested', combos_tested)}{V}")
    p(f"{V}{bar('Bypass transitions found', combos_bypass)}{V}")
    p(f"{MID_L}{DIV * W}{MID_R}")

    # Phase E/F
    p(f"{V}  {'[E] Verification  [F] Stability':<{W - 4}s}{V}")
    p(f"{V}{bar('Verified bypasses', verified)}{V}")
    p(f"{V}{bar('Stability probes', stability_checks)}{V}")
    p(f"{MID_L}{DIV * W}{MID_R}")

    # Phase G/H/I
    p(f"{V}  {'[G] Classification  [H] Scale  [I] Evidence':<{W - 4}s}{V}")
    p(f"{V}{bar('Data classifications', classified)}{V}")
    p(f"{V}{bar('Reachable records', f'{total_records:,}')}{V}")
    p(f"{V}{bar('Extracted records', extracted)}{V}")
    p(f"{V}{bar('Sensitive evidence items', evidence_items)}{V}")
    p(f"{MID_L}{DIV * W}{MID_R}")

    # Phase J/K/L
    p(f"{V}  {'[J] Lateral  [K] Contrast  [L] Temporal':<{W - 4}s}{V}")
    p(f"{V}{bar('Candidate endpoints tested', lateral_eps)}{V}")
    p(f"{V}{bar('Systemic vulns confirmed', systemic)}{V}")
    p(f"{V}{bar('Contrast test runs', contrast_runs)}{V}")
    p(f"{V}{bar('Temporal persistence checks', temporal_checks)}{V}")
    p(f"{MID_L}{DIV * W}{MID_R}")

    # Phase M — Severity
    p(f"{V}  {'[M] Final Severity Distribution':<{W - 4}s}{V}")
    p(f"{V}{bar('🟣 Critical', crit)}{V}")
    p(f"{V}{bar('🔴 High', high)}{V}")
    p(f"{V}{bar('🟠 Medium', med)}{V}")
    p(f"{V}{bar('🟡 Low', low)}{V}")
    p(f"{V}{bar('Endpoints COMPLETED', completed)}{V}")
    p(f"{MID_L}{DIV * W}{MID_R}")

    # Output
    p(f"{V}  {'Reports':<{W - 4}s}{V}")
    p(f"{V}{bar('Output directory', reports_dir)}{V}")
    # List zip files if they exist.
    try:
        zips = sorted(
            f for f in os.listdir(reports_dir)
            if f.endswith(".zip")
        )
        for zf in zips:
            p(f"{V}    📦 {zf:<{W - 8}s}{V}")
    except Exception:
        pass
    p(f"{BL}{H * W}{BR}")

    # Final one-liner
    vuln_total = crit + high + med + low
    if crit > 0:
        p(
            f"\n  ⚠️  {crit} Critical vulnerabilit"
            f"{'ies' if crit != 1 else 'y'} found.  "
            f"Reports saved to {reports_dir}/"
        )
    elif vuln_total > 0:
        p(
            f"\n  {vuln_total} vulnerabilit"
            f"{'ies' if vuln_total != 1 else 'y'} found.  "
            f"Reports saved to {reports_dir}/"
        )
    else:
        p("\n  Pipeline complete. No verified vulnerabilities.")
    p("")


# ═══════════════════════════════════════════════════════════════════════
#  Finalize
# ═══════════════════════════════════════════════════════════════════════

def finalize_pipeline(
    verified_ep_ids: list[int],
    output_dir: str = "reports",
) -> None:
    """
    Final stage of the pipeline.  For each verified endpoint:

    1. Generate the Markdown report + ZIP archive.
    2. Compute the CVSS score.
    3. Mark the endpoint ``COMPLETED`` in the database.
    4. Print a colour-coded summary to the console.

    The ZIP archive is named
    ``Arbiter_Report_<host>_<date>.zip`` and contains the
    Markdown report, poc_evidence JSON(s), stability logs,
    and full aggregate metrics.
    """
    from datetime import datetime, timezone

    conn   = get_connection()
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    archives: list[str] = []

    # Ensure the endpoints table has a pipeline_status column.
    _ensure_status_column(conn)

    for ep_id in verified_ep_ids:
        try:
            # Generate the full archive (Markdown + evidence + logs).
            zip_path = bundle_report_archive(
                ep_id, output_dir=output_dir,
            )
            archives.append(zip_path)

            # Retrieve CVSS severity (already computed inside the
            # archive generation).
            metrics = aggregate_final_metrics(ep_id)
            sev     = metrics.get("cvss", {}).get("severity", "Medium")
            if sev in counts:
                counts[sev] += 1

            # Mark endpoint COMPLETED.
            completed_at = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "UPDATE endpoints "
                "SET pipeline_status = 'COMPLETED', "
                "    completed_at = ? "
                "WHERE id = ?",
                (completed_at, ep_id),
            )
            conn.commit()
            logger.info(
                "[M] endpoint %d → COMPLETED  severity=%s",
                ep_id, sev,
            )

        except Exception as exc:
            logger.warning(
                "[M] finalize error for endpoint %d: %s",
                ep_id, exc,
            )

    conn.close()

    # ── Console summary ──────────────────────────────────────────────
    total    = sum(counts.values())
    abs_dir  = os.path.abspath(output_dir)
    crit     = counts["Critical"]
    high     = counts["High"]
    med      = counts["Medium"]
    low      = counts["Low"]

    w = 60
    print(f"\n{'═' * w}")
    print("  PIPELINE COMPLETE — Final Summary")
    print(f"{'═' * w}")
    print(f"  Total verified vulnerabilities: {total}")
    print(f"    🟣 Critical : {crit}")
    print(f"    🔴 High     : {high}")
    print(f"    🟠 Medium   : {med}")
    print(f"    🟡 Low      : {low}")
    print(f"")
    print(f"  Reports saved to: {abs_dir}/")
    for arc in archives:
        print(f"    📦 {os.path.basename(arc)}")
    print(f"{'═' * w}\n")

    if crit > 0:
        print(
            f"  ⚠️  {crit} Critical vulnerabilit"
            f"{'ies' if crit != 1 else 'y'} found.  "
            f"Reports saved to {abs_dir}/"
        )
    elif total > 0:
        print(
            f"  {total} vulnerabilit"
            f"{'ies' if total != 1 else 'y'} found.  "
            f"Reports saved to {abs_dir}/"
        )
    else:
        print("  No vulnerabilities to report.")
    print()


def _ensure_status_column(conn) -> None:
    """
    Add ``pipeline_status`` and ``completed_at`` columns to the
    ``endpoints`` table if they don't already exist.
    """
    try:
        cols = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(endpoints)"
            ).fetchall()
        }
        if "pipeline_status" not in cols:
            conn.execute(
                "ALTER TABLE endpoints "
                "ADD COLUMN pipeline_status TEXT "
                "NOT NULL DEFAULT 'PENDING'"
            )
        if "completed_at" not in cols:
            conn.execute(
                "ALTER TABLE endpoints "
                "ADD COLUMN completed_at TEXT"
            )
        conn.commit()
    except Exception as exc:
        logger.warning(
            "[M] could not add status columns: %s", exc,
        )


# ═══════════════════════════════════════════════════════════════════════
#  Report
# ═══════════════════════════════════════════════════════════════════════

def _print_intelligence_report(conn) -> None:
    """
    Query the database and print a grouped summary of all WAF
    fingerprint intelligence gathered during the run.
    """
    rows = conn.execute(
        """
        SELECT waf_type,
               COUNT(*)                          AS endpoint_count,
               GROUP_CONCAT(DISTINCT fingerprint_group_id) AS group_ids,
               GROUP_CONCAT(DISTINCT denial_layer)         AS layers,
               GROUP_CONCAT(DISTINCT processing_depth)     AS depths
          FROM endpoints
         WHERE is_stable = 1
         GROUP BY waf_type
         ORDER BY endpoint_count DESC
        """
    ).fetchall()

    if not rows:
        print("[*] No stable endpoints to report on.")
        return

    # Column widths
    col_waf   = 18
    col_cnt   = 6
    col_group = 36
    col_layer = 20
    col_depth = 20
    total_w   = col_waf + col_cnt + col_group + col_layer + col_depth + 12

    hdr = (
        f"  {'WAF / Infra':<{col_waf}}"
        f"  {'#':>{col_cnt}}"
        f"  {'Group IDs':<{col_group}}"
        f"  {'Denial Layer':<{col_layer}}"
        f"  {'Origin Reachable?':<{col_depth}}"
    )

    print(f"\n{'=' * total_w}")
    print("  Fingerprint Intelligence Report")
    print(f"{'=' * total_w}")
    print(hdr)
    print(f"  {'-' * (total_w - 2)}")

    for r in rows:
        waf       = r["waf_type"] or "Unknown"
        count     = r["endpoint_count"]
        groups    = _truncate(r["group_ids"] or "—", col_group)
        layer     = r["layers"] or "—"
        depth_raw = r["depths"] or "—"

        # Translate processing_depth into a readable flag.
        if "Level 2: Origin" in depth_raw:
            reachable = "Yes"
        elif "Level 1: Edge" in depth_raw:
            reachable = "No"
        else:
            reachable = "—"

        print(
            f"  {waf:<{col_waf}}"
            f"  {count:>{col_cnt}}"
            f"  {groups:<{col_group}}"
            f"  {layer:<{col_layer}}"
            f"  {reachable:<{col_depth}}"
        )

    print(f"{'=' * total_w}\n")


def _truncate(text: str, max_len: int) -> str:
    """Shorten *text* with an ellipsis if it exceeds *max_len*."""
    return text if len(text) <= max_len else text[: max_len - 1] + "…"  # type: ignore


def _print_sensitivity_map(conn, live_diffs: list[dict]) -> None:
    """
    Print a formatted Sensitivity Map showing only the **reproducible**
    variables and their observed impact.

    This is the shortlist that will drive Section E (combination phase).
    """
    col_var  = 30
    col_imp  = 44
    total_w  = col_var + col_imp + 8

    if not live_diffs:
        print(
            f"\n{'=' * total_w}\n"
            f"  Section D — Sensitivity Map\n"
            f"{'=' * total_w}\n"
            f"  No reproducible variable effects detected.\n"
            f"  All observed changes were filtered as transient noise.\n"
            f"{'=' * total_w}\n"
        )
        return

    # De-duplicate by (endpoint_id, variable_id).
    seen: set[tuple[int, int]] = set()
    unique: list[dict] = []
    for d in live_diffs:
        key = (d["endpoint_id"], d["variable_id"])
        if key not in seen:
            seen.add(key)
            unique.append(d)

    # Look up endpoint URLs for display.
    ep_urls: dict[int, str] = {}
    for d in unique:
        eid = d["endpoint_id"]
        if eid not in ep_urls:
            row = conn.execute(
                "SELECT url FROM endpoints WHERE id = ?", (eid,),
            ).fetchone()
            ep_urls[eid] = row["url"] if row else f"endpoint#{eid}"

    # ── Header ─────────────────────────────────────────────────────
    print(f"\n{'=' * total_w}")
    print("  Section D — Sensitivity Map  (reproducible only)")
    print(f"{'=' * total_w}")

    # Group by endpoint
    from collections import defaultdict
    by_ep: dict[int, list[dict]] = defaultdict(list)  # type: ignore
    for d in unique:
        by_ep[d["endpoint_id"]].append(d)

    for eid, diffs in by_ep.items():
        url = _truncate(ep_urls[eid], total_w - 4)
        print(f"\n  ▸ {url}")
        print(f"  {'─' * (total_w - 2)}")
        print(f"  {'Variable':<{col_var}}  {'Impact':<{col_imp}}")
        print(f"  {'─' * (total_w - 2)}")

        for d in diffs:
            name = _truncate(d["variable_name"], col_var)
            impact = _describe_impact(d)
            print(f"  {name:<{col_var}}  {impact}")

    # ── Footer ─────────────────────────────────────────────────────
    total_endpoints = len(by_ep)
    total_live = len(unique)
    print(f"\n  {total_live} reproducible variable(s) across "
          f"{total_endpoints} endpoint(s).")
    print(f"  → This shortlist will feed into Section E "
          f"(combination engine).")
    print(f"{'=' * total_w}\n")


def _log_stability(
    conn,
    candidate_id: int,
    endpoint_id: int,
    combo_key: str,
    phase: str,
    outcome: str,
    stability_score: int,
    detail,
) -> None:
    """
    Append one row to ``stability_logs`` recording the outcome of a
    single Phase-F check (``verify_stability`` or ``wait_and_see``).

    Parameters
    ----------
    conn         : active SQLite connection (WAL mode).
    candidate_id : ``candidate_access.id``.
    endpoint_id  : ``endpoints.id``.
    combo_key    : human-readable combination label.
    phase        : ``'verify_stability'`` or ``'wait_and_see'``.
    outcome      : ``'stable'``, ``'fluke'``, ``'temporal_pass'``,
                   ``'temporal_fail'``, or ``'error'``.
    stability_score : 0 for verify_stability rows; 1–5 for wait_and_see.
    detail       : dict or str — JSON-serialised and stored verbatim.
    """
    detail_str = (
        json.dumps(detail, default=str)
        if not isinstance(detail, str)
        else detail
    )
    try:
        conn.execute(
            """
            INSERT INTO stability_logs
                (candidate_id, endpoint_id, combo_key,
                 phase, outcome, stability_score, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                candidate_id,
                endpoint_id,
                str(combo_key),
                phase,
                outcome,
                stability_score,
                detail_str,
            ),
        )
        conn.commit()
    except Exception as exc:
        logger.warning("[F] stability_logs write failed: %s", exc)


def _print_candidate_report(conn, transitions: list[dict]) -> None:
    """
    Print the **Candidate Access Report** for Section E.

    Displays a table of every minimal combination that produced a
    verified transition, showing the target endpoint URL, the variable
    combination that triggered it, the transition type, and the new
    HTTP status code.

    All candidates have already been written to ``candidate_access``
    with ``is_verified = 0`` by :func:`transitions._log_candidate`
    during E2 execution; this function only formats and prints them.
    """
    col_url   = 40
    col_combo = 36
    col_type  = 10
    col_stat  =  7
    total_w   = col_url + col_combo + col_type + col_stat + 12

    print(f"\n{'=' * total_w}")
    print("  Section E — Candidate Access Report")
    print(f"{'=' * total_w}")

    if not transitions:
        print("  No candidate bypasses found.")
        print(f"  All tested combinations remained at 403 or were")
        print(f"  discarded as false positives by the content validator.")
        print(f"{'=' * total_w}\n")
        return

    # Resolve endpoint URLs once.
    ep_urls: dict[int, str] = {}
    for t in transitions:
        eid = t["endpoint_id"]
        if eid not in ep_urls:
            row = conn.execute(
                "SELECT url FROM endpoints WHERE id = ?", (eid,),
            ).fetchone()
            ep_urls[eid] = row["url"] if row else f"endpoint#{eid}"

    # Table header
    print(
        f"  {'Endpoint':<{col_url}}"
        f"  {'Combination':<{col_combo}}"
        f"  {'Type':<{col_type}}"
        f"  {'Status':>{col_stat}}"
    )
    print(f"  {'-' * (total_w - 2)}")

    for t in transitions:
        url   = _truncate(ep_urls[t["endpoint_id"]], col_url)
        combo = _truncate(t["combo_key"], col_combo)
        ttype = t["transition_type"]
        stat  = str(t["combo_status"])

        print(
            f"  {url:<{col_url}}"
            f"  {combo:<{col_combo}}"
            f"  {ttype:<{col_type}}"
            f"  {stat:>{col_stat}}"
        )

    print(
        f"\n  {len(transitions)} minimal candidate bypass(es) identified."
    )
    print(
        f"  All candidates saved to candidate_access "
        f"with is_verified = 0."
    )
    print(f"  → Awaiting Phase F confirmation.")
    print(f"{'=' * total_w}\n")


def _print_verified_access_summary(conn) -> None:
    """
    Print the **Verified Access Summary** for Section F.

    Only rows with ``is_verified = 1`` are displayed — these are
    bypasses that survived the three-check stability schedule, the
    interference check, the cache-bust check, and the temporal
    Wait-and-See re-run.

    Each row shows the target endpoint, the minimal combination that
    triggered the bypass, the transition type, the confirmed HTTP status
    code, and the ``stability_score`` (1–5) assigned by
    :func:`stability.wait_and_see`.
    """
    rows = conn.execute(
        """
        SELECT ca.id,
               ca.combination_id,
               ca.transition_type,
               ca.new_status,
               ca.stability_score,
               ep.url,
               ep.waf_type
          FROM candidate_access ca
          JOIN endpoints ep ON ep.id = ca.endpoint_id
         WHERE ca.is_verified = 1
         ORDER BY ca.stability_score DESC, ep.url
        """
    ).fetchall()

    col_url   = 38
    col_combo = 32
    col_type  = 10
    col_stat  =  7
    col_score =  7
    total_w   = col_url + col_combo + col_type + col_stat + col_score + 14

    print(f"\n{'=' * total_w}")
    print("  Section F — Verified Access Summary")
    print(f"{'=' * total_w}")

    if not rows:
        print("  No confirmed bypasses — all candidates were flukes or")
        print("  failed temporal re-validation.")
        print(f"{'=' * total_w}\n")
        return

    print(
        f"  {'Endpoint':<{col_url}}"
        f"  {'Combination':<{col_combo}}"
        f"  {'Type':<{col_type}}"
        f"  {'Status':>{col_stat}}"
        f"  {'Score':>{col_score}}"
    )
    print(f"  {'-' * (total_w - 2)}")

    for r in rows:
        try:
            combo = json.loads(r["combination_id"])
            combo_key = combo.get("combo_key", str(r["combination_id"]))
        except Exception:
            combo_key = str(r["combination_id"])

        url     = _truncate(r["url"], col_url)
        combo_d = _truncate(combo_key, col_combo)
        ttype   = r["transition_type"]
        stat    = str(r["new_status"])
        score   = str(r["stability_score"])

        print(
            f"  {url:<{col_url}}"
            f"  {combo_d:<{col_combo}}"
            f"  {ttype:<{col_type}}"
            f"  {stat:>{col_stat}}"
            f"  {score:>{col_score}}"
        )

    print(f"\n  {len(rows)} confirmed bypass(es).")
    print(
        f"  Score: 1=Failed re-run  2=Length drift  "
        f"3=Context unknown  4=Context-specific  5=Cache-bust survived"
    )
    print(f"{'=' * total_w}\n")


def _describe_impact(diff: dict) -> str:
    """Build a human-readable impact string from a diff object."""
    parts: list[str] = []

    if diff.get("status_changed"):
        parts.append(
            f"Changed Status {diff['baseline_status']}"
            f"→{diff['mutated_status']}"
        )

    if diff.get("length_changed"):
        delta = diff["length_delta"]
        sign = "+" if delta >= 0 else ""
        parts.append(f"Affected Body Length ({sign}{delta} bytes)")

    if diff.get("headers_changed"):
        parts.append("Changed Headers")

    if diff.get("structure_changed"):
        pct = diff.get("structure_pct", 0) * 100
        parts.append(f"Structural Shift ({pct:.1f}%)")

    return " | ".join(parts) if parts else "Change detected"


def _apply_impact_scores(
    conn,
    endpoint_id: int,
    evidence: list[dict],
    variability: list[dict],
    impact_cls: list[dict],
    ref_checks: list[dict],
) -> None:
    """
    Compute a composite **impact_score** (1–10) for each combo_key on
    *endpoint_id* and write it to ``candidate_access.impact_score``.

    Scoring factors
    ---------------
    * Sensitivity categories (×2 each, max 4 categories = 8)
    * Production-data classification (+2 for High Impact)
    * Variability (+1 High, +0.5 Medium)
    * Referential integrity (+1 Systemic)

    Raw total is clamped to [1, 10].
    """
    # Index helpers keyed by combo_key.
    cats_by_combo: dict[str, set[str]] = {}
    for e in evidence:
        cats_by_combo.setdefault(e["combo_key"], set()).add(e["category"])

    cls_by_combo = {c["combo_key"]: c["impact_label"] for c in impact_cls}
    var_by_combo = {v["combo_key"]: v["classification"] for v in variability}

    systemic_combos: set[str] = set()
    for r in ref_checks:
        if r.get("exposure_class") == "Systemic":
            systemic_combos.add(r["combo_key"])

    # Gather all combo_keys for this endpoint.
    all_keys = (
        set(cats_by_combo)
        | set(cls_by_combo)
        | set(var_by_combo)
        | systemic_combos
    )

    for combo_key in all_keys:
        raw = 0.0

        # Sensitivity: 2 per distinct category.
        raw += 2 * len(cats_by_combo.get(combo_key, set()))

        # Production classification.
        if cls_by_combo.get(combo_key) == "High Impact":
            raw += 2

        # Variability.
        vclass = var_by_combo.get(combo_key, "")
        if vclass == "High":
            raw += 1
        elif vclass == "Medium":
            raw += 0.5

        # Referential integrity.
        if combo_key in systemic_combos:
            raw += 1

        score = max(1, min(10, int(raw)))

        try:
            conn.execute(
                """
                UPDATE candidate_access
                   SET impact_score = ?
                 WHERE endpoint_id = ?
                   AND is_verified = 1
                   AND combination_id LIKE ?
                """,
                (score, endpoint_id, f"%{combo_key}%"),
            )
            conn.commit()
        except Exception as exc:
            logger.warning(
                "[G] impact_score write failed for %s: %s",
                combo_key, exc,
            )


def _print_data_exposure_summary(conn) -> None:
    """
    Print the **Real Data Exposure Summary** for Section G.

    For every verified bypass, shows the types of data leaked,
    impact classification, and the composite impact_score.
    """
    rows = conn.execute(
        """
        SELECT ca.endpoint_id,
               ca.combination_id,
               ca.transition_type,
               ca.new_status,
               ca.stability_score,
               ca.impact_score,
               ep.url
          FROM candidate_access ca
          JOIN endpoints ep ON ep.id = ca.endpoint_id
         WHERE ca.is_verified = 1
           AND ca.impact_score > 0
         ORDER BY ca.impact_score DESC, ep.url
        """
    ).fetchall()

    col_url   = 36
    col_combo = 28
    col_data  = 30
    col_class = 14
    col_score =  7
    total_w   = col_url + col_combo + col_data + col_class + col_score + 14

    print(f"\n{'=' * total_w}")
    print("  Section G — Real Data Exposure Summary")
    print(f"{'=' * total_w}")

    if not rows:
        print("  No data exposure detected for verified bypasses.")
        print(f"{'=' * total_w}\n")
        return

    print(
        f"  {'Endpoint':<{col_url}}"
        f"  {'Combination':<{col_combo}}"
        f"  {'Data Leaked':<{col_data}}"
        f"  {'Impact':<{col_class}}"
        f"  {'Score':>{col_score}}"
    )
    print(f"  {'-' * (total_w - 2)}")

    for r in rows:
        try:
            combo = json.loads(r["combination_id"])
            combo_key = combo.get("combo_key", str(r["combination_id"]))
        except Exception:
            combo_key = str(r["combination_id"])

        endpoint_id = r["endpoint_id"]

        # Gather leaked data categories from leaked_evidence.
        ev_rows = conn.execute(
            "SELECT DISTINCT category FROM leaked_evidence "
            "WHERE endpoint_id = ? AND combo_key = ?",
            (endpoint_id, combo_key),
        ).fetchall()
        categories = [er["category"] for er in ev_rows]
        data_str = ", ".join(categories) if categories else "—"

        # Impact classification from data_classification.
        dc_row = conn.execute(
            "SELECT impact_label FROM data_classification "
            "WHERE endpoint_id = ? AND combo_key = ?",
            (endpoint_id, combo_key),
        ).fetchone()
        impact_label = dc_row["impact_label"] if dc_row else "—"

        url     = _truncate(r["url"], col_url)
        combo_d = _truncate(combo_key, col_combo)
        data_d  = _truncate(data_str, col_data)
        score   = str(r["impact_score"])

        print(
            f"  {url:<{col_url}}"
            f"  {combo_d:<{col_combo}}"
            f"  {data_d:<{col_data}}"
            f"  {impact_label:<{col_class}}"
            f"  {score:>{col_score}}"
        )

    print(f"\n  {len(rows)} bypass(es) with data exposure.")
    print(
        f"  Score: 1–3=Low risk  4–6=Moderate  "
        f"7–10=Critical (real production data exposed)"
    )
    print(f"{'=' * total_w}\n")


# ═══════════════════════════════════════════════════════════════════════
#  Section H helpers — Dataset Reach
# ═══════════════════════════════════════════════════════════════════════

def _persist_reach_summary(conn, endpoint_id: int, exposure: dict) -> None:
    """
    Write the JSON-encoded exposure estimation into
    ``candidate_access.reach_summary`` for every verified combo_key
    on *endpoint_id*.
    """
    summary_json = json.dumps(exposure, default=str)
    conn.execute(
        """
        UPDATE candidate_access
           SET reach_summary = ?
         WHERE endpoint_id = ?
           AND is_verified  = 1
        """,
        (summary_json, endpoint_id),
    )
    conn.commit()


def _print_dataset_reach_map(conn) -> None:
    """
    Print the **Dataset Reach Map** — for every verified bypass, show
    the projected reach, confidence tier, and evidence summary.
    """
    rows = conn.execute(
        """
        SELECT ca.endpoint_id,
               e.url,
               ca.combo_key,
               ca.impact_score,
               ca.reach_summary
          FROM candidate_access ca
          JOIN endpoints e ON e.id = ca.endpoint_id
         WHERE ca.is_verified = 1
           AND ca.reach_summary != '{}'
         ORDER BY ca.endpoint_id
        """
    ).fetchall()

    if not rows:
        print("[*] Section H — No reach data available.\n")
        return

    col_url   = 40
    col_combo = 32
    col_reach = 14
    col_conf  = 12
    col_evid  = 50
    total_w   = col_url + col_combo + col_reach + col_conf + col_evid + 14

    hdr = (
        f"  {'URL':<{col_url}}"
        f"  {'Bypass Combo':<{col_combo}}"
        f"  {'Reach':>{col_reach}}"
        f"  {'Confidence':<{col_conf}}"
        f"  {'Evidence':<{col_evid}}"
    )

    print(f"\n{'=' * total_w}")
    print("  Dataset Reach Map — Systemic Exposure Proof")
    print(f"{'=' * total_w}")
    print(hdr)
    print(f"  {'-' * (total_w - 2)}")

    # Pre-compute aggregates (avoids augmented-assignment type errors).
    _exposures: list[dict] = []
    for _r in rows:
        try:
            _e: dict = (
                json.loads(_r["reach_summary"])
                if isinstance(_r["reach_summary"], str)
                else {}
            )
        except (json.JSONDecodeError, TypeError):
            _e = {}
        _exposures.append(_e)
    total_reach = sum(
        e.get("projected_reach", 0)
        for e in _exposures
        if isinstance(e.get("projected_reach", 0), int)
    )
    high_count = sum(1 for e in _exposures if e.get("confidence") == "High")

    for r in rows:
        raw = r["reach_summary"]
        try:
            exposure = json.loads(raw) if isinstance(raw, str) else {}
        except (json.JSONDecodeError, TypeError):
            exposure = {}

        reach_fmt  = exposure.get("reach_formatted", "Unknown")
        confidence = exposure.get("confidence", "—")
        evidence   = exposure.get("evidence_summary", "—")
        projected  = exposure.get("projected_reach", 0)

        url_d   = _truncate(r["url"], col_url)
        combo_d = _truncate(r["combo_key"], col_combo)
        evid_d  = _truncate(evidence, col_evid)

        print(
            f"  {url_d:<{col_url}}"
            f"  {combo_d:<{col_combo}}"
            f"  {reach_fmt:>{col_reach}}"
            f"  {confidence:<{col_conf}}"
            f"  {evid_d:<{col_evid}}"
        )

    print(f"\n  {len(rows)} endpoint(s) with reach data.")
    print(f"  Total Projected Reach: ~{total_reach:,} reachable records")
    if high_count:
        print(
            f"  {high_count} bypass(es) with HIGH confidence — "
            f"systemic authorisation failure confirmed."
        )
    print(
        f"\n  → This proves the bypass is a systemic failure, "
        f"not a localised fluke."
    )
    print(f"{'=' * total_w}\n")


# ═══════════════════════════════════════════════════════════════════════
#  Section I helpers — Evidence Acquisition Summary
# ═══════════════════════════════════════════════════════════════════════

def _print_evidence_acquisition_summary(
    results: list[dict],
) -> None:
    """
    Print the **Evidence Acquisition Summary** for Section I.

    For each endpoint, displays:
    - Records Extracted
    - Segments Proven  (extracted / total)
    - Schema Status    (Logically Complete | Incomplete)
    - PoC File Path
    """
    if not results:
        print("\n[*] No Section I results to report.\n")
        return

    col_ep     = 12
    col_recs   = 10
    col_segs   = 18
    col_schema = 22
    col_poc    = 40
    total_w    = col_ep + col_recs + col_segs + col_schema + col_poc + 4

    print(f"\n{'=' * total_w}")
    print("  EVIDENCE ACQUISITION SUMMARY  (Section I)")
    print(f"{'=' * total_w}")

    header = (
        f"  {'Endpoint':<{col_ep}}"
        f"{'Records':<{col_recs}}"
        f"{'Segments Proven':<{col_segs}}"
        f"{'Schema Status':<{col_schema}}"
        f"{'PoC File':<{col_poc}}"
    )
    print(header)
    print(f"  {'-' * (total_w - 2)}")

    total_records  = sum(r["records"] for r in results)
    total_seg_ok   = sum(r["segments_proven"] for r in results)
    total_seg_all  = sum(r["segments_total"] for r in results)
    complete_count = sum(1 for r in results if r.get("logically_complete"))
    errors         = sum(1 for r in results if r.get("error"))
    poc_files: list[str] = [r["poc_file"] for r in results if r.get("poc_file")]

    for r in results:
        ep_id    = r["endpoint_id"]
        recs     = r["records"]
        seg_ok   = r["segments_proven"]
        seg_all  = r["segments_total"]
        complete = r["logically_complete"]
        poc_file = r["poc_file"]
        error    = r.get("error")

        schema_str = (
            "✓ Logically Complete" if complete
            else "✗ Incomplete"
        )
        seg_str = f"{seg_ok}/{seg_all}" if seg_all else "—"

        # Truncate PoC path for display.
        poc_display = poc_file if poc_file else "—"
        if len(poc_display) > col_poc - 2:
            poc_display = "…" + poc_display[-(col_poc - 3):]

        row = (
            f"  {ep_id:<{col_ep}}"
            f"{recs:<{col_recs}}"
            f"{seg_str:<{col_segs}}"
            f"{schema_str:<{col_schema}}"
            f"{poc_display}"
        )
        print(row)

        if error:
            print(f"    ⚠ ERROR: {error}")

    print(f"  {'-' * (total_w - 2)}")

    # Totals.
    print(f"\n  Records Extracted  : {total_records}")
    print(f"  Segments Proven    : {total_seg_ok}/{total_seg_all}")
    print(f"  Schema Complete    : {complete_count}/{len(results)} endpoint(s)")
    if errors:
        print(f"  Errors             : {errors}")

    if poc_files:
        print(f"\n  PoC Evidence Files:")
        for pf in poc_files:
            print(f"    → {pf}")
    else:
        print("\n  No PoC evidence files generated.")

    # Overall verdict.
    if total_records > 0 and total_seg_ok > 0 and complete_count > 0:
        print(
            f"\n  ✓ PROOF OF IMPACT ESTABLISHED"
            f" — {total_records} record(s) extracted across "
            f"{total_seg_ok} segment(s), schema-verified."
        )
    elif total_records > 0:
        print(
            f"\n  ◐ PARTIAL PROOF — {total_records} record(s) extracted "
            f"but schema or segment coverage is incomplete."
        )
    else:
        print(
            "\n  ✗ NO DATA EXTRACTED — extraction was unsuccessful. "
            "Check logs for details."
        )

    print(f"{'=' * total_w}\n")

# ═══════════════════════════════════════════════════════════════════════
#  Section K helpers — Cross-Context Logic Report
# ═══════════════════════════════════════════════════════════════════════

def _print_cross_context_report(
    results: list[dict],
) -> None:
    """
    Print the **Cross-Context Logic Report** for Section K.

    For each high-impact finding that was contrast-tested, displays:
    - Endpoint ID
    - Contrast Verdict (BYPASS_CONFIRMED, FULL_EQUIVALENCE, etc.)
    - Information Gain %
    - Privilege Parity level
    - Failure Classification (Edge vs Origin / Incomplete / Trust)
    - Confidence level
    - Proof file path
    """
    # Column widths.
    c_ep      = 8
    c_verdict = 20
    c_gain    = 10
    c_parity  = 24
    c_class   = 22
    c_conf    = 10
    c_proof   = 30
    total_w   = c_ep + c_verdict + c_gain + c_parity + c_class + c_conf + c_proof + 22

    print(f"\n{'=' * total_w}")
    print("  Section K — Cross-Context Logic Report")
    print(f"{'=' * total_w}")
    print(
        f"  {'EP':>{c_ep}}"
        f"  {'Verdict':<{c_verdict}}"
        f"  {'Gain %':>{c_gain}}"
        f"  {'Parity':<{c_parity}}"
        f"  {'Failure Class':<{c_class}}"
        f"  {'Conf.':<{c_conf}}"
        f"  {'Proof File':<{c_proof}}"
    )
    print(f"  {'-' * (total_w - 4)}")

    errored_count   = sum(1 for r in results if r.get("error"))
    confirmed_count = sum(
        1 for r in results
        if not r.get("error")
        and (r.get("contrast") or {}).get("verdict", "") in (
            "BYPASS_CONFIRMED", "FULL_EQUIVALENCE"
        )
    )
    parity_count = sum(
        1 for r in results
        if not r.get("error")
        and "Parity" in str((r.get("diff") or {}).get("privilege_parity", ""))
    )

    for r in results:
        ep_id = r.get("endpoint_id", 0)

        if r.get("error"):
            print(
                f"  {ep_id:>{c_ep}}"
                f"  {'ERROR':<{c_verdict}}"
                f"  {'—':>{c_gain}}"
                f"  {'—':<{c_parity}}"
                f"  {'—':<{c_class}}"
                f"  {'—':<{c_conf}}"
                f"  {_truncate(str(r['error']), c_proof):<{c_proof}}"
            )
            continue

        contrast   = r.get("contrast") or {}
        diff       = r.get("diff") or {}
        inference  = r.get("inference") or {}
        proof_file = r.get("proof_file", "") or ""

        verdict    = contrast.get("verdict", "?")
        gain_pct   = diff.get("information_gain_pct", 0)
        parity     = diff.get("privilege_parity", "?")
        fail_class = inference.get("failure_class", "?")
        confidence = inference.get("confidence", "?")

        print(
            f"  {ep_id:>{c_ep}}"
            f"  {verdict:<{c_verdict}}"
            f"  {gain_pct:>{c_gain}.1f}"
            f"  {parity:<{c_parity}}"
            f"  {fail_class:<{c_class}}"
            f"  {confidence:<{c_conf}}"
            f"  {_truncate(proof_file, c_proof):<{c_proof}}"
        )

    # Summary footer.
    print(f"  {'-' * (total_w - 4)}")
    print(
        f"\n  Tested: {len(results)}   "
        f"Confirmed: {confirmed_count}   "
        f"Full Privilege Parity: {parity_count}   "
        f"Errors: {errored_count}"
    )

    if parity_count > 0:
        print(
            "\n  🔴 CRITICAL: The bypass achieves Full Privilege Parity "
            "on one or more endpoints — the attacker sees everything "
            "an admin would see."
        )
    elif confirmed_count > 0:
        print(
            "\n  🟡 CONFIRMED: Bypass produces authenticated-level "
            "data on one or more endpoints."
        )

    print(f"{'=' * total_w}\n")


# ═══════════════════════════════════════════════════════════════════════
#  Section L helpers — Temporal Persistence Report
# ═══════════════════════════════════════════════════════════════════════

def _print_temporal_persistence_report(
    results: list[dict],
) -> None:
    """
    Print the **Temporal Persistence Report** for Section L.

    For every endpoint that was tested, displays:
    * Persistence score (High / Medium / Low)
    * Survival Index (0–100)
    * Cache-artifact verdict
    * Consistency conclusion
    * Overall triager rating

    Parameters
    ----------
    results : list[dict]
        Each dict has the structure produced by the Section L loop.
    """
    if not results:
        print("[*] Section L — No temporal results to report.\n")
        return

    # Column widths.
    c_ep     = 12
    c_pers   = 12
    c_score  = 14
    c_cache  = 20
    c_cons   = 20
    c_rating = 10
    c_status = 10
    total_w  = c_ep + c_pers + c_score + c_cache + c_cons + c_rating + c_status + 16

    print(f"\n{'=' * total_w}")
    print("  TEMPORAL PERSISTENCE REPORT")
    print(f"{'=' * total_w}")
    print(
        f"  {'Endpoint':<{c_ep}}"
        f"  {'Persistence':<{c_pers}}"
        f"  {'Survival':<{c_score}}"
        f"  {'Cache':<{c_cache}}"
        f"  {'Consistency':<{c_cons}}"
        f"  {'Rating':<{c_rating}}"
        f"  {'Status':<{c_status}}"
    )
    print(f"  {'-' * (total_w - 4)}")

    errored = sum(1 for r in results if r.get("error"))
    _ratings: list[str] = []
    for _r in results:
        if _r.get("error"):
            continue
        _rating_val = "—"
        if _r.get("survival"):
            _rating_val = str(_r["survival"].get("rating", "—"))
        _ratings.append(_rating_val)
    high_count   = _ratings.count("High")
    medium_count = _ratings.count("Medium")
    low_count    = sum(1 for rt in _ratings if rt not in ("High", "Medium"))

    for r in results:
        ep_id = r["endpoint_id"]

        if r["error"]:
            print(
                f"  {ep_id:<{c_ep}}"
                f"  {'—':<{c_pers}}"
                f"  {'—':<{c_score}}"
                f"  {'—':<{c_cache}}"
                f"  {'—':<{c_cons}}"
                f"  {'—':<{c_rating}}"
                f"  {'ERROR':<{c_status}}"
            )
            continue

        # Persistence score.
        persistence = "—"
        if r.get("persistence"):
            persistence = r["persistence"].get(
                "persistence_score", "—",
            )

        # Survival score.
        survival_str = "—"
        rating       = "—"
        if r.get("survival"):
            s = r["survival"].get("survival_score", 0)
            survival_str = f"{s}/100"
            rating = r["survival"].get("rating", "—")

        # Cache verdict.
        cache_verdict = "—"
        if r.get("cache_check"):
            cache_verdict = r["cache_check"].get("verdict", "—")

        # Consistency.
        consistency = "—"
        if r.get("consistency"):
            raw = r["consistency"].get("conclusion", "—")
            consistency = raw.split(" — ")[0] if " — " in raw else raw

        # Status indicator.
        if rating == "High":
            status = "✅ READY"
        elif rating == "Medium":
            status = "⚠️ CHECK"
        else:
            status = "❌ FAIL"

        print(
            f"  {ep_id:<{c_ep}}"
            f"  {persistence:<{c_pers}}"
            f"  {survival_str:<{c_score}}"
            f"  {_truncate(cache_verdict, c_cache):<{c_cache}}"
            f"  {_truncate(consistency, c_cons):<{c_cons}}"
            f"  {rating:<{c_rating}}"
            f"  {status:<{c_status}}"
        )

    # Summary footer.
    print(f"  {'-' * (total_w - 4)}")
    print(
        f"\n  Tested: {len(results)}   "
        f"High: {high_count}   "
        f"Medium: {medium_count}   "
        f"Low: {low_count}   "
        f"Errors: {errored}"
    )

    if high_count > 0:
        print(
            f"\n  🟢 {high_count} bypass(es) rated HIGH — stable, "
            f"persistent, and ready for Section M: "
            f"Impact Consolidation."
        )
    if low_count > 0:
        print(
            f"\n  🔴 {low_count} bypass(es) rated LOW — transient "
            f"or closed by IPS.  Consider removing from the "
            f"final report."
        )

    print(f"{'=' * total_w}\n")


if __name__ == "__main__":
    main()
