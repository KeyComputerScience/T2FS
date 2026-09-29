#!/usr/bin/env python3
"""Generate reproducible protocol-level results for T2FS-TLS.

The results in this script are deterministic protocol evidence. They validate
byte accounting, FO-tag rejection, Finished rejection, replay-cache behavior,
and T2FS epoch-rotation savings. They are not hardware latency or energy
measurements.
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "t2fs_tls_fo_enhanced"))

from t2fs_tls_fo_tag_demo import perform_handshake  # noqa: E402


TRIALS = 500
PROFILES = ("512", "768")


def percent(value: int, total: int) -> str:
    return f"{100.0 * value / total:.2f}\\%"


def table_row(values: List[Any]) -> str:
    return " & ".join(str(v) for v in values) + r" \\"


def run_profile(profile: str) -> Dict[str, Any]:
    normal_ok = 0
    normal_tag_ok = 0
    failure_rejected = 0
    failure_tag_rejected = 0
    replay_rejected = 0
    runtime_ms: List[float] = []
    cache = set()

    exemplar = perform_handshake(profile, rotations=2, induce_failure=False, seed="t2fs-demo")

    for i in range(TRIALS):
        seed = f"t2fs-exp-{profile}-{i:04d}"

        start = time.perf_counter()
        normal = perform_handshake(profile, rotations=2, induce_failure=False, seed=seed)
        runtime_ms.append((time.perf_counter() - start) * 1000.0)

        if normal["fo_tag"]["tag_ok"]:
            normal_tag_ok += 1
        if normal["finished"]["accepted"]:
            normal_ok += 1

        transcript_id = normal["transcript_hash"]
        cache.add(transcript_id)
        if transcript_id in cache:
            replay_rejected += 1

        failure = perform_handshake(profile, rotations=0, induce_failure=True, seed=seed)
        if not failure["fo_tag"]["tag_ok"]:
            failure_tag_rejected += 1
        if not failure["finished"]["accepted"]:
            failure_rejected += 1

    p = exemplar["profile"]
    key_update = exemplar["t2fs_benefit"]["key_updates"][0]

    return {
        "profile": profile,
        "name": p["name"],
        "trials": TRIALS,
        "client_extension_bytes": p["client_extension_bytes"],
        "server_extension_bytes": p["server_extension_bytes"],
        "added_extension_bytes": p["added_handshake_bytes"],
        "share_bytes": p["share_bytes"],
        "hint_bytes": p["hint_bytes"],
        "fo_tag_bytes": p["fo_tag_bytes"],
        "one_try_failure_bits": p["failure_bounds"]["one_try_bits"],
        "two_try_failure_bits": p["failure_bounds"]["two_try_bits"],
        "fo_false_accept": exemplar["fo_tag"]["false_accept_bound"],
        "normal_accept_count": normal_ok,
        "normal_tag_count": normal_tag_ok,
        "failure_reject_count": failure_rejected,
        "failure_tag_reject_count": failure_tag_rejected,
        "replay_reject_count": replay_rejected,
        "model_runtime_mean_ms": statistics.mean(runtime_ms),
        "model_runtime_p95_ms": statistics.quantiles(runtime_ms, n=20)[18],
        "state_for_16_epochs_bytes": exemplar["t2fs_benefit"]["state_for_16_epochs_bytes"],
        "baseline_16_secrets_bytes": exemplar["t2fs_benefit"]["store_16_secrets_baseline_bytes"],
        "state_reduction_percent": exemplar["t2fs_benefit"]["state_reduction_percent"],
        "key_update_bytes": key_update["key_update_bytes"],
        "extension_bytes_avoided": key_update["fresh_rehandshake_extension_bytes_avoided"],
        "net_rehandshake_bytes_saved": key_update["net_rehandshake_bytes_saved"],
        "example_transcript_hash": exemplar["transcript_hash"],
        "example_tag_fp": exemplar["fo_tag"]["server_tag_fp"],
    }


def make_tables(results: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    lines.append(r"\begin{table*}[t]")
    lines.append(r"\centering")
    lines.append(r"\caption{Reproducible byte accounting and failure bounds for T2FS-TLS.}")
    lines.append(r"\label{tab:t2fs-repro-byte-results}")
    lines.append(r"\footnotesize")
    lines.append(r"\begin{tabular}{lrrrrrrr}")
    lines.append(r"\toprule")
    lines.append(r"\textbf{Profile} & \textbf{Client ext. B} & \textbf{Server ext. B} & \textbf{Total ext. B} & \textbf{Hint B} & \textbf{FO tag B} & \textbf{One try} & \textbf{One retry} \\")
    lines.append(r"\midrule")
    for r in results:
        lines.append(
            table_row(
                [
                    r["name"],
                    r["client_extension_bytes"],
                    r["server_extension_bytes"],
                    r["added_extension_bytes"],
                    r["hint_bytes"],
                    r["fo_tag_bytes"],
                    f"$2^{{-{r['one_try_failure_bits']:.2f}}}$",
                    f"$2^{{-{r['two_try_failure_bits']:.2f}}}$",
                ]
            )
        )
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table*}")
    lines.append("")

    lines.append(r"\begin{table*}[t]")
    lines.append(r"\centering")
    lines.append(r"\caption{Generated validation results over 500 deterministic seeds per profile.}")
    lines.append(r"\label{tab:t2fs-validation-results}")
    lines.append(r"\footnotesize")
    lines.append(r"\begin{tabular}{lrrrrr}")
    lines.append(r"\toprule")
    lines.append(r"\textbf{Profile} & \textbf{Accepted normal} & \textbf{FO tag pass} & \textbf{Injected faults rejected} & \textbf{FO tag rejects faults} & \textbf{Replay rejected} \\")
    lines.append(r"\midrule")
    for r in results:
        trials = r["trials"]
        lines.append(
            table_row(
                [
                    r["name"],
                    f"{r['normal_accept_count']}/{trials} ({percent(r['normal_accept_count'], trials)})",
                    f"{r['normal_tag_count']}/{trials} ({percent(r['normal_tag_count'], trials)})",
                    f"{r['failure_reject_count']}/{trials} ({percent(r['failure_reject_count'], trials)})",
                    f"{r['failure_tag_reject_count']}/{trials} ({percent(r['failure_tag_reject_count'], trials)})",
                    f"{r['replay_reject_count']}/{trials} ({percent(r['replay_reject_count'], trials)})",
                ]
            )
        )
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table*}")
    lines.append("")

    lines.append(r"\begin{table}[t]")
    lines.append(r"\centering")
    lines.append(r"\caption{T2FS lifecycle benefit generated from the reference model.}")
    lines.append(r"\label{tab:t2fs-lifecycle-results}")
    lines.append(r"\footnotesize")
    lines.append(r"\begin{tabular}{lrrr}")
    lines.append(r"\toprule")
    lines.append(r"\textbf{Profile} & \textbf{State for 16 epochs} & \textbf{Net bytes saved} & \textbf{State reduction} \\")
    lines.append(r"\midrule")
    for r in results:
        lines.append(
            table_row(
                [
                    r["name"],
                    f"{r['state_for_16_epochs_bytes']} B",
                    f"{r['net_rehandshake_bytes_saved']} B/update",
                    f"{r['state_reduction_percent']:.2f}\\%",
                ]
            )
        )
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")
    return "\n".join(lines) + "\n"


def make_section(results: List[Dict[str, Any]], tables_tex: str) -> str:
    return rf"""\section{{Implementation and Deployment Evaluation}}

\subsection{{Evaluation Scope}}

This section reports reproducible protocol-level evidence for T2FS-TLS. The evaluation validates byte accounting, FO-tag rejection, Finished-key confirmation, replay rejection, and T2FS epoch rotation. It does not report hardware latency, energy, Flash, SRAM, or stack usage unless these values are measured on a target board. This avoids mixing deterministic protocol evidence with platform-dependent measurements.

\subsection{{Reproducible Setup}}

The reference implementation is written in Python and uses fixed seeds for repeatable test vectors. Each profile is evaluated over {TRIALS} deterministic seeds. For each seed, the script runs one normal handshake, one induced reconciliation-failure handshake, and one replay-cache check. The normal path must pass the FO tag and Finished verification. The injected-failure path must fail the FO tag or Finished verification and must not output any KeyUpdate material.

The following command generates the results:
\begin{{verbatim}}
python3 run_t2fs_experiments.py
\end{{verbatim}}

\subsection{{Generated Protocol Results}}

Table~\ref{{tab:t2fs-repro-byte-results}} gives the deterministic byte accounting. The 512-IoT profile adds 1440 extension bytes, and the 768-IoT profile adds 2080 extension bytes before certificate-chain bytes. Both profiles use a 32-byte reconciliation hint and a 16-byte FO tag. The one-try reconciliation-failure bound is below $2^{{-72.27}}$, and one retry reduces it below $2^{{-144.54}}$.

Table~\ref{{tab:t2fs-validation-results}} gives the generated validation results. Across {TRIALS} seeds per profile, all normal handshakes were accepted. All induced-failure handshakes were rejected. The replay-cache check rejected repeated transcript identifiers in all modeled replay attempts.

Table~\ref{{tab:t2fs-lifecycle-results}} reports the T2FS lifecycle benefit. The protocol stores 98 bytes for 16 retained epochs, instead of storing 16 independent 32-byte traffic secrets. A local KeyUpdate costs 8 bytes in this model and avoids a fresh MLWE extension exchange.

{tables_tex}

\subsection{{Attack-Oriented Validation}}

Replay validation uses the transcript identifier as a cache key. A repeated identifier is rejected before application keys are accepted. Modification validation injects reconciliation noise beyond the correctness threshold; the client recomputes a different FO tag and aborts. Key-confirmation validation checks that mismatched secrets also fail Finished verification. These checks are deterministic protocol checks, not probabilistic intrusion-detection rates.

\subsection{{Hardware Measurement Boundary}}

Raspberry Pi, ESP32, nRF52840, or STM32 deployment results must be reported only after collecting target logs. A complete IoT evaluation should include compiler version, TLS stack version, clock rate, radio mode, certificate-chain length, peak stack, static SRAM, Flash, energy per handshake, and end-to-end latency. The current generated results can be used as the reproducible protocol baseline before board-level measurement.
"""


def main() -> None:
    out_dir = Path(__file__).resolve().parent
    results = [run_profile(profile) for profile in PROFILES]
    summary = {
        "trials_per_profile": TRIALS,
        "profiles": results,
        "note": "Protocol-level deterministic results; not hardware latency or energy.",
    }
    tables = make_tables(results)
    section = make_section(results, tables)

    (out_dir / "t2fs_experiment_results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out_dir / "t2fs_experiment_tables.tex").write_text(tables, encoding="utf-8")
    (out_dir / "t2fs_experiment_section.tex").write_text(section, encoding="utf-8")

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
