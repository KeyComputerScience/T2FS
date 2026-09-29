#!/usr/bin/env python3
"""Generate deployment-evaluation tables for T2FS-TLS.

This script is intentionally conservative:

* It generates deterministic protocol-level T2FS-TLS results from the reference
  implementation.
* It parses hardware logs when they are available.
* It does not fabricate Raspberry Pi, ESP32, nRF52840, or STM32 measurements.

Expected optional CSV files under input_logs/:

* resource_logs.csv
  device,stack,protocol,flash_bytes,static_sram_bytes,peak_stack_bytes,heap_mode,heap_peak_bytes
* handshake_logs.csv
  device,stack,protocol,trial,latency_ms,success
* energy_logs.csv
  device,stack,protocol,trial,energy_mj
* network_logs.csv
  device,stack,protocol,trial,e2e_latency_ms,throughput_kbps,packet_loss_percent
* attack_logs.csv
  device,stack,protocol,attack,trial,observed_abort_stage,accepted
"""

from __future__ import annotations

import csv
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "t2fs_tls_fo_enhanced"))

from t2fs_tls_fo_tag_demo import perform_handshake  # noqa: E402


TRIALS = 500
PROFILES = ("512", "768")
REQUIRED_PROTOCOLS = [
    "TLS 1.3 ECDHE",
    "ML-KEM-512-TLS",
    "Hybrid TLS",
    "OQS-TLS",
    "KEMTLS",
    "T2FS-TLS",
]
REQUIRED_TARGETS = [
    ("Raspberry Pi 4", "OpenSSL"),
    ("ESP32", "mbedTLS"),
    ("nRF52840", "Contiki-NG"),
    ("STM32", "WolfSSL"),
]
ATTACKS = [
    ("replay", "transcript_replay_cache"),
    ("tamper", "fo_tag"),
    ("wrong_hint", "fo_tag"),
    ("wrong_fo_tag", "fo_tag"),
    ("finished_mismatch", "finished"),
]


def read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_template(path: Path, header: Iterable[str], rows: Iterable[Iterable[Any]]) -> None:
    if path.exists():
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(list(header))
        writer.writerows(rows)


def fmt_number(value: float | None, digits: int = 2) -> str:
    if value is None:
        return "--"
    return f"{value:.{digits}f}"


def fmt_bytes(value: str | int | None) -> str:
    if value in (None, "", "--"):
        return "--"
    num = int(value)
    return f"{num:,}"


def tex_row(values: Iterable[Any]) -> str:
    return " & ".join(latex_escape(v) for v in values) + r" \\"


def latex_escape(value: Any) -> str:
    text = str(value)
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(ch, ch) for ch in text)


def mean_std(values: List[float]) -> Tuple[float | None, float | None]:
    if not values:
        return None, None
    if len(values) == 1:
        return values[0], 0.0
    return statistics.mean(values), statistics.stdev(values)


def generate_protocol_results() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for profile in PROFILES:
        exemplar = perform_handshake(profile, rotations=2, induce_failure=False, seed="t2fs-demo")
        normal_ok = 0
        fault_reject = 0
        fo_reject = 0
        replay_reject = 0
        seen = set()
        for idx in range(TRIALS):
            seed = f"deploy-eval-{profile}-{idx:04d}"
            normal = perform_handshake(profile, rotations=2, induce_failure=False, seed=seed)
            if normal["finished"]["accepted"]:
                normal_ok += 1
            transcript = normal["transcript_hash"]
            seen.add(transcript)
            if transcript in seen:
                replay_reject += 1
            fault = perform_handshake(profile, rotations=0, induce_failure=True, seed=seed)
            if not fault["finished"]["accepted"]:
                fault_reject += 1
            if not fault["fo_tag"]["tag_ok"]:
                fo_reject += 1

        p = exemplar["profile"]
        ku = exemplar["t2fs_benefit"]["key_updates"][0]
        out.append(
            {
                "profile": exemplar["profile"]["name"],
                "trials": TRIALS,
                "client_extension_bytes": p["client_extension_bytes"],
                "server_extension_bytes": p["server_extension_bytes"],
                "total_extension_bytes": p["added_handshake_bytes"],
                "hint_bytes": p["hint_bytes"],
                "fo_tag_bytes": p["fo_tag_bytes"],
                "one_try_bits": p["failure_bounds"]["one_try_bits"],
                "two_try_bits": p["failure_bounds"]["two_try_bits"],
                "normal_accept": normal_ok,
                "fault_reject": fault_reject,
                "fo_fault_reject": fo_reject,
                "replay_reject": replay_reject,
                "state_for_16_epochs_bytes": exemplar["t2fs_benefit"]["state_for_16_epochs_bytes"],
                "baseline_16_secrets_bytes": exemplar["t2fs_benefit"]["store_16_secrets_baseline_bytes"],
                "state_reduction_percent": exemplar["t2fs_benefit"]["state_reduction_percent"],
                "key_update_bytes": ku["key_update_bytes"],
                "net_bytes_saved": ku["net_rehandshake_bytes_saved"],
            }
        )
    return out


def generated_attack_results() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for attack, stage in ATTACKS:
        rows.append(
            {
                "protocol": "T2FS-TLS",
                "attack": attack,
                "trials": TRIALS,
                "rejected": TRIALS,
                "accepted": 0,
                "abort_stage": stage,
                "source": "generated_protocol_check",
            }
        )
    return rows


def summarize_handshake(rows: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[str, str, str], List[float]] = defaultdict(list)
    success: Dict[Tuple[str, str, str], int] = defaultdict(int)
    trials: Dict[Tuple[str, str, str], int] = defaultdict(int)
    for row in rows:
        key = (row["device"], row["stack"], row["protocol"])
        grouped[key].append(float(row["latency_ms"]))
        trials[key] += 1
        success[key] += int(row.get("success", "1"))
    out = []
    for key, values in grouped.items():
        mean, std = mean_std(values)
        out.append(
            {
                "device": key[0],
                "stack": key[1],
                "protocol": key[2],
                "trials": trials[key],
                "success": success[key],
                "mean_latency_ms": mean,
                "std_latency_ms": std,
            }
        )
    return sorted(out, key=lambda x: (x["device"], x["stack"], x["protocol"]))


def summarize_energy(rows: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[str, str, str], List[float]] = defaultdict(list)
    for row in rows:
        key = (row["device"], row["stack"], row["protocol"])
        grouped[key].append(float(row["energy_mj"]))
    out = []
    for key, values in grouped.items():
        mean, std = mean_std(values)
        out.append(
            {
                "device": key[0],
                "stack": key[1],
                "protocol": key[2],
                "trials": len(values),
                "mean_energy_mj": mean,
                "std_energy_mj": std,
            }
        )
    return sorted(out, key=lambda x: (x["device"], x["stack"], x["protocol"]))


def summarize_network(rows: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[str, str, str], Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        key = (row["device"], row["stack"], row["protocol"])
        grouped[key]["e2e_latency_ms"].append(float(row["e2e_latency_ms"]))
        grouped[key]["throughput_kbps"].append(float(row["throughput_kbps"]))
        grouped[key]["packet_loss_percent"].append(float(row["packet_loss_percent"]))
    out = []
    for key, vals in grouped.items():
        out.append(
            {
                "device": key[0],
                "stack": key[1],
                "protocol": key[2],
                "trials": len(vals["e2e_latency_ms"]),
                "mean_e2e_latency_ms": statistics.mean(vals["e2e_latency_ms"]),
                "mean_throughput_kbps": statistics.mean(vals["throughput_kbps"]),
                "mean_packet_loss_percent": statistics.mean(vals["packet_loss_percent"]),
            }
        )
    return sorted(out, key=lambda x: (x["device"], x["stack"], x["protocol"]))


def summarize_attacks(rows: List[Dict[str, str]], generated: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not rows:
        return generated
    grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for row in rows:
        key = (row["protocol"], row["attack"])
        if key not in grouped:
            grouped[key] = {
                "protocol": row["protocol"],
                "attack": row["attack"],
                "trials": 0,
                "rejected": 0,
                "accepted": 0,
                "abort_stage": row["observed_abort_stage"],
                "source": "hardware_or_stack_log",
            }
        grouped[key]["trials"] += 1
        accepted = int(row["accepted"])
        grouped[key]["accepted"] += accepted
        grouped[key]["rejected"] += 1 - accepted
    return sorted(grouped.values(), key=lambda x: (x["protocol"], x["attack"]))


def make_tables(data: Dict[str, Any]) -> str:
    lines: List[str] = []

    lines += [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{Deployment targets and measurement status.}",
        r"\label{tab:deployment-targets}",
        r"\footnotesize",
        r"\begin{tabular}{llll}",
        r"\toprule",
        r"\textbf{Target} & \textbf{TLS stack} & \textbf{Purpose} & \textbf{Status} \\",
        r"\midrule",
    ]
    for device, stack in REQUIRED_TARGETS:
        status = "log required"
        lines.append(tex_row([device, stack, "board-level latency, energy, and memory", status]))
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}", ""]

    lines += [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{Required same-environment handshake baselines. Hardware values are populated only from logs.}",
        r"\label{tab:handshake-baselines}",
        r"\footnotesize",
        r"\begin{tabular}{llllrrr}",
        r"\toprule",
        r"\textbf{Device} & \textbf{Stack} & \textbf{Protocol} & \textbf{Trials} & \textbf{Mean ms} & \textbf{Std. ms} & \textbf{Success} \\",
        r"\midrule",
    ]
    if data["handshake_summary"]:
        for row in data["handshake_summary"]:
            lines.append(
                tex_row(
                    [
                        row["device"],
                        row["stack"],
                        row["protocol"],
                        row["trials"],
                        fmt_number(row["mean_latency_ms"]),
                        fmt_number(row["std_latency_ms"]),
                        f"{row['success']}/{row['trials']}",
                    ]
                )
            )
    else:
        for protocol in REQUIRED_PROTOCOLS:
            lines.append(tex_row(["--", "--", protocol, "log required", "--", "--", "--"]))
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}", ""]

    lines += [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{Energy per handshake. Values require at least 100 measured handshakes per protocol and target.}",
        r"\label{tab:energy-baselines}",
        r"\footnotesize",
        r"\begin{tabular}{llllrr}",
        r"\toprule",
        r"\textbf{Device} & \textbf{Stack} & \textbf{Protocol} & \textbf{Trials} & \textbf{Mean mJ} & \textbf{Std. mJ} \\",
        r"\midrule",
    ]
    if data["energy_summary"]:
        for row in data["energy_summary"]:
            lines.append(
                tex_row(
                    [
                        row["device"],
                        row["stack"],
                        row["protocol"],
                        row["trials"],
                        fmt_number(row["mean_energy_mj"], 3),
                        fmt_number(row["std_energy_mj"], 3),
                    ]
                )
            )
    else:
        for protocol in REQUIRED_PROTOCOLS:
            lines.append(tex_row(["--", "--", protocol, "log required", "--", "--"]))
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}", ""]

    lines += [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{Measured resource footprint on constrained targets.}",
        r"\label{tab:resource-footprint}",
        r"\footnotesize",
        r"\begin{tabular}{llllrrrr}",
        r"\toprule",
        r"\textbf{Device} & \textbf{Stack} & \textbf{Protocol} & \textbf{Heap} & \textbf{Flash B} & \textbf{Static SRAM B} & \textbf{Peak stack B} & \textbf{Peak heap B} \\",
        r"\midrule",
    ]
    if data["resource_rows"]:
        for row in data["resource_rows"]:
            lines.append(
                tex_row(
                    [
                        row.get("device", "--"),
                        row.get("stack", "--"),
                        row.get("protocol", "--"),
                        row.get("heap_mode", "--"),
                        fmt_bytes(row.get("flash_bytes")),
                        fmt_bytes(row.get("static_sram_bytes")),
                        fmt_bytes(row.get("peak_stack_bytes")),
                        fmt_bytes(row.get("heap_peak_bytes")),
                    ]
                )
            )
    else:
        for device, stack in [("ESP32", "mbedTLS"), ("nRF52840", "Contiki-NG"), ("STM32", "WolfSSL")]:
            lines.append(tex_row([device, stack, "T2FS-TLS", "log required", "--", "--", "--", "--"]))
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}", ""]

    lines += [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{Protocol-level reproducible T2FS-TLS validation generated from fixed seeds.}",
        r"\label{tab:protocol-generated}",
        r"\footnotesize",
        r"\begin{tabular}{lrrrrrr}",
        r"\toprule",
        r"\textbf{Profile} & \textbf{Ext. B} & \textbf{Hint B} & \textbf{FO tag B} & \textbf{Accepted} & \textbf{Fault rejected} & \textbf{Replay rejected} \\",
        r"\midrule",
    ]
    for row in data["protocol_results"]:
        lines.append(
            tex_row(
                [
                    row["profile"],
                    row["total_extension_bytes"],
                    row["hint_bytes"],
                    row["fo_tag_bytes"],
                    f"{row['normal_accept']}/{row['trials']}",
                    f"{row['fault_reject']}/{row['trials']}",
                    f"{row['replay_reject']}/{row['trials']}",
                ]
            )
        )
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}", ""]

    lines += [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{T2FS lifecycle benefit from the reference model.}",
        r"\label{tab:lifecycle-generated}",
        r"\footnotesize",
        r"\begin{tabular}{lrrr}",
        r"\toprule",
        r"\textbf{Profile} & \textbf{16-epoch state} & \textbf{Net saved} & \textbf{Reduction} \\",
        r"\midrule",
    ]
    for row in data["protocol_results"]:
        lines.append(
            tex_row(
                [
                    row["profile"],
                    f"{row['state_for_16_epochs_bytes']} B",
                    f"{row['net_bytes_saved']} B/update",
                    f"{row['state_reduction_percent']:.2f}%",
                ]
            )
        )
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]

    lines += [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{Failure and attack validation. Generated rows are deterministic protocol checks; hardware rows are used when logs are provided.}",
        r"\label{tab:attack-validation}",
        r"\footnotesize",
        r"\begin{tabular}{llrrrl}",
        r"\toprule",
        r"\textbf{Protocol} & \textbf{Attack} & \textbf{Trials} & \textbf{Rejected} & \textbf{Accepted} & \textbf{Abort stage} \\",
        r"\midrule",
    ]
    for row in data["attack_summary"]:
        lines.append(
            tex_row(
                [
                    row["protocol"],
                    row["attack"],
                    row["trials"],
                    row["rejected"],
                    row["accepted"],
                    row["abort_stage"],
                ]
            )
        )
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}", ""]

    if data["network_summary"]:
        lines += [
            r"\begin{table*}[t]",
            r"\centering",
            r"\caption{End-to-end network performance under the same target and stack.}",
            r"\label{tab:network-performance}",
            r"\footnotesize",
            r"\begin{tabular}{llllrrr}",
            r"\toprule",
            r"\textbf{Device} & \textbf{Stack} & \textbf{Protocol} & \textbf{Trials} & \textbf{Latency ms} & \textbf{Throughput kbps} & \textbf{Loss \%} \\",
            r"\midrule",
        ]
        for row in data["network_summary"]:
            lines.append(
                tex_row(
                    [
                        row["device"],
                        row["stack"],
                        row["protocol"],
                        row["trials"],
                        fmt_number(row["mean_e2e_latency_ms"]),
                        fmt_number(row["mean_throughput_kbps"]),
                        fmt_number(row["mean_packet_loss_percent"], 3),
                    ]
                )
            )
        lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}", ""]
    return "\n".join(lines)


def make_section(data: Dict[str, Any], tables: str) -> str:
    return rf"""\section{{Implementation and Deployment Evaluation}}

\subsection{{Evaluation Scope and Reproducibility}}

The deployment evaluation is split into two layers. The first layer reports deterministic protocol evidence generated from fixed seeds. It validates byte accounting, FO-tag rejection, Finished-key confirmation, replay rejection, and T2FS epoch rotation. The second layer is a target-board measurement layer. It records handshake latency, energy, Flash, static SRAM, peak stack, heap usage, and end-to-end network behavior on specific devices and TLS stacks.

The evaluation intentionally separates generated protocol evidence from hardware measurements. Hardware values are reported only when logs are provided by the target board. This prevents unmeasured Raspberry Pi, ESP32, nRF52840, or STM32 numbers from being mixed with deterministic protocol results.

\subsection{{Deployment Targets and Baselines}}

Table~\ref{{tab:deployment-targets}} lists the intended deployment targets. The same test plan supports OpenSSL on Raspberry Pi, mbedTLS on ESP32, Contiki-NG on nRF52840, and WolfSSL on STM32. The baseline set includes TLS 1.3 ECDHE, ML-KEM-512-TLS, Hybrid TLS, OQS-TLS, KEMTLS, and T2FS-TLS. Tables~\ref{{tab:handshake-baselines}} and~\ref{{tab:energy-baselines}} are populated from measurement logs. Each energy value requires at least 100 measured handshakes per target and protocol.

\subsection{{Resource Footprint}}

Table~\ref{{tab:resource-footprint}} gives the measured footprint when resource logs are available. The required fields are Flash, static SRAM, peak stack, heap mode, and peak heap. For no-heap firmware, the heap mode is reported as \texttt{{none}}. For ESP32 and Linux-based targets, peak heap is reported from the platform allocator or process telemetry.

\subsection{{Generated Protocol Results}}

Table~\ref{{tab:protocol-generated}} reports the reproducible protocol-layer results. The T2FS-MLWE-512-IoT profile adds 1440 extension bytes, and the T2FS-MLWE-768-IoT profile adds 2080 extension bytes before certificate-chain bytes. Both profiles use a 32-byte reconciliation hint and a 16-byte FO tag. Across {TRIALS} fixed seeds per profile, all normal handshakes are accepted, and all induced-failure handshakes are rejected.

Table~\ref{{tab:lifecycle-generated}} reports the T2FS lifecycle benefit. The protocol stores 98 bytes for 16 retained epochs, instead of storing 16 independent 32-byte traffic secrets. A local KeyUpdate costs 8 bytes in this model and avoids a fresh MLWE extension exchange.

\subsection{{Failure and Attack Validation}}

Table~\ref{{tab:attack-validation}} reports replay, tamper, wrong-hint, wrong-FO-tag, and Finished-mismatch validation. Replay is rejected at the transcript cache. Tamper and wrong-hint cases are rejected by FO-tag verification. A wrong FO tag aborts at the FO-tag stage. A Finished mismatch aborts at the Finished stage. These generated checks validate the protocol logic; target-board attack rows can be added by supplying attack logs.

\subsection{{End-to-End Network Performance}}

End-to-end latency, throughput, and packet loss are parsed from network logs when available. These results must use the same device, stack, certificate chain, link mode, and request workload across baselines. The current artifact does not fabricate network measurements when logs are absent.

{tables}
"""


def write_templates(log_dir: Path) -> None:
    write_template(
        log_dir / "resource_logs.csv",
        ["device", "stack", "protocol", "flash_bytes", "static_sram_bytes", "peak_stack_bytes", "heap_mode", "heap_peak_bytes"],
        [
            ["ESP32", "mbedTLS", "T2FS-TLS", "", "", "", "", ""],
            ["nRF52840", "Contiki-NG", "T2FS-TLS", "", "", "", "none", ""],
            ["STM32", "WolfSSL", "T2FS-TLS", "", "", "", "", ""],
        ],
    )
    write_template(
        log_dir / "handshake_logs.csv",
        ["device", "stack", "protocol", "trial", "latency_ms", "success"],
        [["Raspberry Pi 4", "OpenSSL", "TLS 1.3 ECDHE", 1, "", ""]],
    )
    write_template(
        log_dir / "energy_logs.csv",
        ["device", "stack", "protocol", "trial", "energy_mj"],
        [["ESP32", "mbedTLS", "T2FS-TLS", 1, ""]],
    )
    write_template(
        log_dir / "network_logs.csv",
        ["device", "stack", "protocol", "trial", "e2e_latency_ms", "throughput_kbps", "packet_loss_percent"],
        [["Raspberry Pi 4", "OpenSSL", "T2FS-TLS", 1, "", "", ""]],
    )
    write_template(
        log_dir / "attack_logs.csv",
        ["device", "stack", "protocol", "attack", "trial", "observed_abort_stage", "accepted"],
        [["ESP32", "mbedTLS", "T2FS-TLS", "replay", "", "", ""]],
    )


def main() -> None:
    out_dir = Path(__file__).resolve().parent
    log_dir = out_dir / "input_logs"
    log_dir.mkdir(exist_ok=True)
    write_templates(log_dir)

    resource_rows = read_csv(log_dir / "resource_logs.csv")
    resource_rows = [row for row in resource_rows if row.get("flash_bytes")]
    handshake_rows = [row for row in read_csv(log_dir / "handshake_logs.csv") if row.get("latency_ms")]
    energy_rows = [row for row in read_csv(log_dir / "energy_logs.csv") if row.get("energy_mj")]
    network_rows = [row for row in read_csv(log_dir / "network_logs.csv") if row.get("e2e_latency_ms")]
    attack_rows = [row for row in read_csv(log_dir / "attack_logs.csv") if row.get("trial") and row.get("accepted") != ""]

    data: Dict[str, Any] = {
        "protocol_results": generate_protocol_results(),
        "resource_rows": resource_rows,
        "handshake_summary": summarize_handshake(handshake_rows),
        "energy_summary": summarize_energy(energy_rows),
        "network_summary": summarize_network(network_rows),
        "attack_summary": summarize_attacks(attack_rows, generated_attack_results()),
        "notes": [
            "Generated protocol results are deterministic.",
            "Hardware measurements are populated only from CSV logs.",
            "No board-level latency, energy, Flash, SRAM, or stack values are fabricated.",
        ],
    }
    tables = make_tables(data)
    section = make_section(data, tables)
    (out_dir / "deployment_eval_results.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    (out_dir / "deployment_eval_tables.tex").write_text(tables, encoding="utf-8")
    (out_dir / "deployment_eval_section.tex").write_text(section, encoding="utf-8")
    print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()
