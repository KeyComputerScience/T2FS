#!/usr/bin/env python3
"""T2FS-TLS computational security-bound reproducer."""
from __future__ import annotations
import argparse, json, math
from dataclasses import asdict, dataclass
from pathlib import Path

def neg_log2_probability(p: float) -> float:
    return math.inf if p <= 0.0 else -math.log2(p)

def format_bits(p: float) -> str:
    return "0 (infinite-bit exponent)" if p == 0 else f"{p:.6e}  (~2^-{neg_log2_probability(p):.3f})"

@dataclass(frozen=True)
class T2FSProfile:
    name: str
    n: int
    k: int
    q: int
    eta_s: float
    eta_e: float
    tag_bits: int = 128
    finished_bits: int = 128
    def variance_bound(self) -> float:
        return self.k * self.n * self.eta_s * self.eta_e / 2.0 + self.eta_e / 2.0

PROFILES = {
    "512-IoT": T2FSProfile("T2FS-MLWE-512-IoT", 256, 2, 3329, 3, 2),
    "768-IoT": T2FSProfile("T2FS-MLWE-768-IoT", 256, 3, 3329, 2, 2),
}

def coefficient_failure_bound(q: int, sigma2: float) -> float:
    threshold = q / 8.0
    return min(1.0, 2.0 * math.exp(-(threshold ** 2) / (2.0 * sigma2)))

def reconciliation_failure_bound(profile: T2FSProfile) -> float:
    return min(1.0, profile.n * coefficient_failure_bound(profile.q, profile.variance_bound()))

def retry_failure_bound(p: float) -> float:
    return min(1.0, p * p)

def tag_guessing_bound(q_tag: int, bits: int = 128) -> float:
    return min(1.0, q_tag * 2.0 ** (-bits))

def finished_guessing_bound(q_fin: int, bits: int = 128) -> float:
    return min(1.0, q_fin * 2.0 ** (-bits))

def evaluate(profile, q_tag, q_fin):
    sigma2 = profile.variance_bound()
    pc = coefficient_failure_bound(profile.q, sigma2)
    p1 = reconciliation_failure_bound(profile)
    p2 = retry_failure_bound(p1)
    pt = tag_guessing_bound(q_tag, profile.tag_bits)
    pf = finished_guessing_bound(q_fin, profile.finished_bits)
    return {
        "profile": asdict(profile),
        "variance_bound": sigma2,
        "coefficient_failure_bound": pc,
        "coefficient_failure_bits": neg_log2_probability(pc),
        "single_reconciliation_failure_bound": p1,
        "single_reconciliation_failure_bits": neg_log2_probability(p1),
        "retry_failure_bound": p2,
        "retry_failure_bits": neg_log2_probability(p2),
        "tag_guessing_bound": pt,
        "tag_guessing_bits": neg_log2_probability(pt),
        "finished_guessing_bound": pf,
        "finished_guessing_bits": neg_log2_probability(pf),
    }

def main():
    ap = argparse.ArgumentParser(description="Reproduce T2FS-TLS computational security bounds.")
    ap.add_argument("--profile", choices=["512-IoT", "768-IoT", "all"], default="all")
    ap.add_argument("--q-tag", type=int, default=1)
    ap.add_argument("--q-finished", type=int, default=1)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()
    selected = list(PROFILES.values()) if args.profile == "all" else [PROFILES[args.profile]]
    results = [evaluate(p, args.q_tag, args.q_finished) for p in selected]
    for r in results:
        print("=" * 72)
        print(r["profile"]["name"])
        print(f'sigma_Delta^2 <= {r["variance_bound"]:.6f}')
        print("single reconciliation:", format_bits(r["single_reconciliation_failure_bound"]))
        print("one-retry failure    :", format_bits(r["retry_failure_bound"]))
        print("tag guessing         :", format_bits(r["tag_guessing_bound"]))
        print("Finished guessing    :", format_bits(r["finished_guessing_bound"]))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, indent=2), encoding="utf-8")

if __name__ == "__main__":
    main()
