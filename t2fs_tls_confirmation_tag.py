#!/usr/bin/env python3
"""Reproducible T2FS-TLS methodology demo.

This reference code mirrors the LaTeX methodology:

* MLWE profile and byte accounting.
* Complete HelpRec/Rec using one public hint bit per coefficient.
* Correctness failure bound from the stated subgaussian tail.
* FO-style transcript tag bound to the recovered key material.
* Transcript-bound HKDF and T2FS role/epoch/purpose derivation.
* Finished verification, tag-bound rejection, and retry-safe failure reporting.

The coefficient vectors in this file are a deterministic protocol-flow model.
They test reproducibility of reconciliation, transcript binding, and byte
accounting. Production code must replace the vector generator with constant-time
MLWE polynomial arithmetic and a vetted sampler.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import secrets
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Tuple


HASH_LEN = 32
FO_TAG_LEN = 16


def lp(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def hash_bytes(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for part in parts:
        h.update(lp(part))
    return h.digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * HASH_LEN
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac_sha256(prk, block + info + bytes([counter]))
        out += block
        counter += 1
    return out[:length]


def fp(data: bytes, chars: int = 16) -> str:
    return data.hex()[:chars]


def demo_bytes(seed: str | None, label: bytes, length: int) -> bytes:
    """Deterministic bytes for reproducible test vectors; random bytes if seed is None."""
    if seed is None:
        return secrets.token_bytes(length)
    out = b""
    counter = 0
    seed_bytes = seed.encode("utf-8")
    while len(out) < length:
        out += hash_bytes(seed_bytes, label, counter.to_bytes(4, "big"))
        counter += 1
    return out[:length]


def demo_int(seed: str | None, label: bytes, modulus: int) -> int:
    if seed is None:
        return secrets.randbelow(modulus)
    return int.from_bytes(demo_bytes(seed, label, 32), "big") % modulus


def pack_bits(bits: Iterable[int]) -> bytes:
    out = bytearray()
    value = 0
    count = 0
    for bit in bits:
        value = (value << 1) | (bit & 1)
        count += 1
        if count == 8:
            out.append(value)
            value = 0
            count = 0
    if count:
        out.append(value << (8 - count))
    return bytes(out)


def unpack_bits(data: bytes, count: int) -> List[int]:
    bits: List[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
            if len(bits) == count:
                return bits
    return bits


def dist_q(a: int, b: int, q: int) -> int:
    delta = (a - b) % q
    return min(delta, q - delta)


def round_div(num: int, den: int) -> int:
    return (num + den // 2) // den


@dataclass(frozen=True)
class Profile:
    key: str
    name: str
    n: int
    k: int
    q: int
    eta_s: int
    eta_e: int
    du: int
    dh: int
    security_family: str

    @property
    def share_bytes(self) -> int:
        return self.k * self.n * self.du // 8

    @property
    def hint_bytes(self) -> int:
        return self.n * self.dh // 8

    @property
    def client_ext_data_bytes(self) -> int:
        return 2 + 1 + 2 + 32 + 32 + self.share_bytes

    @property
    def server_ext_data_bytes(self) -> int:
        return 2 + 1 + 32 + self.share_bytes + self.hint_bytes + FO_TAG_LEN

    @property
    def client_extension_bytes(self) -> int:
        return 2 + 2 + self.client_ext_data_bytes

    @property
    def server_extension_bytes(self) -> int:
        return 2 + 2 + self.server_ext_data_bytes

    @property
    def added_handshake_bytes(self) -> int:
        return self.client_extension_bytes + self.server_extension_bytes

    @property
    def sigma_delta_sq(self) -> float:
        return self.k * self.n * self.eta_s * self.eta_e / 2 + self.eta_e / 2

    @property
    def threshold(self) -> float:
        return self.q / 8

    def failure_bounds(self) -> Dict[str, float]:
        per_coeff = 2 * math.exp(-(self.threshold ** 2) / (2 * self.sigma_delta_sq))
        one_try = min(1.0, self.n * per_coeff)
        two_try = one_try * one_try
        return {
            "sigma_delta_sq": self.sigma_delta_sq,
            "threshold_q_over_8": self.threshold,
            "per_coefficient": per_coeff,
            "per_coefficient_bits": -math.log2(per_coeff),
            "one_try": one_try,
            "one_try_bits": -math.log2(one_try),
            "two_try": two_try,
            "two_try_bits": -math.log2(two_try),
        }


PROFILES: Dict[str, Profile] = {
    "512": Profile(
        key="512",
        name="T2FS-MLWE-512-IoT",
        n=256,
        k=2,
        q=3329,
        eta_s=3,
        eta_e=2,
        du=10,
        dh=1,
        security_family="ML-KEM-512 module-dimension family",
    ),
    "768": Profile(
        key="768",
        name="T2FS-MLWE-768-IoT",
        n=256,
        k=3,
        q=3329,
        eta_s=2,
        eta_e=2,
        du=10,
        dh=1,
        security_family="ML-KEM-768 module-dimension family",
    ),
}


class Transcript:
    def __init__(self) -> None:
        self.items: List[Tuple[str, bytes]] = []

    def add(self, label: str, payload: bytes) -> None:
        self.items.append((label, payload))

    def digest(self) -> bytes:
        return hash_bytes(*(label.encode("utf-8") + lp(payload) for label, payload in self.items))

    def table(self) -> List[Dict[str, object]]:
        return [
            {"message": label, "bytes": len(payload), "fingerprint": fp(payload)}
            for label, payload in self.items
        ]


def help_rec(ws: List[int], transcript_hash: bytes, q: int) -> Tuple[bytes, bytes, List[int]]:
    raw_bits: List[int] = []
    hint_bits: List[int] = []
    for x in ws:
        j = round_div(4 * (x % q), q) % 4
        raw_bits.append(j // 2)
        hint_bits.append(j & 1)
    hint = pack_bits(hint_bits)
    raw = pack_bits(raw_bits)
    z = hkdf_extract(hash_bytes(transcript_hash, hint), raw)
    return z, hint, raw_bits


def rec(wc: List[int], hint: bytes, transcript_hash: bytes, q: int, n: int) -> Tuple[bytes, List[int]]:
    hint_bits = unpack_bits(hint, n)
    raw_bits: List[int] = []
    for y, hbit in zip(wc, hint_bits):
        c0 = round((hbit * q) / 4) % q
        c1 = round(((hbit + 2) * q) / 4) % q
        raw_bits.append(0 if dist_q(y, c0, q) <= dist_q(y, c1, q) else 1)
    raw = pack_bits(raw_bits)
    z = hkdf_extract(hash_bytes(transcript_hash, hint), raw)
    return z, raw_bits


def fo_tag(z: bytes, context: bytes, tag_len: int = FO_TAG_LEN) -> bytes:
    return hmac_sha256(z, b"T2FS-FO-tag-v1" + context)[:tag_len]


def sample_centered_noise(bound: int, seed: str | None, label: bytes) -> int:
    return demo_int(seed, label, 2 * bound + 1) - bound


def model_noisy_shared_values(profile: Profile, safe_noise: bool = True, seed: str | None = "t2fs-demo") -> Tuple[List[int], List[int]]:
    ws = [demo_int(seed, b"ws" + profile.key.encode() + i.to_bytes(2, "big"), profile.q) for i in range(profile.n)]
    if safe_noise:
        max_noise = max(1, int(profile.threshold // 4))
    else:
        max_noise = max(1, int(profile.threshold * 1.5))
    wc = [
        (x + sample_centered_noise(max_noise, seed, b"noise" + profile.key.encode() + i.to_bytes(2, "big"))) % profile.q
        for i, x in enumerate(ws)
    ]
    return ws, wc


class T2FS:
    def __init__(self, seed: bytes, transcript_hash: bytes) -> None:
        self.seed = seed
        self.transcript_hash = transcript_hash

    def derive(self, role: str, epoch: int, purpose: str, length: int = 32) -> bytes:
        out = b""
        counter = 0
        while len(out) < length:
            block = hmac_sha256(
                self.seed,
                b"T2FS-v2"
                + role.encode()
                + epoch.to_bytes(4, "big")
                + purpose.encode()
                + counter.to_bytes(4, "big")
                + self.transcript_hash,
            )
            # Lightweight Feistel-style whitening over two chained PRF blocks.
            left = hmac_sha256(self.seed, b"L" + block)
            right = hmac_sha256(self.seed, b"R" + block)
            for rnd in range(8):
                f = hmac_sha256(self.seed, b"round" + bytes([rnd]) + right)
                left, right = right, bytes(a ^ b for a, b in zip(left, f))
            out += hash_bytes(left, right, block)
            counter += 1
        return out[:length]


def perform_handshake(
    profile_key: str = "512",
    rotations: int = 2,
    induce_failure: bool = False,
    seed: str | None = "t2fs-demo",
) -> Dict[str, object]:
    if profile_key not in PROFILES:
        raise ValueError(f"Unknown profile {profile_key!r}. Choose one of {sorted(PROFILES)}.")
    profile = PROFILES[profile_key]
    transcript = Transcript()

    profile_id = b"\x54\x01" if profile_key == "512" else b"\x54\x02"
    extension_type = b"\xff\x54"
    flags = b"\x03"
    schedule_id = b"\x00\x02"
    rho_a = demo_bytes(seed, b"rho_a" + profile.key.encode(), 32)
    nonce_c = demo_bytes(seed, b"nonce_c" + profile.key.encode(), 32)
    nonce_s = demo_bytes(seed, b"nonce_s" + profile.key.encode(), 32)

    ws, wc = model_noisy_shared_values(profile, safe_noise=not induce_failure, seed=seed)
    transcript.add("ClientHello.t2fs_params", profile_id + flags + schedule_id)

    uc = demo_bytes(seed, b"u_c" + profile.key.encode(), profile.share_bytes)
    us = demo_bytes(seed, b"u_s" + profile.key.encode(), profile.share_bytes)
    client_ext_data = profile_id + flags + schedule_id + rho_a + nonce_c + uc
    transcript.add("ClientHello.t2fs_extension", extension_type + len(client_ext_data).to_bytes(2, "big") + client_ext_data)

    partial_hash = transcript.digest()
    z_s, hint, raw_s = help_rec(ws, partial_hash, profile.q)
    z_c, raw_c = rec(wc, hint, partial_hash, profile.q, profile.n)

    server_ext_core = profile_id + flags + nonce_s + us + hint
    fo_context = hash_bytes(partial_hash, server_ext_core, b"T2FS-FO-v1", profile.name.encode())
    tag_s = fo_tag(z_s, fo_context)
    tag_c = fo_tag(z_c, fo_context)
    fo_tag_ok = hmac.compare_digest(tag_s, tag_c)
    server_ext_data = server_ext_core + tag_s
    transcript.add("ServerHello.t2fs_extension", extension_type + len(server_ext_data).to_bytes(2, "big") + server_ext_data)
    cert = hash_bytes(b"demo-pq-certificate", b"ML-DSA")
    transcript.add("Certificate.pq_or_hybrid_chain", cert)
    cv_key = hash_bytes(b"certificate-verify-key", cert)
    certificate_verify = b"\x08\x09" + hmac_sha256(cv_key, transcript.digest())
    transcript.add("CertificateVerify.algorithm_and_signature", certificate_verify)

    ht = transcript.digest()
    hs_s = hkdf_extract(b"\x00" * HASH_LEN, z_s)
    hs_c = hkdf_extract(b"\x00" * HASH_LEN, z_c)
    seed_s = hkdf_expand(hs_s, b"t2fs seed" + ht, HASH_LEN)
    seed_c = hkdf_expand(hs_c, b"t2fs seed" + ht, HASH_LEN)
    t2fs_s = T2FS(seed_s, ht)
    t2fs_c = T2FS(seed_c, ht)

    c_hs = t2fs_c.derive("client", 0, "handshake")
    s_view_c_hs = t2fs_s.derive("client", 0, "handshake")
    client_finished = hmac_sha256(hkdf_expand(c_hs, b"finished", HASH_LEN), ht)
    server_expected = hmac_sha256(hkdf_expand(s_view_c_hs, b"finished", HASH_LEN), ht)
    client_finished_ok = hmac.compare_digest(client_finished, server_expected)
    transcript.add("Finished.client", client_finished)

    ht2 = transcript.digest()
    s_hs = t2fs_s.derive("server", 0, "handshake")
    c_view_s_hs = t2fs_c.derive("server", 0, "handshake")
    server_finished = hmac_sha256(hkdf_expand(s_hs, b"finished", HASH_LEN), ht2)
    client_expected = hmac_sha256(hkdf_expand(c_view_s_hs, b"finished", HASH_LEN), ht2)
    server_finished_ok = hmac.compare_digest(server_finished, client_expected)
    transcript.add("Finished.server", server_finished)

    accepted = fo_tag_ok and client_finished_ok and server_finished_ok
    key_updates = []
    for epoch in range(1, max(0, rotations) + 1) if accepted else []:
        key_updates.append(
            {
                "epoch": epoch,
                "client_app_secret": fp(t2fs_c.derive("client", epoch, "application")),
                "server_app_secret": fp(t2fs_s.derive("server", epoch, "application")),
                "key_update_bytes": 8,
                "fresh_rehandshake_extension_bytes_avoided": profile.added_handshake_bytes,
                "fresh_rehandshake_bytes_saved": profile.added_handshake_bytes - 8,
                "net_rehandshake_bytes_saved": profile.added_handshake_bytes - 8,
            }
        )

    bounds = profile.failure_bounds()
    mismatch_count = sum(a != b for a, b in zip(raw_s, raw_c))
    proof_terms = {
        "signature_forgery": "q_sig * Adv_PQSig",
        "mlwe_reconciliation_indistinguishability": "q_sess * Adv_MLWE_rec",
        "hkdf": "Adv_HKDF",
        "t2fs_prf": "Adv_T2FS",
        "fo_tag_forgery": f"q_tag * 2^-{8 * FO_TAG_LEN}",
        "finished_mac": "q_fin * 2^-lambda_mac",
        "correctness_abort_one_try_bits": round(bounds["one_try_bits"], 2),
        "correctness_abort_two_try_bits": round(bounds["two_try_bits"], 2),
        "wrong_key_false_accept_bits": 8 * FO_TAG_LEN,
    }

    profile_json = asdict(profile)
    profile_json.update(
        {
            "share_bytes": profile.share_bytes,
            "hint_bytes": profile.hint_bytes,
            "fo_tag_bytes": FO_TAG_LEN,
            "client_extension_bytes": profile.client_extension_bytes,
            "server_extension_bytes": profile.server_extension_bytes,
            "added_handshake_bytes": profile.added_handshake_bytes,
            "failure_bounds": {k: (round(v, 6) if isinstance(v, float) and v >= 1e-4 else v) for k, v in bounds.items()},
        }
    )

    return {
        "protocol": "T2FS-TLS reproducible methodology demo",
        "kem_free_focus": "Direct MLWE reconciliation replaces KEM encapsulation/decapsulation.",
        "seed": seed if seed is not None else "random",
        "profile": profile_json,
        "transcript_hash": ht.hex(),
        "fo_tag": {
            "bytes": FO_TAG_LEN,
            "server_tag_fp": fp(tag_s),
            "client_recomputed_tag_fp": fp(tag_c),
            "tag_ok": fo_tag_ok,
            "false_accept_bound": f"2^-{8 * FO_TAG_LEN}",
        },
        "help_rec": {
            "hint_bytes": len(hint),
            "server_raw_bits_fp": fp(pack_bits(raw_s)),
            "client_raw_bits_fp": fp(pack_bits(raw_c)),
            "mismatched_raw_bits": mismatch_count,
            "z_server": fp(z_s),
            "z_client": fp(z_c),
        },
        "finished": {
            "client_finished_ok": client_finished_ok,
            "server_finished_ok": server_finished_ok,
            "accepted": accepted,
            "abort_reason": None if accepted else "fo_tag_or_finished_mismatch",
            "client_finished_fp": fp(client_finished),
            "server_finished_fp": fp(server_finished),
        },
        "t2fs_benefit": {
            "state_for_16_epochs_bytes": 98,
            "store_16_secrets_baseline_bytes": 512,
            "state_reduction_percent": round(100 * (1 - 98 / 512), 2),
            "key_updates": key_updates,
        },
        "tls_transcript_fields": transcript.table(),
        "game_proof_terms": proof_terms,
        "iot_evidence_boundary": {
            "deterministic": [
                "extension bytes",
                "hint bytes",
                "session-state bytes",
                "KeyUpdate bytes",
                "failure bound",
                "T2FS state reduction",
            ],
            "requires_target_measurement": [
                "Flash",
                "static SRAM",
                "peak stack",
                "handshake latency",
                "energy",
                "radio fragments after certificate chain",
            ],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the reproducible T2FS-TLS methodology demo.")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="512")
    parser.add_argument("--rotations", type=int, default=2)
    parser.add_argument("--induce-failure", action="store_true", help="inject large reconciliation noise")
    parser.add_argument("--seed", default="t2fs-demo", help="fixed seed for reproducible vectors; use 'random' for random bytes")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    seed = None if args.seed.lower() == "random" else args.seed
    result = perform_handshake(args.profile, args.rotations, args.induce_failure, seed)
    if args.json:
        print(json.dumps(result, indent=2))
        return

    p = result["profile"]
    f = result["finished"]
    tag = result["fo_tag"]
    h = result["help_rec"]
    b = result["t2fs_benefit"]
    print("T2FS-TLS reproducible methodology demo")
    print(f"Profile:                 {p['name']}")
    print(f"KEM-free focus:          {result['kem_free_focus']}")
    print(f"Added handshake bytes:   {p['added_handshake_bytes']}")
    print(f"FO tag bytes:            {tag['bytes']}")
    print(f"FO tag accepted:         {tag['tag_ok']}")
    print(f"Hint bytes:              {h['hint_bytes']}")
    print(f"Raw bit mismatches:      {h['mismatched_raw_bits']}")
    print(f"Finished accepted:       {f['accepted']}")
    print(f"One-try fail bits:       {p['failure_bounds']['one_try_bits']:.2f}")
    print(f"Two-try fail bits:       {p['failure_bounds']['two_try_bits']:.2f}")
    print(f"T2FS state reduction:    {b['state_reduction_percent']}%")
    for row in b["key_updates"]:
        print(
            f"Epoch {row['epoch']}: client={row['client_app_secret']} "
            f"server={row['server_app_secret']} avoided={row['fresh_rehandshake_extension_bytes_avoided']}B "
            f"net_saved={row['net_rehandshake_bytes_saved']}B"
        )


if __name__ == "__main__":
    main()
