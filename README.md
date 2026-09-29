# T2FS-TLS Reproducible Methodology

This package contains a methodology-focused revision of T2FS-TLS.

## Contents

- `t2fs_tls_reproducible_methodology.tex`: LaTeX source.
- `references.bib`: BibTeX references.
- `t2fs_tls_reproducible_demo.py`: Python reference demo for HelpRec/Rec, byte accounting, failure bounds, Finished verification, and T2FS benefits.
- `app.py`: local white-background Times New Roman interface.

## Main corrections

- KEM-free innovation is explicit: direct MLWE reconciliation replaces KEM encapsulation and decapsulation.
- MLWE is the only lattice assumption; RLWE is not mixed into the protocol.
- `HelpRec/Rec` is fully specified using one public hint bit per coefficient.
- Failure probability is derived and reported for one try and one retry.
- TLS extension bytes are specified field by field: 1424 B for 512-IoT and 2064 B for 768-IoT, excluding certificate-chain bytes.
- T2FS is preserved as an IoT lifecycle layer for epoch state, revocation, and bounded reconstruction.
- IoT evidence is split into deterministic protocol evidence and target-dependent MCU measurements.

## Run the demo

```bash
python3 t2fs_tls_reproducible_demo.py --profile 512 --rotations 2 --json
python3 t2fs_tls_reproducible_demo.py --profile 768 --rotations 2
```

## Run the interface

```bash
python3 app.py --host 127.0.0.1 --port 8767
```

Open:

```text
http://127.0.0.1:8767
```

## Important note

The Python code is a reproducible protocol-flow and accounting model. It is not a production MLWE implementation. Production deployment must replace the model vector generator with constant-time polynomial arithmetic, a vetted sampler, and device-specific measurement logs.
