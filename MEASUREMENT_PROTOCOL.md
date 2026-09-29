# Hardware Measurement Protocol

Use the same certificate chain, cipher suite policy, network mode, and request
workload for all protocols on a given target.

## Resource Footprint

Record one row in `input_logs/resource_logs.csv` per target, stack, and protocol.

- `flash_bytes`: code plus constants. For ELF firmware, use `text + data`.
- `static_sram_bytes`: initialized data plus BSS. For ELF firmware, use `data + bss`.
- `peak_stack_bytes`: stack watermark or high-water mark.
- `heap_mode`: `none`, `static`, or `dynamic`.
- `heap_peak_bytes`: peak heap when a heap is used.

Suggested commands:

```bash
arm-none-eabi-size firmware.elf
size firmware.elf
```

For ESP32, use:

```bash
idf.py size
idf.py size-json
```

For nRF52840/Contiki-NG, report the firmware map and stack watermark.

## Handshake Latency

Record at least 100 handshakes per target and protocol in
`input_logs/handshake_logs.csv`.

Columns:

```text
device,stack,protocol,trial,latency_ms,success
```

Protocols:

- TLS 1.3 ECDHE
- ML-KEM-512-TLS
- Hybrid TLS
- OQS-TLS
- KEMTLS
- T2FS-TLS

## Energy

Record at least 100 handshakes per target and protocol in
`input_logs/energy_logs.csv`.

Columns:

```text
device,stack,protocol,trial,energy_mj
```

Use a board power monitor or an external power analyzer. Report idle-subtracted
energy when possible.

## End-to-End Network Performance

Record end-to-end application performance in `input_logs/network_logs.csv`.

Columns:

```text
device,stack,protocol,trial,e2e_latency_ms,throughput_kbps,packet_loss_percent
```

Use the same payload size, request count, radio configuration, and network path
for all protocols.

## Attack Validation

Record each attack run in `input_logs/attack_logs.csv`.

Columns:

```text
device,stack,protocol,attack,trial,observed_abort_stage,accepted
```

Attack names:

- `replay`
- `tamper`
- `wrong_hint`
- `wrong_fo_tag`
- `finished_mismatch`

Abort stages:

- `transcript_replay_cache`
- `fo_tag`
- `finished`
- `parser`
- `certificate_verify`
