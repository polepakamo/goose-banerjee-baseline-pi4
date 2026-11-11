# Banerjee-style baseline on Raspberry Pi 4 Model B - recorded results

Everything below is copied from the analysis output of two measurement runs. Nothing is retyped from memory. Raw data: `results/20261018-180636/` (performance) and `results/sec-20261018-181211/` (security), copied to `results-banerjee-all/`.

## Setup (confirm against `meta_pub.txt` / `meta_sub.txt` in the performance folder)
* Two Raspberry Pi 4 Model B boards, publisher 192.168.31.127, subscriber 192.168.31.89, wired through a home router, 100 Mbit/s link.
* libIEC61850 v1.5.3 with patched `goose_publisher.c` / `goose_receiver.c`; Ascon-AEAD128 (NIST SP 800-232) from ascon-c, `ref` implementation, `-O2`.
* Dataset: libIEC61850 example (INT32 1234, binary time, INT32 5678), goID unset. 8 frames per state, 100 us nominal gap, 1,000 warm-up + 50,000 measured frames per run, 5 runs per scheme in shuffled order, CPU governor `performance` (set by `run_matrix.sh`).
* Extension: 20-byte IV field (59-byte extension), which gives the paper's 261-byte frame.

## What is the paper's and what is assumed
Nonce construction (BER(stNum) BER(sqNum) timestamp, zero padded) and replay handling (stock library only) are **assumptions**; the paper specifies neither. The baseline is "built after the description in Banerjee and Banerjee (FNWF 2025)", not their code.

## Performance (microseconds, mean of the five per-run means)

| scheme | frame B | T_gen | T_tx (calc.) | T_proc | T_E2E | T_E2E run-to-run std |
|---|---|---|---|---|---|---|
| none | 203 | 5.765 | 16.240 | 2.992 | 24.997 | 0.029 |
| banerjee | 262 | 8.686 | 20.960 | 5.570 | 35.215 | 0.029 |

Paired difference banerjee - none: T_gen +2.921, T_tx +4.720, T_proc +2.578, **T_E2E +10.219** (95% CI half-width 0.017); all significant over 5 runs.

Per-run T_E2E: none 25.003, 25.014, 24.971, 25.032, 24.962; banerjee 35.224, 35.217, 35.211, 35.253, 35.172.
Per-run T_proc p99: none 3.80-3.85, banerjee 6.43-6.54.

Notes for the paper
* Frame sizes are 203/262 B, one byte above the 202/261 B of the paper's Tables, because BER encodes stNum >= 128 in two bytes and a run reaches stNum ~6,300. The first frames were exactly 202/261 B (checked with `--expect-size`).
* T_tx is calculated from frame size at 100 Mbit/s; the Pi 4B NIC has no hardware timestamping.
* T_E2E is the sum of three means from two hosts with unsynchronised clocks, not a measured one-way delay.
* Frame loss: at most 300 of 51,300 per run (the subscriber stops at 51,000 delivered); the security runs show loss concentrated in the first 20-40 frames of a run, which the warm-up discards.

## Paper values for context (Raspberry Pi 5; do not compare directly)
none 202 B: T_gen 26.68, T_tx 16.16, T_proc 5.52, T_E2E 48.36. Ascon-AEAD 261 B: T_gen 40.74, T_tx 20.88, T_proc 22.53, T_E2E 84.15.
Our Ascon overhead (+2.9 T_gen, +2.6 T_proc) is far smaller than theirs (+14, +17). The cipher benchmark below shows why it cannot be our code being slow: Ascon takes 1.9 us for the 176-byte PDU. Their Fig. 6 reads roughly 28 us at 1,024 bytes against our 8 us; the cause (compiler flags, implementation, measurement boundaries) is unknown. Do not claim a cause without testing (`-O0` build of `ascon_bench` is the obvious test).

## Pure cipher cost, Ascon-AEAD128 `ref`, `-O2`, Pi 4B (median ns)

| bytes | encrypt | decrypt |
|---|---|---|
| 5 | 704 | 741 |
| 20 | 815 | 852 |
| 40 | 963 | 981 |
| 176 | 1945 | 1926 |
| 245 | 2426 | 2389 |
| 512 | 4333 | 4204 |
| 1024 | 7982 | 7704 |

## Security tests on the baseline (measured)

| scenario | config | published | delivered (all) | distinct frames delivered | replays accepted | legit frames lost | rej auth | rej replay | cost of replay reject (us) | cost of auth reject (us) |
|---|---|---|---|---|---|---|---|---|---|---|
| flood | banerjee-strict | 20000 | 23642 | 19991 | 3651 | 9 | 0 | 303537 | 5.204 | n/a |
| flood | banerjee | 20000 | 323505 | 19988 | 303517 | 12 | 0 | 0 | n/a | n/a |
| forge | banerjee-strict | 2000 | 1990 | 1990 | 0 | 10 | 200 | 0 | n/a | 4.559 |
| forge | banerjee | 2000 | 1992 | 1992 | 0 | 8 | 200 | 0 | n/a | 4.580 |
| replay | banerjee-strict | 2000 | 2177 | 2000 | 177 | 0 | 0 | 0 | n/a | n/a |
| replay | banerjee | 2000 | 2185 | 2000 | 185 | 0 | 0 | 0 | n/a | n/a |

Flood injector logs: baseline run sent 303,517 frames in 8.0 s (37,940 pps); strict run sent 307,188 (38,398 pps). Accepted + rejected = sent in both runs.

Findings
1. **Forgery**: all 200 bit-flipped frames rejected by the Ascon tag in both configurations (about 4.6 us each).
2. **Replay**: a frame replayed from an earlier state is accepted by the baseline and also by the "strict" option. "Strict" is only a same-state filter (`sqNum != last + 1` is checked only when stNum equals the last stNum), so it does not stop cross-state replays. The "replays accepted" of 185/177 are 200 minus the 15/23 originals lost at stream start (those replays were first deliveries; distinct frames delivered is 2000 in both runs).
3. **Flood**: the baseline decrypts and parses before it rejects, so a rejected replay costs 5.2 us against 5.57 us for a delivered frame. At about 38,000 frames/s this is roughly 20-21% of one core (my estimate from these figures; includes the receive call), about a quarter at the 100 Mbit/s line rate (~44,500 frames/s). Legitimate frames lost during the flood (9-12 of 20,000) are no worse than in quiet runs. No overload on a Pi 4B.

## Not yet done
* The `-O0` cipher test, a direct-cable run (to remove the router), `ASCON_IMPL=opt64`, the dataset `bool` run (single boolean), and everything about the proposed scheme.
