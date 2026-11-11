> **About this repository.** Raspberry Pi 4 Model B test harness for a *reproduction* of the scheme of
> A. Banerjee and U. Banerjee, "Securing IEC 61850 with Ascon lightweight authenticated encryption: A case study,"
> *IEEE Future Networks World Forum (FNWF)*, 2025, DOI 10.1109/FNWF66845.2025.11317357, built on libIEC61850 v1.5.3.
> Details that the original paper does not specify (nonce construction, replay handling, exact extension layout,
> example data set) are **assumptions**; they are listed in the table below. This is not the original authors' code.
> The proposed scheme and its measurements are in the companion repository
> https://github.com/polepakamo/goose-ascon-proposed-pi4
>
> **License.** GPL-3.0-or-later (two files are modified copies of libIEC61850 files); see `LICENSE` and `NOTICE.md`.
>
> **Reproducibility.** `setup.sh` clones libIEC61850 tag `v1.5.3` and ascon-c and writes the exact commits to
> `versions.txt`. Quote that file when citing results.

---

# Banerjee & Banerjee GOOSE scheme on Raspberry Pi 4 Model B (baseline only)

Step 1 of 2. This code base implements **only** the Banerjee & Banerjee scheme
("Securing IEC 61850 with Ascon Lightweight Authenticated Encryption: A Case Study",
IEEE FNWF 2025) **as their paper describes it**, plus the unsecured libIEC61850 run as a
reference. Our own scheme is deliberately not in here; it is added later as a separate step
(a copy of an earlier combined draft is kept outside this folder in `../proposed-scheme-later/`
and is not built or used).

```
lib/goose_sec.[ch]      scheme switch (none | banerjee), baseline nonce, IEC 62351-6 extension, receive log.
                        Pure C, unit-tested on a PC.
lib/goose_publisher.c   drop-in for libIEC61850 v1.5.3 goose_publisher.c  (Banerjee applied in publish())
lib/goose_receiver.c    drop-in for libIEC61850 v1.5.3 goose_receiver.c   (Banerjee applied in parseGooseMessage())
src/gs_pub.c            publisher (times publish() from outside, per-frame CSV)
src/gs_sub.c            subscriber (threaded GooseReceiver_start, per-frame CSV)
src/gs_inject.c         on-wire attacker: replay / forge / flood
src/ascon_bench.c       pure cipher cost, built per Ascon variant
scripts/run_matrix.sh   performance matrix (shuffled order, repeated runs)
scripts/run_security.sh measured replay / forgery / flood tests on the baseline
scripts/analyze.py      CSVs -> results.md / results.json / figure   (no numbers typed by hand)
tests/test_sec.c        unit tests          tests/test_collision.c   real-cipher nonce demo
tests/make_fake_results.py   synthetic CSVs to test analyze.py
```

## What the paper specifies, and what is assumed

| item | source |
|---|---|
| libIEC61850 sample publisher/subscriber, Raspberry Pi test platform | paper, Sec. III |
| security extension: Authentication Value (version, time of current key, time of next key, **Initialization Vector**, key id) + MAC | paper, Fig. 3 |
| the **entire PDU** is encrypted, tag goes in the MAC field | paper, Sec. V-A |
| AAD = EtherType, AppID, Length, Reserved1, Reserved2, Authentication Value | paper, Fig. 5 |
| subscriber **decrypts the PDU before parsing** | paper, Sec. V-B |
| Ascon-AEAD per NIST SP 800-232, 128-bit key and tag, official ascon-c library | paper, Sec. II-III |
| frame sizes: 202 B unsecured, 261 B with Ascon-AEAD; T_tx 16.16 / 20.88 us at 100 Mbit/s | paper, Tables I and II |
| **nonce construction** | **not specified - ASSUMED**: BER(stNum) BER(sqNum) timestamp, zero padded to 16 B, carried in the IV field |
| **replay handling** | **not specified - ASSUMED: nothing beyond the stock library**: stock v1.5.3 flags a non-increasing sqNum as `isValid=false` but still delivers the frame (kept unchanged); no cryptographic replay protection. `GOOSE_BANERJEE_REPLAY=strict` adds a *same-state* sqNum == last+1 drop, only for the security tests: it compares sqNum only when the stNum equals the last one, so it does NOT stop replays of frames from older states (measured: 177 of 200 replays accepted) |
| exact extension byte layout (55 or 59 B) | **not specified**; `GOOSE_IV_LEN=20` gives 59 B so that 202 + 59 = 261 |
| dataset / GOOSE names of the "sample" message | **not specified**; must be tuned until the unsecured frame is 202 B |

Anything in the second half of this table must be written in the paper as an assumption.
Do **not** present the assumed nonce or the absent replay filter as flaws of their code.

## Paper reference values (Raspberry Pi 5 - context only, never to be compared with Pi 4B numbers)

| row | frame B | T_gen | T_tx | T_proc | T_E2E |
|---|---|---|---|---|---|
| GOOSE, no security | 202 | 26.68 | 16.16 | 5.52 | 48.36 |
| GOOSE, Ascon-AEAD | 261 | 40.74 | 20.88 | 22.53 | 84.15 |

(microseconds; the AEAD row sums correctly: 40.74 + 20.88 + 22.53 = 84.15)
What a faithful reproduction can be expected to match: the **frame sizes and T_tx**, and the
**shape** (T_proc several times larger than unsecured, T_gen about +14 us). Absolute times on a
Pi 4B differ and must not be forced to match.

## Timing definitions
* **T_gen** - wall time of `GoosePublisher_publish()` as seen from `gs_pub` (encode, encrypt, extension, sendto). `increaseStNum()` is timed separately and excluded.
* **T_tx** - `frame_bytes * 8 / 100 Mbit/s`, **calculated**: the Pi 4B NIC has no hardware timestamping (the paper also computes it from the frame size).
* **T_proc** - from right after `select()` returns to right after the subscriber callback returns, per frame, via a lock-free ring (no polling, no lost frames).
* **T_E2E** = mean T_gen + mean T_tx + mean T_proc: three means from two hosts with unsynchronised clocks; not a measured one-way delay.
* Run-to-run spread is taken over per-run means (5 runs), never over pooled frames.

## Step by step
```bash
# on EACH Pi (Raspberry Pi OS 64-bit)
cd goose-banerjee
bash setup.sh      # libIEC61850 v1.5.3, ascon-c, versions.txt
bash build.sh      # unit tests, collision demo, all binaries

# 1. fidelity checks BEFORE any measurement
sudo GOOSE_SCHEME=none ./build/gs_pub eth0 --count 10 --warmup 0 --expect-size 202
sudo GOOSE_SCHEME=banerjee GOOSE_IV_LEN=20 ./build/gs_pub eth0 --count 10 --warmup 0 --expect-size 261
#   unsecured frame != 202 B  -> adjust --cbref/--datset/--goid/--dataset until it is
#   secured frame != 261 B    -> report the size you got and why
# (the unsecured frame is predicted to be 202 B with the defaults: 26 B header + 176 B PDU, see 'Verified against the real sources')
# sanity: start gs_sub on the other Pi; GOOSE_SCHEME=banerjee must show delivered ~ frames sent, rej_auth=0

# 2. pure cipher cost (does the Ascon variant matter?)
./build/ascon_bench_asconaead128 ; ./build/ascon_bench_ascon128 ; ./build/ascon_bench_ascon128a

# 3. performance matrix, 5 shuffled runs per scheme
PUB=pi@192.168.31.127 SUB=pi@192.168.31.89 RUNS=5 bash scripts/run_matrix.sh
#    -> results/<tag>/results.md, results.json, latency_stages.png

# 4. measured behaviour of the baseline under replay / forgery / flood
PUB=... SUB=... bash scripts/run_security.sh
```

## Verified against the real sources (done from the public repositories, nothing compiled)
* **libIEC61850 v1.5.3** (`mz-automation/libiec61850`, tag v1.5.3): the public API used by `gs_pub`/`gs_sub` matches the headers (`GoosePublisher_*` signatures, `GooseSubscriber_create(char*, MmsValue*)`, `setAppId(uint16_t)`, `setListener`, `GooseSubscriber_isValid`). The internal headers the patched files include (`ber_decode.h`, `ber_encoder.h`, `mms_value_internal.h`, `mms_server_internal.h`) live in `src/mms/inc_private`, which `build.sh` passes with `-I`. `goose_receiver_internal.h` is in `src/goose`.
* **Stock receiver behaviour**: v1.5.3 `parseGoosePayload` marks `isValid = false` when `sqNum <= last` for the same `stNum` but still calls the listener. This is kept unchanged. (An earlier draft of this harness had silently replaced it; fixed.)
* **Stock vs patched files**: the stock `parseAllData` was compared with the copy used here and is equivalent. Two intentional differences: malformed frames are logged as `rej_parse` instead of silently returning, and the dispatch/timing hooks.
* **Ascon (`ascon-c`, main)**: only `crypto_aead/asconaead128` exists now (the old `ascon128`/`ascon128a` directories are gone). Its `ref/aead.c` uses 16-byte rate with 12/8-round permutations (the NIST SP 800-232 parameters), `api.h` gives key/nonce/tag = 16 B, and `CRYPTO_NOOVERLAP` is set, so input and output buffers must not overlap (they do not). `aead.c` includes `crypto_aead.h`, which exists in `ascon-c/tests/` and is copied by `setup.sh`. Implementation directory is selectable with `ASCON_IMPL` (default `ref`, the slowest; the paper does not say which was used).
* **Frame-size arithmetic**: with the defaults (goCbRef `simpleIOGenericIO/LLN0$GO$gcbAnalogValues`, datSet `simpleIOGenericIO/LLN0$AnalogValues`, goID unset so it repeats the goCbRef, confRev 1, timeAllowedToLive 500, dataset INT32 1234 / binary time / INT32 5678, VLAN tag) the PDU is 176 B and the frame 202 B, exactly the paper's Table I values. This supports the dataset guess but must still be confirmed by the `--expect-size 202` run. stNum above 127 adds a byte to the BER encoding, so long runs can show 203-204 B.

## Honest status
* TESTED on a PC: `lib/goose_sec.c` (BER nonce layout and collisions, extension build/parse, BER helpers, log ring) via `tests/test_sec.c`; `scripts/analyze.py` on synthetic CSVs; `src/gs_pub.c` / `gs_sub.c` pass a syntax check against stub headers (only the old-MinGW `clock_gettime` complaint remains).
* NOT YET COMPILED OR RUN: `lib/goose_publisher.c`, `lib/goose_receiver.c`, `src/gs_inject.c`, `src/ascon_bench.c`, the shell scripts. They need libIEC61850 and a Linux/ARM toolchain that were not available here; expect to fix header paths or typos on the first `build.sh` on the Pi. The AAD/length/extension handling of publisher and receiver is checked only by reading until the first run: the first thing to look at is that `GOOSE_SCHEME=banerjee` frames authenticate (`rej_auth=0`).
* Key provisioning (IEC 62351-9) is out of scope: a fixed FIPS 197 test key is used.
* Window/replay state for the strict option lives in the stock subscriber state (`stNum`/`sqNum` of the last frame); this is only used for the security tests.

## Next step (not started)
Add the proposed scheme as a separate change, reusing the same publisher/subscriber apps, timing
boundaries, datasets and scripts, so that the two results come from identical infrastructure.
