#!/bin/bash
# run_matrix.sh - run the performance matrix from a controller (either Pi or your PC with ssh keys).
#
#   PUB=pi@192.168.31.127 SUB=pi@192.168.31.89 bash scripts/run_matrix.sh
#
# For RUNS repetitions it runs every scheme once per repetition, in a shuffled
# order each time (so thermal drift / background load hits all schemes equally),
# each time: start subscriber, start publisher, wait, fetch the two CSV files.
# Nothing is typed in by hand: scripts/analyze.py builds every table from the CSVs.
#
# Settings (environment variables, defaults in brackets):
#   PUB, SUB          ssh targets                         [pi@192.168.31.127, pi@192.168.31.89]
#   PUB_IF, SUB_IF    interface names                     [eth0, eth0]
#   REMOTE            project dir on the Pis              [~/goose-banerjee]
#   RUNS              repetitions                         [5]
#   COUNT, WARMUP     measured / warm-up frames           [50000, 1000]
#   BURST             frames per state (stNum change)     [8]
#   DATASET           example | bool | four               [example]
#   GAP               inter-frame gap in microseconds     [100]
#   SCHEMES           which schemes                       [none banerjee]
#   EXPECT_NONE       expected unsecured frame size       [202]  (Banerjee Table II)
#   EXPECT_SEC        expected secured frame size         [261]  (Banerjee Table II, Ascon-AEAD)
#   IV_LEN            16 or 20 (extension size 55/59)     [20]   (20 reproduces the 261-byte frame
#                                                          if the base frame is 202 bytes)
set -u
PUB=${PUB:-pi@192.168.31.127}
SUB=${SUB:-pi@192.168.31.89}
PUB_IF=${PUB_IF:-eth0}
SUB_IF=${SUB_IF:-eth0}
REMOTE=${REMOTE:-'~/goose-banerjee'}
RUNS=${RUNS:-5}
COUNT=${COUNT:-50000}
WARMUP=${WARMUP:-1000}
BURST=${BURST:-8}
DATASET=${DATASET:-example}
GAP=${GAP:-100}
SCHEMES=${SCHEMES:-"none banerjee"}
EXPECT_NONE=${EXPECT_NONE:-202}
EXPECT_SEC=${EXPECT_SEC:-261}
IV_LEN=${IV_LEN:-20}

TAG=${TAG:-$(date +%Y%m%d-%H%M%S)}
OUT="results/$TAG"
mkdir -p "$OUT"
SSHO="-o BatchMode=yes -o ConnectTimeout=8"

echo "== results -> $OUT"
for who in PUB SUB; do
    host=${!who}
    echo "== environment of $who ($host)"
    ssh $SSHO "$host" 'bash -s' > "$OUT/meta_${who,,}.txt" <<'EOS'
echo "host: $(hostname)"; echo "model: $(tr -d '\0' < /proc/device-tree/model 2>/dev/null)"
echo "kernel: $(uname -r)"; echo "os: $(. /etc/os-release && echo $PRETTY_NAME)"
echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null)"
echo "arm_freq_hz: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null)"
echo "temp: $(vcgencmd measure_temp 2>/dev/null)"
echo "throttled: $(vcgencmd get_throttled 2>/dev/null)"
echo "nic: $(ethtool -i eth0 2>/dev/null | head -3 | tr '\n' ' ')"
echo "ptp: $(ethtool -T eth0 2>/dev/null | grep -i 'PTP Hardware Clock')"
[ -f ~/goose-banerjee/versions.txt ] && cat ~/goose-banerjee/versions.txt
EOS
    # fixed CPU frequency behaviour for the whole experiment
    ssh $SSHO "$host" 'echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null' || echo "  (could not set governor on $who)"
done

for run in $(seq 1 "$RUNS"); do
    for s in $(echo $SCHEMES | tr ' ' '\n' | shuf); do
        tagf="perf_${s}_r${run}"
        echo "== run $run  scheme=$s"
        envs="GOOSE_SCHEME=$s GOOSE_IV_LEN=$IV_LEN"
        exp=$EXPECT_SEC; [ "$s" = none ] && exp=$EXPECT_NONE

        ssh $SSHO "$SUB" "cd $REMOTE && mkdir -p results && sudo -E env $envs ./build/gs_sub $SUB_IF \
            --count $COUNT --warmup $WARMUP --idle-timeout 6 --out results/$tagf.sub.csv" \
            > "$OUT/$tagf.sub.log" 2>&1 &
        subjob=$!
        sleep 3
        ssh $SSHO "$PUB" "cd $REMOTE && mkdir -p results && sudo -E env $envs ./build/gs_pub $PUB_IF \
            --count $((COUNT + 300)) --warmup $WARMUP --gap-us $GAP --burst $BURST --dataset $DATASET \
            --expect-size $exp --out results/$tagf.pub.csv" \
            > "$OUT/$tagf.pub.log" 2>&1
        wait $subjob
        scp -q $SSHO "$SUB:$REMOTE/results/$tagf.sub.csv" "$OUT/" || echo "  !! subscriber CSV missing"
        scp -q $SSHO "$PUB:$REMOTE/results/$tagf.pub.csv" "$OUT/" || echo "  !! publisher CSV missing"
        grep -h "first frame" "$OUT/$tagf.pub.log" || true
        grep -h "delivered=" "$OUT/$tagf.sub.log" || true
        sleep 2
    done
done

echo "== cipher micro-benchmarks (pure Ascon cost per variant)"
for who in PUB SUB; do
    host=${!who}
    for v in asconaead128 ascon128 ascon128a; do
        ssh $SSHO "$host" "cd $REMOTE && [ -x build/ascon_bench_$v ] && ./build/ascon_bench_$v 100000" \
            > "$OUT/bench_${who,,}_$v.txt" 2>/dev/null || rm -f "$OUT/bench_${who,,}_$v.txt"
    done
done

echo "== analysing"
python3 scripts/analyze.py "$OUT"
echo "done: $OUT/results.md"
