#!/bin/bash
# run_security.sh - measured security tests (replaces the old calculated DoS estimates).
#
#   PUB=pi@192.168.31.127 SUB=pi@192.168.31.89 bash scripts/run_security.sh
#
# The attacker (gs_inject) runs on the PUBLISHER Pi: it captures the live stream
# and re-injects it towards the subscriber. Configurations compared:
#   banerjee        baseline as described (no replay filter)
#   banerjee-strict baseline + same-state sqNum == last+1 drop (does not stop replays of older states)
#
# Scenarios:
#   replay  200 captured frames re-sent unchanged       -> measured: accepted by 'banerjee' (no filter) and also by 'banerjee-strict' (same-state filter only)
#   forge   200 frames, one ciphertext bit flipped      -> expect: all rejected (auth)
#   flood   one captured frame replayed at line rate for 8 s while the publisher keeps
#           publishing                                   -> legitimate-frame loss, reject cost
set -u
PUB=${PUB:-pi@192.168.31.127}
SUB=${SUB:-pi@192.168.31.89}
PUB_IF=${PUB_IF:-eth0}
SUB_IF=${SUB_IF:-eth0}
REMOTE=${REMOTE:-'~/goose-banerjee'}
DATASET=${DATASET:-example}
IV_LEN=${IV_LEN:-20}
TAG=${TAG:-sec-$(date +%Y%m%d-%H%M%S)}
OUT="results/$TAG"
mkdir -p "$OUT"
SSHO="-o BatchMode=yes -o ConnectTimeout=8"

run_case() {   # $1 scenario  $2 config-name  $3 GOOSE_SCHEME  $4 extra env for subscriber
    local sc=$1 cfg=$2 scheme=$3 xenv=$4
    local name="sec_${sc}_${cfg}"
    local pubcount=2000 gap=500 inj=""
    case $sc in
        replay) inj="./build/gs_inject $PUB_IF replay --n 200" ;;
        forge)  inj="./build/gs_inject $PUB_IF forge  --n 200" ;;
        flood)  pubcount=20000; inj="sleep 2; ./build/gs_inject $PUB_IF flood --secs 8" ;;
    esac
    echo "== $sc / $cfg"
    ssh $SSHO "$SUB" "cd $REMOTE && mkdir -p results && sudo -E env GOOSE_SCHEME=$scheme GOOSE_IV_LEN=$IV_LEN $xenv \
        ./build/gs_sub $SUB_IF --duration 30 --warmup 0 --out results/$name.sub.csv" > "$OUT/$name.sub.log" 2>&1 &
    local subjob=$!
    sleep 3
    ssh $SSHO "$PUB" "cd $REMOTE && mkdir -p results && ( sudo -E env GOOSE_SCHEME=$scheme GOOSE_IV_LEN=$IV_LEN bash -c '$inj' > results/$name.inj.log 2>&1 & ) ; \
        sleep 1; sudo -E env GOOSE_SCHEME=$scheme GOOSE_IV_LEN=$IV_LEN ./build/gs_pub $PUB_IF \
        --count $pubcount --warmup 0 --gap-us $gap --burst 8 --dataset $DATASET --out results/$name.pub.csv" \
        > "$OUT/$name.pub.log" 2>&1
    wait $subjob
    scp -q $SSHO "$SUB:$REMOTE/results/$name.sub.csv" "$OUT/"
    scp -q $SSHO "$PUB:$REMOTE/results/$name.pub.csv" "$PUB:$REMOTE/results/$name.inj.log" "$OUT/"
    grep -h "delivered=" "$OUT/$name.sub.log" || true
}

for sc in replay forge flood; do
    run_case $sc banerjee        banerjee ""
    run_case $sc banerjee-strict banerjee "GOOSE_BANERJEE_REPLAY=strict"
done
python3 scripts/analyze.py "$OUT"
