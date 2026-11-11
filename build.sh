#!/bin/bash
# build.sh - build the harness. Run on EACH Pi after setup.sh.
#   bash build.sh
# Our goose_publisher.c / goose_receiver.c / goose_sec.c are compiled and linked
# as plain object files BEFORE libiec61850.a, so they take precedence over the
# stock goose_publisher.o / goose_receiver.o inside the archive (no ar surgery).
set -e
cd "$(dirname "$0")"
H="$(pwd)"
LIB="$H/libiec61850"
SRC="$LIB/src"
ASCON="$H/third_party/ascon"
OUT="$H/build"
mkdir -p "$OUT"

# stack_config.h: use the copy cmake generated in the build tree (the one libiec61850.a was
# built with); fall back to the stock config/ copy.
STACK_CFG=""
gen="$(find "$LIB/build" -name stack_config.h 2>/dev/null | head -1)"
if [ -n "$gen" ]; then STACK_CFG="$(dirname "$gen")"
elif [ -f "$LIB/config/stack_config.h" ]; then STACK_CFG="$LIB/config"
fi
[ -n "$STACK_CFG" ] || { echo "stack_config.h not found - run setup.sh"; exit 1; }
echo "    stack_config.h from $STACK_CFG"

# libIEC61850 v1.5.3 layout: the HAL headers (hal_*.h, platform_endian.h, lib_memory.h) are in
# <repo>/hal/inc, NOT in src/; the internal MMS/BER headers are in src/mms/inc_private.
HAL="$LIB/hal"
INC="-I$STACK_CFG -I$HAL/inc -I$SRC -I$SRC/goose -I$SRC/common/inc \
 -I$SRC/mms/inc -I$SRC/mms/inc_private -I$SRC/mms/iso_mms/common -I$SRC/mms/iso_mms/server \
 -I$SRC/mms/iso_mms/asn1c -I$SRC/mms/asn1 \
 -I$SRC/iec61850/inc -I$SRC/iec61850/inc_private -I$SRC/logging"
CFLAGS="-O2 -std=gnu99 -Wall -Wno-misleading-indentation -Wno-unused-but-set-variable -DPLATFORM_LINUX -D_GNU_SOURCE"

echo "[1] unit tests (goose_sec.c, no network)"
gcc -std=c99 -Wall -Wextra -O2 -Ilib tests/test_sec.c lib/goose_sec.c -o "$OUT/test_sec"
"$OUT/test_sec"

echo "[2] Ascon-AEAD128 (NIST SP 800-232) objects"
A="$ASCON/asconaead128"
rm -f "$OUT"/ascon_*.o
for f in "$A"/*.c; do
    gcc $CFLAGS -I"$A" -c "$f" -o "$OUT/ascon_$(basename "$f" .c).o"
done

echo "[2b] nonce-collision demonstration with the real cipher"
gcc -std=gnu99 -O2 -Ilib -I"$A" tests/test_collision.c lib/goose_sec.c "$OUT"/ascon_*.o -o "$OUT/test_collision"
"$OUT/test_collision"

echo "[3] patched libIEC61850 GOOSE files + shared layer"
gcc $CFLAGS -Ilib $INC -c lib/goose_sec.c       -o "$OUT/goose_sec.o"
gcc $CFLAGS -Ilib $INC -c lib/goose_publisher.c -o "$OUT/goose_publisher.o"
gcc $CFLAGS -Ilib $INC -c lib/goose_receiver.c  -o "$OUT/goose_receiver.o"

LIBA=/usr/local/lib/libiec61850.a
[ -f "$LIBA" ] || LIBA="$(find /usr/local/lib /usr/local/lib64 /usr/lib -name libiec61850.a 2>/dev/null | head -1)"
[ -n "$LIBA" ] || { echo "libiec61850.a not found"; exit 1; }
# v1.5.3 builds the hardware abstraction layer (Memory_*, Ethernet_*, Thread_*, Hal_getTimeInMs)
# as a separate static library; libiec61850.a alone leaves those symbols undefined.
HALA="$(find /usr/local/lib /usr/local/lib64 "$LIB/build" -name libhal.a 2>/dev/null | head -1)"
[ -n "$HALA" ] || { echo "libhal.a not found - look in $LIB/build/hal and /usr/local/lib"; exit 1; }
echo "    linking $LIBA and $HALA"
OBJS="$OUT/goose_publisher.o $OUT/goose_receiver.o $OUT/goose_sec.o $OUT/ascon_*.o"

echo "[4] applications"
gcc $CFLAGS -Ilib $INC -c src/gs_pub.c -o "$OUT/gs_pub.o"
gcc $CFLAGS -Ilib $INC -c src/gs_sub.c -o "$OUT/gs_sub.o"
gcc "$OUT/gs_pub.o" $OBJS "$LIBA" "$HALA" -lpthread -lm -o "$OUT/gs_pub"
gcc "$OUT/gs_sub.o" $OBJS "$LIBA" "$HALA" -lpthread -lm -o "$OUT/gs_sub"
gcc $CFLAGS src/gs_inject.c -o "$OUT/gs_inject"

echo "[5] cipher micro-benchmarks (one binary per Ascon variant)"
for v in asconaead128 ascon128 ascon128a; do
    d="$ASCON/$v"
    [ -d "$d" ] || continue
    srcs=$(ls "$d"/*.c)
    gcc -O2 -std=gnu99 -I"$d" src/ascon_bench.c $srcs -o "$OUT/ascon_bench_$v" && echo "  built ascon_bench_$v"
done

echo "build ok -> $OUT"
echo "frame-size self-check:  sudo GOOSE_SCHEME=none ./build/gs_pub <iface> --count 10 --warmup 0 --expect-size 202"
