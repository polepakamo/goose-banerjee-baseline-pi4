#!/bin/bash
# setup.sh - one-time setup on EACH Raspberry Pi 4 Model B (Raspberry Pi OS, 64-bit).
#   bash setup.sh
# Installs build tools, builds stock libIEC61850 v1.5.3 (static) and fetches the
# Ascon reference implementations. Records the exact versions in versions.txt.
set -e
cd "$(dirname "$0")"
H="$(pwd)"

echo "[1/3] system packages"
sudo apt-get update -qq
sudo apt-get install -y build-essential cmake git python3 linuxptp ethtool

echo "[2/3] libIEC61850 v1.5.3"
if [ ! -d libiec61850 ]; then
    git clone --branch v1.5.3 --depth 1 https://github.com/mz-automation/libiec61850.git
fi
( cd libiec61850 && mkdir -p build && cd build &&
  cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_EXAMPLES=OFF -DBUILD_TESTS=OFF &&
  make -j"$(nproc)" && sudo make install && sudo ldconfig )

echo "[3/3] Ascon (ascon-c)"
# ASCON_IMPL selects the implementation directory inside crypto_aead/asconaead128/ (default: ref).
# The paper only says "official ascon-c library", so the implementation is a choice that changes
# absolute timings a lot (ref is the slowest). Record it; use the same one for every scheme.
IMPL="${ASCON_IMPL:-ref}"
if [ ! -d ascon-c ]; then
    git clone --depth 1 https://github.com/ascon/ascon-c.git
fi
mkdir -p third_party/ascon
for v in asconaead128 ascon128 ascon128a; do
    src="ascon-c/crypto_aead/$v/$IMPL"
    if [ -d "$src" ]; then
        rm -rf "third_party/ascon/$v"
        mkdir -p "third_party/ascon/$v"
        cp "$src"/* "third_party/ascon/$v"/
        # aead.c includes crypto_aead.h, which lives in tests/
        cp ascon-c/tests/crypto_aead.h "third_party/ascon/$v"/
        echo "  variant $v ($IMPL): ok"
    else
        echo "  variant $v ($IMPL): not in this ascon-c checkout (skipped)"
    fi
done
[ -d third_party/ascon/asconaead128 ] || { echo "ERROR: asconaead128/$IMPL (NIST SP 800-232 Ascon-AEAD128) not found"; ls ascon-c/crypto_aead; exit 1; }
# NOTE: on ascon-c main only asconaead128 exists; the legacy ascon128 / ascon128a directories were
# removed. To benchmark them, check out an older ascon-c tag by hand and rerun this step.

{
  echo "date: $(date -u +%FT%TZ)"
  echo "libiec61850: $(cd libiec61850 && git describe --tags --always 2>/dev/null)  $(cd libiec61850 && git rev-parse HEAD)"
  echo "ascon-c:     $(cd ascon-c && git rev-parse HEAD)  impl=$IMPL"
  echo "gcc:         $(gcc --version | head -1)"
  echo "kernel:      $(uname -r)"
  echo "os:          $(. /etc/os-release && echo "$PRETTY_NAME")"
} | tee versions.txt
echo "setup done. Next: bash build.sh"
