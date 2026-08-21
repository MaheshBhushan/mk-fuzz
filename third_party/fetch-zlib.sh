#!/usr/bin/env bash
# Fetch zlib's source so the fuzz target can be built WITH coverage
# instrumentation.
#
# Why this exists: the original zlib target linked the system -lz, which is not
# instrumented, so trace-pc-guard only ever saw the 8 edges inside the harness
# file itself. Coverage sat flat at 8 for the whole run and the "real library"
# target measured nothing. Compiling zlib's inflate path from source alongside
# the harness is the fix.
set -euo pipefail
cd "$(dirname "$0")"
VER=1.3.1
[ -f zlib/inflate.c ] && { echo "third_party/zlib already present"; exit 0; }
URL="https://github.com/madler/zlib/archive/refs/tags/v${VER}.tar.gz"
echo "fetching ${URL}"
curl -sSL -m 120 -o zlib.tar.gz "$URL"
tar xzf zlib.tar.gz
rm -rf zlib && mv "zlib-${VER}" zlib && rm -f zlib.tar.gz
echo "third_party/zlib ready"
