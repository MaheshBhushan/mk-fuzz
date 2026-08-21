#!/usr/bin/env bash
# Fetch cJSON's source, for the same reason as fetch-zlib.sh: the fuzz target
# needs the library compiled WITH coverage instrumentation, not linked as an
# opaque uninstrumented blob.
set -euo pipefail
cd "$(dirname "$0")"
VER=1.7.18
[ -f cjson/cJSON.c ] && { echo "third_party/cjson already present"; exit 0; }
URL="https://github.com/DaveGamble/cJSON/archive/refs/tags/v${VER}.tar.gz"
echo "fetching ${URL}"
curl -sSL -m 120 -o cjson.tar.gz "$URL"
tar xzf cjson.tar.gz
mkdir -p cjson
cp "cJSON-${VER}/cJSON.c" "cJSON-${VER}/cJSON.h" cjson/
rm -rf "cJSON-${VER}" cjson.tar.gz
echo "third_party/cjson ready"
