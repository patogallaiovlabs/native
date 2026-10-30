#!/usr/bin/env bash
# Build the secp256k1 JNI library for every platform the jar ships, from the
# unmodified upstream sources vendored under secp256k1/ plus the JNI shim in
# secp256k1/jni/, and stage the binaries where Secp256k1Loader looks for them.
#
#   ./build_secp256k1.sh            # all targets (macOS ones only on a Mac)
#   ./build_secp256k1.sh mac        # macOS arm64 + x86_64 only
#   ./build_secp256k1.sh linux      # Linux amd64 + arm64 only (needs Docker buildx)
#
# The shim is one translation unit that #includes src/secp256k1.c, so the whole
# library is compiled here with plain cc: no autotools, no CMake. The two
# precomputed-table files are the only other sources. Compile flags mirror
# upstream's defaults (ECMULT_WINDOW_SIZE 15, COMB_BLOCKS 11 / COMB_TEETH 6,
# x86_64 scalar asm on amd64).
#
# Requirements: a JDK (for javac -h), clang on macOS, Docker with buildx for Linux.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
ROOT="$PWD"
SRC="$ROOT/secp256k1"
JNI="$SRC/jni"
RES="$ROOT/src/main/resources/org/bitcoin/native"
WORK="${TMPDIR:-/tmp}/rsk-secp256k1-build"
WHAT="${1:-all}"

JDK="${JAVA_HOME:-$(/usr/libexec/java_home 2>/dev/null || dirname "$(dirname "$(readlink -f "$(command -v javac)")")")}"

DEFS="-DENABLE_MODULE_RECOVERY=1 -DENABLE_MODULE_ECDH=1"
SOURCES="jni/org_bitcoin_NativeSecp256k1.c src/precomputed_ecmult.c src/precomputed_ecmult_gen.c"
INCLUDES="-I. -Iinclude -Isrc"
WARN="-Wall -Wextra -Wno-unused-function -Wno-unused-parameter -Wno-long-long -Wno-overlength-strings"

rm -rf "$WORK"; mkdir -p "$WORK/h" "$WORK/classes"

echo "==> generating JNI headers with $JDK"
"$JDK/bin/javac" --release 8 -nowarn -h "$WORK/h" -d "$WORK/classes" \
  "$ROOT"/src/main/java/org/bitcoin/*.java 2>&1 | grep -v '^Note:' || true
cp "$WORK/h/org_bitcoin_NativeSecp256k1.h" "$WORK/h/org_bitcoin_Secp256k1Context.h" "$JNI/"

if [ "$WHAT" = all ] || [ "$WHAT" = mac ]; then
  if [ "$(uname -s)" = Darwin ]; then
    for pair in "arm64 aarch64" "x86_64 x86_64"; do
      set -- $pair; carch=$1; jarch=$2
      echo "==> macOS $jarch"
      mkdir -p "$RES/Mac/$jarch"
      ( cd "$SRC" && clang -O3 -fPIC -arch "$carch" -mmacosx-version-min=11.0 -dynamiclib \
          $DEFS $INCLUDES $WARN -I"$JDK/include" -I"$JDK/include/darwin" \
          $SOURCES -o "$RES/Mac/$jarch/libsecp256k1.jnilib" )
    done
  else
    echo "==> skipping macOS (not on Darwin)"
  fi
fi

if [ "$WHAT" = all ] || [ "$WHAT" = linux ]; then
  echo "==> Linux amd64 + arm64 (Docker buildx)"
  rsync -a --delete "$SRC/" "$WORK/secp256k1/"
  cat > "$WORK/Dockerfile" <<EOF
FROM eclipse-temurin:17-jdk AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY secp256k1 /src
WORKDIR /src
RUN ASM=""; [ "\$(uname -m)" = x86_64 ] && ASM="-DUSE_ASM_X86_64=1"; \\
    gcc -O3 -fPIC -shared -Wl,-soname,libsecp256k1.so $DEFS \$ASM $INCLUDES $WARN \\
        -I/opt/java/openjdk/include -I/opt/java/openjdk/include/linux \\
        $SOURCES -o /libsecp256k1.so && strip --strip-unneeded /libsecp256k1.so
FROM scratch
COPY --from=build /libsecp256k1.so /libsecp256k1.so
EOF
  for pair in "amd64 x86_64" "arm64 aarch64"; do
    set -- $pair; plat=$1; jarch=$2
    docker buildx build --platform "linux/$plat" -f "$WORK/Dockerfile" \
      --output "type=local,dest=$WORK/out-$plat" "$WORK" >"$WORK/linux-$plat.log" 2>&1 \
      || { tail -30 "$WORK/linux-$plat.log"; exit 1; }
    mkdir -p "$RES/Linux/$jarch"
    cp "$WORK/out-$plat/libsecp256k1.so" "$RES/Linux/$jarch/libsecp256k1.so"
  done
fi

echo
echo "==> staged binaries:"
find "$RES" -type f | sort | while read -r f; do printf "    %-40s %s\n" "${f#"$RES"/}" "$(file -b "$f" | cut -d, -f1-2)"; done
