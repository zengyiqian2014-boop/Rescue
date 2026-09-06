#!/usr/bin/env bash
# Build RescueSetup.exe for one arch: stage the install payload, tar it, embed it
# as a resource, and compile the native installer (src/setup.cpp).
#
#   tools/build-setup.sh x86_64
#   tools/build-setup.sh arm64
#
# Requires the arch's user-mode exes already built (make x64 / make arm64) and,
# for arm64, llvm-mingw on PATH.
set -euo pipefail
cd "$(dirname "$0")/.."
ARCH="${1:?usage: build-setup.sh <x86_64|arm64>}"

case "$ARCH" in
  x86_64) CXX="${X64_CXX:-x86_64-w64-mingw32-g++}";   WINDRES="${X64_WINDRES:-x86_64-w64-mingw32-windres}" ;;
  arm64)  CXX="${ARM64_CXX:-aarch64-w64-mingw32-clang++}"; WINDRES="${ARM64_WINDRES:-aarch64-w64-mingw32-windres}" ;;
  *) echo "unknown arch: $ARCH"; exit 1 ;;
esac

BDIR="build/$ARCH"
[ -f "$BDIR/Rescue.exe" ] || { echo "build $ARCH first (make $ARCH)"; exit 1; }

STAGE="$BDIR/payload"
rm -rf "$STAGE"; mkdir -p "$STAGE/advanced/offline" "$STAGE/advanced/installer" "$STAGE/advanced/driver"
# top-level product: the GUI + engines
cp "$BDIR"/Rescue.exe "$STAGE"/
for t in scanner ransom_guard asep_cleaner lockdown_breaker watchdog backup; do
  [ -f "$BDIR/$t.exe" ] && cp "$BDIR/$t.exe" "$STAGE"/
done
cp offline/*   "$STAGE/advanced/offline/"   2>/dev/null || true
cp installer/* "$STAGE/advanced/installer/" 2>/dev/null || true
cp driver/*    "$STAGE/advanced/driver/"    2>/dev/null || true
# ship the cross-compiled, UNSIGNED driver binary next to its source when present
[ -f "$BDIR/rescuemon.sys" ] && cp "$BDIR/rescuemon.sys" "$STAGE/advanced/driver/"
cp README.md   "$STAGE"/ 2>/dev/null || true

# uncompressed tar (portable ustar); paths relative with ./ prefix
TAR="$BDIR/payload.tar"
tar --format=ustar -cf "$TAR" -C "$STAGE" .
echo "payload: $(du -h "$TAR" | cut -f1)"

# generate the resource script for this arch
RC="$BDIR/setup.rc"
cat > "$RC" <<EOF
#include <winver.h>
1 24 "src/rescue.manifest"
#define IDI_APPICON 1
#define IDR_PAYLOAD 300
#define IDP_BRAND   212
IDI_APPICON ICON "src/icons/rescue.ico"
IDP_BRAND   RCDATA "src/icons/brand.png"
IDR_PAYLOAD RCDATA "$TAR"
EOF

"$WINDRES" "$RC" -O coff -o "$BDIR/setup_res.o"
$CXX -O2 -std=c++17 -municode -Wall -static -static-libgcc -static-libstdc++ \
    src/setup.cpp "$BDIR/setup_res.o" -o "$BDIR/RescueSetup.exe" \
    -Wl,--subsystem,windows -lshell32 -lole32 -loleaut32 -luuid -lshlwapi -lgdi32 -lgdiplus -ladvapi32
rm -rf "$STAGE"
echo "built $BDIR/RescueSetup.exe ($(du -h "$BDIR/RescueSetup.exe" | cut -f1))"
