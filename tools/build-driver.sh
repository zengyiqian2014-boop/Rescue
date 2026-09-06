#!/usr/bin/env bash
# Cross-compile the RescueMon kernel minifilter (driver/rescuemon.c) into
# rescuemon.sys ON LINUX, using clang + lld-link from llvm-mingw against the
# Microsoft WDK headers/libs distributed as NuGet packages. No Windows or Visual
# Studio needed to BUILD; the result still needs signing to LOAD (see the CI /
# test-signing scripts in installer/), and has not been run on a real kernel.
#
#   tools/build-driver.sh            # x64   -> build/x86_64/rescuemon.sys
#   tools/build-driver.sh arm64      # arm64 -> build/arm64/rescuemon.sys
#   tools/build-driver.sh all        # both
#
# Requires: clang + lld-link on PATH or under $LLVM_MINGW/bin, curl, unzip.
set -euo pipefail
cd "$(dirname "$0")/.."

WDK_VER="10.0.28000.2526"     # Microsoft.Windows.WDK.<arch>
SDK_VER="10.0.28000.2705"     # Microsoft.Windows.SDK.cpp (arch-neutral headers)
SDK_INC="10.0.28000.0"
CACHE="build/wdk-cache"
mkdir -p "$CACHE"

CLANG="$(command -v clang || true)"; LLDLINK="$(command -v lld-link || true)"
if [ -n "${LLVM_MINGW:-}" ]; then
    [ -x "$LLVM_MINGW/bin/clang" ]    && CLANG="$LLVM_MINGW/bin/clang"
    [ -x "$LLVM_MINGW/bin/lld-link" ] && LLDLINK="$LLVM_MINGW/bin/lld-link"
fi
[ -n "$CLANG" ] && [ -n "$LLDLINK" ] || { echo "need clang + lld-link (set LLVM_MINGW to the llvm-mingw root)"; exit 1; }

fetch(){ # id version
    local id="$1" ver="$2" low; low="$(echo "$id" | tr '[:upper:]' '[:lower:]')"
    local dir="$CACHE/$id"
    if [ -d "$dir/c/Include" ] || [ -d "$dir/c/Lib" ]; then echo "  cached $id"; return; fi
    echo "  downloading $id $ver ..."
    curl -fsSL -o "$CACHE/$low.nupkg" "https://api.nuget.org/v3-flatcontainer/$low/$ver/$low.$ver.nupkg"
    mkdir -p "$dir"; ( cd "$dir" && unzip -oq "../$low.nupkg" )
}

build_one(){ # $1 = x64 | arm64
    local arch="$1" pkg target machine libsub outdir archdef gslib
    case "$arch" in
      x64)   pkg="Microsoft.Windows.WDK.x64";   target="x86_64-pc-windows-msvc";  machine="X64";   libsub="x64";   outdir="build/x86_64"; archdef="-D_AMD64_ -DAMD64"; gslib="BufferOverflowK.lib" ;;
      arm64) pkg="Microsoft.Windows.WDK.arm64"; target="aarch64-pc-windows-msvc"; machine="ARM64"; libsub="ARM64"; outdir="build/arm64";  archdef="-D_ARM64_ -DARM64"; gslib="bufferoverflowfastfailk.lib" ;;
      *) echo "unknown arch: $arch"; return 1 ;;
    esac
    echo "== $arch: fetching packages =="
    fetch "$pkg" "$WDK_VER"; fetch "Microsoft.Windows.SDK.cpp" "$SDK_VER"
    local WDK="$CACHE/$pkg/c" SDK="$CACHE/Microsoft.Windows.SDK.cpp/c"
    local KINC="$WDK/Include/$SDK_INC" SINC="$SDK/Include/$SDK_INC" LIB="$WDK/Lib/$SDK_INC/km/$libsub"
    [ -f "$KINC/km/fltKernel.h" ] || { echo "fltKernel.h missing in $pkg"; return 1; }
    [ -f "$LIB/fltMgr.lib" ]      || { echo "fltMgr.lib missing in $pkg ($LIB)"; return 1; }
    mkdir -p "$outdir"
    echo "== $arch: compiling =="
    "$CLANG" --driver-mode=cl -c driver/rescuemon.c -o "$outdir/rescuemon.obj" \
        --target="$target" -D_KERNEL_MODE $archdef -D_WIN64 \
        -DNTDDI_VERSION=0x0A000010 -D_WIN32_WINNT=0x0A00 -DPOOL_NX_OPTIN=1 \
        -X -W3 -O2 -GS -Zc:wchar_t- -guard:cf \
        -Wno-unknown-pragmas -Wno-ignored-attributes -Wno-pragma-pack \
        -I"$KINC/km" -I"$KINC/km/crt" -I"$KINC/shared" -I"$SINC/shared"
    echo "== $arch: linking =="
    "$LLDLINK" "$outdir/rescuemon.obj" /OUT:"$outdir/rescuemon.sys" \
        /DRIVER /SUBSYSTEM:NATIVE,10.00 /ENTRY:GsDriverEntry /NODEFAULTLIB "/MACHINE:$machine" \
        /GUARD:CF /INTEGRITYCHECK "/LIBPATH:$LIB" \
        ntoskrnl.lib fltMgr.lib "$gslib"
    rm -f "$outdir/rescuemon.obj"
    echo "built $outdir/rescuemon.sys ($(du -h "$outdir/rescuemon.sys" | cut -f1)) - UNSIGNED; sign to load."
}

case "${1:-x64}" in
  all) build_one x64; build_one arm64 ;;
  *)   build_one "${1:-x64}" ;;
esac
