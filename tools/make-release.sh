#!/usr/bin/env bash
# Assemble a runnable Rescue release: the built user-mode tools for both arches,
# the offline + installer scripts, the driver source (needs signing), a launcher,
# and the docs - zipped into dist/.
set -euo pipefail
cd "$(dirname "$0")/.."
VER="0.1.0"
OUT="dist/Rescue-${VER}"
rm -rf "$OUT" "dist/Rescue-${VER}.zip"
mkdir -p "$OUT/x86_64" "$OUT/arm64"

cp build/x86_64/*.exe "$OUT/x86_64/" 2>/dev/null || { echo "build x64 first (make x64)"; exit 1; }
cp build/arm64/*.exe  "$OUT/arm64/"  2>/dev/null || { echo "build arm64 first (make arm64)"; exit 1; }

cp Rescue.cmd "$OUT/"
cp README.md "$OUT/"
mkdir -p "$OUT/offline" "$OUT/installer" "$OUT/driver"
cp offline/*   "$OUT/offline/"   2>/dev/null || true
cp installer/* "$OUT/installer/" 2>/dev/null || true
cp driver/*    "$OUT/driver/"    2>/dev/null || true

cat > "$OUT/START-HERE.txt" <<'TXT'
RESCUE - defensive anti-ransomware / anti-malware toolkit
=========================================================

QUICK START
  Double-click  Rescue.cmd  and approve the admin prompt. Pick from the menu.
  (32/64-bit Intel/AMD uses x86_64\, Windows-on-ARM uses arm64\ - the launcher
   picks automatically.)

WHAT WORKS OUT OF THE BOX (no signing, no extra downloads)
  - Scanner            heuristic + hash file scanner, quarantine, scheduled scans
  - ASEP Cleaner       flags unsigned autostart entries (no virus database needed)
  - Lockdown Breaker   undoes malware lockouts, kills MEMZ-style screen effects
  - Anti-Ransomware Guard   canary + ETW attribution + wiper detection + disk shield
  - Watchdog           service that keeps the guard alive
  - Backup & Restore   Time Machine-style versioned snapshots + recovery-disk maker
  - Offline rescue     WinPE cleanup, boot repair, partition/file recovery scripts

NOT INCLUDED AS A LOADABLE BINARY (by design)
  - Kernel minifilter (driver\)  - the "inspect every write, block before it lands"
    tier. This is the ONE part that Windows requires to be Microsoft-signed to
    load; it ships as reviewable source + build/sign guide, not a ready .sys.
    Everything above runs without it.

SAFETY
  Every tool is read-only / report-only by default and asks for a UAC prompt.
  Use only on machines you own or are authorized to administer.
TXT

cd dist
zip -rq "Rescue-${VER}.zip" "Rescue-${VER}"
cd ..
echo "built dist/Rescue-${VER}.zip"
du -h "dist/Rescue-${VER}.zip"
