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
# The cross-compiled (unsigned) driver ships next to its source when built.
[ -f build/x86_64/rescuemon.sys ] && cp build/x86_64/rescuemon.sys "$OUT/x86_64/"
[ -f build/arm64/rescuemon.sys ]  && cp build/arm64/rescuemon.sys  "$OUT/arm64/"

cp README.md "$OUT/"
# Advanced/edge tools (offline WinPE, driver signing) stay as scripts + source,
# tucked under advanced/ so the product surface is the exes.
mkdir -p "$OUT/advanced/offline" "$OUT/advanced/installer" "$OUT/advanced/driver"
cp offline/*   "$OUT/advanced/offline/"   2>/dev/null || true
cp installer/* "$OUT/advanced/installer/" 2>/dev/null || true
cp driver/*    "$OUT/advanced/driver/"    2>/dev/null || true
[ -f build/x86_64/rescuemon.sys ] && cp build/x86_64/rescuemon.sys "$OUT/advanced/driver/"

cat > "$OUT/START-HERE.txt" <<'TXT'
RESCUE - anti-ransomware / anti-malware security center
======================================================

QUICK START (recommended: use the installer)
  Double-click  x86_64\RescueSetup.exe  (or  arm64\RescueSetup.exe  on a
  Windows-on-ARM PC) and approve the admin prompt. The installer copies Rescue
  into Program Files, makes Start-menu/Desktop shortcuts, and offers ONE optional
  checkbox - "Enable kernel protection now". Everything is one program: if you
  tick it, Rescue signs the driver, deploys its custom Code-Integrity policy, and
  after a reboot finishes on its own. Uninstall from Add/Remove Programs.

PORTABLE (no install)
  Or just double-click  x86_64\Rescue.exe  directly - the Security Center opens,
  one app, big buttons, real-time protection toggle. Kernel protection can be
  turned on later from the Kernel Filter page.

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
