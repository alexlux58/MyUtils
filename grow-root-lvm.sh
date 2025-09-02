#!/usr/bin/env bash
set -euo pipefail

# Grow LVM root on Ubuntu (ext4 or xfs). No sed; robust and idempotent.
# Requires: cloud-guest-utils (growpart), lvm2
# Usage: sudo ./grow-root-lvm.sh [--percent N] [--dry-run]
#   --percent N  use N% of FREE space in the VG (e.g. 80). Default: 100% of FREE.
#   --dry-run    print actions but do not change anything.

PERCENT=""
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --percent)
      [[ $# -ge 2 ]] || { echo "ERROR: --percent requires a value"; exit 2; }
      PERCENT="$2"; shift 2;;
    --dry-run)
      DRY_RUN=1; shift;;
    -h|--help)
      echo "Usage: sudo $0 [--percent N] [--dry-run]"; exit 0;;
    *)
      echo "Unknown arg: $1"; exit 2;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
need findmnt; need lsblk; need lvs; need vgs; need pvs; need lvextend; need pvresize
need growpart || { echo "Missing growpart (cloud-guest-utils). Install: sudo apt-get update && sudo apt-get install -y cloud-guest-utils"; exit 1; }

[[ $EUID -eq 0 ]] || { echo "Please run as root (use sudo)."; exit 1; }

run() { if [[ $DRY_RUN -eq 1 ]]; then echo "+ $*"; else eval "$@"; fi; }

ROOT_SRC="$(findmnt -no SOURCE /)"
if [[ -z "$ROOT_SRC" ]]; then echo "Cannot find root mount source"; exit 1; fi

# Normalize /dev/mapper/vg-lv to LVM names
VG_NAME="$(lvs --noheadings -o vg_name "$ROOT_SRC" | awk '{$1=$1;print}')"
LV_NAME="$(lvs --noheadings -o lv_name "$ROOT_SRC" | awk '{$1=$1;print}')"
if [[ -z "$VG_NAME" || -z "$LV_NAME" ]]; then
  echo "Root is not on LVM or cannot resolve VG/LV: $ROOT_SRC"; exit 1
fi

# Get PV backing the VG (assume single-PV root VG; common on single-disk installs)
PV_PATH="$(pvs --noheadings -o pv_name --select "vg_name=$VG_NAME" | awk '{$1=$1;print}' | head -n1)"
if [[ -z "$PV_PATH" ]]; then echo "Cannot resolve PV for VG $VG_NAME"; exit 1; fi

# Determine base disk and partition number (if partitioned PV)
PKNAME="$(lsblk -no PKNAME "$PV_PATH" 2>/dev/null || true)"
PARTNUM="$(lsblk -no PARTNUM "$PV_PATH" 2>/dev/null || true)"
BASE_DISK=""
if [[ -n "$PKNAME" && -n "$PARTNUM" ]]; then
  BASE_DISK="/dev/$PKNAME"
else
  # Whole-disk PV (rare on VMs, but handle it)
  BASE_DISK="$PV_PATH"
fi

echo "Detected:"
echo "  Root LV:   /dev/$VG_NAME/$LV_NAME ($ROOT_SRC)"
echo "  VG:        $VG_NAME"
echo "  PV:        $PV_PATH"
echo "  Base disk: $BASE_DISK  Part#: ${PARTNUM:-<none>}"

# 1) Grow the partition if PV is a partition
if [[ -n "${PARTNUM:-}" ]]; then
  echo "Growing partition $BASE_DISK partition $PARTNUM with growpart..."
  run growpart "$BASE_DISK" "$PARTNUM"
  run partprobe "$BASE_DISK" || true
else
  echo "PV appears to be the whole disk; skipping growpart."
fi

# 2) Resize PV to claim new space
echo "Resizing PV $PV_PATH..."
run pvresize "$PV_PATH"

# 3) Extend LV (root) and filesystem
LV_PATH="/dev/$VG_NAME/$LV_NAME"
EXT_ARG="+100%FREE"
if [[ -n "$PERCENT" ]]; then
  # LVM supports %FREE directly: e.g., +80%FREE
  EXT_ARG="+${PERCENT}%FREE"
fi

echo "Extending LV $LV_PATH by $EXT_ARG and resizing filesystem (-r)..."
run lvextend -r -l "$EXT_ARG" "$LV_PATH"

echo "Done."
echo "New sizes:"
run lsblk -f
EOF

chmod +x grow-root-lvm.sh
