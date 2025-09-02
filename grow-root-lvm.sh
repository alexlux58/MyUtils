#!/usr/bin/env bash
# Expand the root filesystem on LVM (single disk, single PV) VMs.
# Works for ext4 and xfs root filesystems.
# Alex-friendly: safe checks + dry run.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: sudo ./grow-root-lvm.sh [--dry-run] [--percent <N>] [--lv <VG/LV>]

Options:
  --dry-run          Show what would be done, but don't execute.
  --percent <N>      Extend LV by N% of FREE PV space instead of 100% (e.g., 80).
  --lv <VG/LV>       Override detected root LV (format: vgname/lvname).

Notes:
- Requires: cloud-guest-utils (growpart), lvm2, util-linux.
- Designed for 1 disk with LVM PV on a single partition (common Proxmox/Ubuntu install).
- Run as root (sudo).
EOF
}

DRY_RUN=0
PCT="+100%FREE"
OVERRIDE_LV=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --percent) shift; PCT="+${1}%FREE"; shift ;;
    --lv) shift; OVERRIDE_LV="$1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }

[[ $EUID -eq 0 ]] || { echo "Please run as root (sudo)."; exit 1; }
need lsblk; need findmnt; need growpart; need pvresize; need lvextend

# 1) Detect root device/LV/VG
ROOT_SRC=$(findmnt -no SOURCE /)
ROOT_FS=$(findmnt -no FSTYPE /)

if [[ -n "$OVERRIDE_LV" ]]; then
  VG="${OVERRIDE_LV%%/*}"
  LV="${OVERRIDE_LV##*/}"
  LV_PATH="/dev/${VG}/${LV}"
else
  # Expect /dev/mapper/<vgname>-<lvname>
  if [[ "$ROOT_SRC" =~ ^/dev/mapper/ ]]; then
    # Map back to VG/LV names
    # Example: /dev/mapper/ubuntu--vg-ubuntu--lv -> ubuntu-vg/ubuntu-lv
    MAPPED=$(ls -l "$ROOT_SRC" | awk '{print $NF}')
    # Get DM name:
    DM_NAME=$(basename "$ROOT_SRC")
    # lvdisplay is robust:
    need lvdisplay
    VG=$(lvdisplay "$ROOT_SRC" 2>/dev/null | awk '/VG Name/{print $3; exit}')
    LV=$(lvdisplay "$ROOT_SRC" 2>/dev/null | awk '/LV Name/{print $3; exit}')
    LV_PATH="/dev/${VG}/${LV}"
  else
    echo "Root is not on LVM mapper device: $ROOT_SRC"
    echo "If your root LV is known, re-run with: --lv VG/LV"
    exit 1
  fi
fi

# 2) Find backing PV and disk/partition
need pvs
PV_LINE=$(pvs --noheadings -o pv_name,vg_name | awk -v vg="$VG" '$2==vg {print $1; exit}')
[[ -n "$PV_LINE" ]] || { echo "Could not find PV for VG ${VG}."; exit 1; }
PV_DEV=$(echo "$PV_LINE" | xargs)      # e.g., /dev/sda3

# Disk device (pkname) and partition number
DISK=$(lsblk -no pkname "$PV_DEV")
DISK="/dev/${DISK}"                    # e.g., /dev/sda
PARTNUM=$(echo "$PV_DEV" | sed -E "s#^${DISK}##; s#/dev/##")
PARTNUM="${PARTNUM##*[[:alpha:]]}"     # extract trailing digits (e.g., 3)

[[ -b "$DISK" ]] || { echo "Disk not found: $DISK"; exit 1; }
[[ -n "$PARTNUM" ]] || { echo "Could not determine partition number for $PV_DEV"; exit 1; }

echo "Detected:"
echo "  Root FS:        $ROOT_FS"
echo "  Root LV:        $LV_PATH   (VG=$VG, LV=$LV)"
echo "  PV device:      $PV_DEV"
echo "  Disk device:    $DISK"
echo "  Partition num:  $PARTNUM"
echo "  Extend percent: $PCT"
echo

doit() { if [[ $DRY_RUN -eq 1 ]]; then echo "DRY-RUN: $*"; else echo "+ $*"; eval "$@"; fi; }

# 3) Grow the partition to fill the disk
doit "growpart $DISK $PARTNUM"

# 4) Tell LVM the PV grew
doit "pvresize $PV_DEV"

# 5) Extend the LV
doit "lvextend -l $PCT $LV_PATH"

# 6) Grow the filesystem
case "$ROOT_FS" in
  ext4|ext3|ext2)
    need resize2fs
    doit "resize2fs $LV_PATH"
    ;;
  xfs)
    need xfs_growfs
    # xfs_growfs takes the mountpoint
    doit "xfs_growfs /"
    ;;
  *)
    echo "Unsupported/unknown root filesystem: $ROOT_FS"
    echo "Extend performed at LVM level; please grow the filesystem manually."
    exit 1
    ;;
esac

echo
echo "Done. New sizes:"
df -h /
lsblk
