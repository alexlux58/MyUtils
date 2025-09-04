#!/bin/bash
# hardware-diagnose.sh
# Basic Ubuntu hardware diagnostic script
# Run with: sudo bash hardware-diagnose.sh
# It generates a log file like:
# hardware_diagnose_myhost_2025-09-03_15-30-00.log

LOGFILE="hardware_diagnose_$(hostname)_$(date +%F_%H-%M-%S).log"

exec > >(tee -a "$LOGFILE") 2>&1

echo "===== Ubuntu Hardware Diagnostic Script ====="
echo "Hostname: $(hostname)"
echo "Date: $(date)"
echo "Kernel: $(uname -r)"
echo "============================================"
echo ""

### CPU INFO
echo ">>> CPU Information"
lscpu
echo ""

### MEMORY INFO
echo ">>> Memory (RAM) Information"
free -h
echo ""
echo "Detailed Memory Devices:"
sudo dmidecode -t memory | egrep -i "Size|Speed|Type|Manufacturer|Locator"
echo ""

### DISK INFO
echo ">>> Disk Information"
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT
echo ""
echo "SMART status of drives (if supported):"
for disk in /dev/sd[a-z]; do
    echo "--- $disk ---"
    sudo smartctl -H "$disk" 2>/dev/null | grep -i "test result"
done
echo ""

### FILESYSTEM HEALTH
echo ">>> Filesystem Usage"
df -hT | grep -v tmpfs
echo ""

### PCI / USB DEVICES
echo ">>> PCI Devices"
lspci -nn
echo ""
echo ">>> USB Devices"
lsusb
echo ""

### SENSORS (Temperature, Fans, Voltages)
echo ">>> Hardware Sensors"
which sensors >/dev/null 2>&1 && sensors || echo "lm-sensors not installed (sudo apt install lm-sensors)"
echo ""

### NETWORK INTERFACES
echo ">>> Network Interfaces"
ip -brief addr
echo ""
echo ">>> Network Link Status"
ethtool $(ls /sys/class/net | grep -v lo | head -n1) 2>/dev/null | grep -i "Link detected"
echo ""

### DMI / BIOS
echo ">>> System / BIOS Information"
sudo dmidecode -t system | egrep -i "Manufacturer|Product|Serial|UUID"
sudo dmidecode -t bios | egrep -i "Vendor|Version|Release"
echo ""

### LOG CHECKS
echo ">>> Kernel Hardware Errors (last 100 lines)"
dmesg | egrep -i "error|fail|critical|fault" | tail -n 100
echo ""

echo "============================================"
echo "Diagnostics complete. Log saved to $LOGFILE"
