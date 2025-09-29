# show help
# python3 carve_and_extract.py -h

# example: run against a disk image with 8 threads for bulk_extractor
# sudo python3 carve_and_extract.py --target /mnt/cases/disk.img --out /mnt/cases/output --threads 8

# example: run against a block device (read-only advisable)
# sudo python3 carve_and_extract.py --target /dev/sdb --out /mnt/cases/output --threads 8

#!/usr/bin/env python3
import argparse
import os
import platform
import shutil
import subprocess
import sys
import textwrap

def run(cmd, check=True, capture=False):
    print(f"\n[+] Running: {' '.join(cmd)}")
    if capture:
        return subprocess.run(cmd, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    else:
        return subprocess.run(cmd, check=check)

def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows (not supported) — treat as not root.
        return False

def which(pkg):
    return shutil.which(pkg) is not None

def parse_os_release():
    data = {}
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    data[k] = v.strip('"')
    return data

def install_packages():
    system = platform.system().lower()

    # Determine package manager and package names
    pkgs = {
        "testdisk": False,
        "bulk_extractor": False,
    }

    if system == "linux":
        osr = parse_os_release()
        like = osr.get("ID_LIKE", "")
        distro_id = osr.get("ID", "")

        # Debian/Ubuntu
        if "debian" in like or distro_id in ("debian", "ubuntu", "linuxmint", "kali"):
            pkg_mgr = "apt"
            update_cmd = ["sudo", "apt", "update", "-y"]
            testdisk_pkg = "testdisk"
            bulk_pkg = "bulk-extractor"
            install_cmd = ["sudo", "apt", "install", "-y", testdisk_pkg, bulk_pkg]

        # RHEL/Fedora
        elif "rhel" in like or "fedora" in like or distro_id in ("fedora", "rhel", "centos", "rocky", "almalinux"):
            # Prefer dnf if available
            pkg_mgr = "dnf" if which("dnf") else "yum"
            update_cmd = ["sudo", pkg_mgr, "makecache", "-y"]
            testdisk_pkg = "testdisk"
            bulk_pkg = "bulk_extractor"
            install_cmd = ["sudo", pkg_mgr, "install", "-y", testdisk_pkg, bulk_pkg]
        else:
            print("[!] Unsupported or unrecognized Linux distribution. Please install TestDisk/PhotoRec and bulk_extractor manually.")
            return

        print(f"[i] Detected Linux ({distro_id}). Using {pkg_mgr} to install packages.")
        try:
            run(update_cmd)
            run(install_cmd)
        except subprocess.CalledProcessError:
            print("[!] Package installation failed. You may need to install manually.")
            return

    elif system == "darwin":  # macOS
        if not which("brew"):
            print("[!] Homebrew is required on macOS. Installing Homebrew...")
            # Non-interactive brew install
            try:
                run(['/bin/bash', '-c',
                     "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"], check=True)
            except subprocess.CalledProcessError:
                print("[!] Failed to install Homebrew automatically. Install from https://brew.sh and re-run.")
                return

        print("[i] Installing testdisk and bulk_extractor with Homebrew...")
        try:
            run(["brew", "update"])
            run(["brew", "install", "testdisk", "bulk_extractor"])
        except subprocess.CalledProcessError:
            print("[!] brew install failed. Verify Homebrew and try again.")
            return

    else:
        print("[!] Unsupported OS. This script supports Linux and macOS.")
        sys.exit(1)

def validate_tools():
    ok = True
    if not which("photorec"):
        print("[!] photorec not found in PATH (TestDisk install may have failed).")
        ok = False
    if not which("bulk_extractor"):
        print("[!] bulk_extractor not found in PATH (install may have failed).")
        ok = False
    return ok

def ensure_dirs(outdir):
    os.makedirs(outdir, exist_ok=True)
    be_out = os.path.join(outdir, "bulk_extractor")
    pr_out = os.path.join(outdir, "photorec")
    os.makedirs(be_out, exist_ok=True)
    os.makedirs(pr_out, exist_ok=True)
    return be_out, pr_out

def run_bulk_extractor(target, outdir, threads):
    print("\n=== Bulk Extractor ===")
    cmd = ["bulk_extractor", "-o", outdir]
    if threads and threads > 1:
        cmd += ["-j", str(threads)]
    # Common useful scanners (email/url/telephone/domain/pdf/zip). You can comment this to run all defaults.
    # Example to explicitly enable a subset:
    # cmd += ["-E", "email", "-E", "url", "-E", "telephone", "-E", "domain", "-E", "pdf", "-E", "zip"]
    cmd += [target]
    try:
        run(cmd)
        print(f"[✓] bulk_extractor finished. Output in: {outdir}")
    except subprocess.CalledProcessError as e:
        print(f"[!] bulk_extractor failed: {e}")

def try_photorec_cli(target, outdir):
    """
    Attempt a non-interactive PhotoRec run.
    Notes:
      - PhotoRec supports limited CLI automation via /log, /d, and /cmd.
      - /cmd expects: <device> <partition> <options>
        Examples of <options> tokens include:
          1) 'search' (start immediately),
          2) 'options,paranoid,keep_corrupted_file_no' etc.,
          3) 'fileopt,everything' then 'search'
      - Partition token varies by disk layout; for raw images without a partition table, use 'whole'.
    We’ll attempt a conservative 'whole' search. If it fails, we fall back to interactive mode.
    """
    print("\n=== PhotoRec (non-interactive attempt) ===")
    # Create a dedicated output; PhotoRec will create recup_dir.* inside this path
    # We’ll try searching the whole disk/image and dump to outdir.
    # The flags here are best-effort; PhotoRec’s CLI is limited and can differ by version.
    cmd = [
        "photorec",
        "/log",
        "/debug",
        "/d", outdir,
        "/cmd",
        target,
        "whole",
        "fileopt,everything",
        "options,keep_corrupted_file_no,paranoid_no,mode_ext2",
        "search"
    ]
    try:
        run(cmd)
        print(f"[✓] PhotoRec (CLI) run attempted. Check recovered files in: {outdir}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] PhotoRec CLI attempt failed or not supported on this build: {e}")
        return False

def launch_photorec_interactive(target, outdir):
    print("\n=== PhotoRec (interactive fallback) ===")
    help_txt = textwrap.dedent(f"""
    PhotoRec will open in TUI. Recommended steps:
      1) Select the target: {target}
      2) Choose 'whole disk' or the correct partition
      3) Filesystem type: usually 'Other' for NTFS/FAT/exFAT; 'Ext2/3/4' for Linux
      4) Choose 'Free' space (faster) or 'Whole' (more thorough)
      5) Output directory: {outdir}
    Press 'c' to confirm the output directory and start recovery.
    """).strip()
    print(help_txt)
    try:
        run(["photorec"])
    except subprocess.CalledProcessError as e:
        print(f"[!] photorec exited with an error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Install PhotoRec (TestDisk) + bulk_extractor and run automated carving/artefact extraction.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--target", required=True,
                        help="Path to forensic image (e.g., /cases/disk.img) or block device (e.g., /dev/sdb). Prefer images.")
    parser.add_argument("--out", required=True, help="Output directory (should be on a different disk than the target).")
    parser.add_argument("--threads", type=int, default=4, help="Threads for bulk_extractor (-j).")
    parser.add_argument("--skip-install", action="store_true", help="Skip package installation step.")
    parser.add_argument("--photorec-interactive", action="store_true",
                        help="Force PhotoRec interactive mode (skip CLI attempt).")
    args = parser.parse_args()

    if not is_root():
        print("[!] This script should be run with root/sudo (especially for raw devices).")
        print("    Re-run with: sudo " + " ".join(["python3"] + sys.argv))
        sys.exit(1)

    # Safety checks
    target = os.path.abspath(args.target)
    outdir = os.path.abspath(args.out)

    if not os.path.exists(target):
        print(f"[!] Target not found: {target}")
        sys.exit(1)

    if os.path.isdir(target) and not os.path.islink(target):
        print(f"[!] Target is a directory. Provide a block device or an image file.")
        sys.exit(1)

    if not args.skip_install:
        install_packages()

    if not validate_tools():
        print("[!] Required tools missing. Fix installation issues and re-run.")
        sys.exit(1)

    be_out, pr_out = ensure_dirs(outdir)

    # 1) bulk_extractor (automatic)
    run_bulk_extractor(target, be_out, args.threads)

    # 2) PhotoRec (try non-interactive, then interactive fallback)
    if args.photorec_interactive:
        launch_photorec_interactive(target, pr_out)
    else:
        ok = try_photorec_cli(target, pr_out)
        if not ok:
            print("\n[→] Falling back to interactive PhotoRec...")
            launch_photorec_interactive(target, pr_out)

    print("\nAll done. Summary:")
    print(f"  bulk_extractor output: {be_out}")
    print(f"  PhotoRec output:       {pr_out}")
    print("\nTip: Review bulk_extractor reports (e.g., email.txt, url.txt) and sift PhotoRec’s recup_dir.* folders.")

if __name__ == "__main__":
    main()
