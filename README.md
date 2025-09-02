# MyUtils

# 1) Install dependencies (if needed)
sudo apt-get update
sudo apt-get install -y cloud-guest-utils lvm2

# 2) Save & run
nano grow-root-lvm.sh    # paste the script
chmod +x grow-root-lvm.sh

# Preview (no changes):
sudo ./grow-root-lvm.sh --dry-run

# Do it (use 100% of free space):
sudo ./grow-root-lvm.sh

# Or only use 80% of the free PV space:
sudo ./grow-root-lvm.sh --percent 80

df -h /usr/share/elasticsearch/data
curl -s http://localhost:9200/_cluster/health?pretty
