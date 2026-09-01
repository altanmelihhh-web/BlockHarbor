#!/usr/bin/env sh
#
# Create the runtime files and directories the application expects.
#
# These are deliberately not tracked in git: they hold credentials and
# operational data, so the repository ships only *.example templates. Several
# endpoints (add-ip.php among them) refuse to write to a file that does not
# exist yet, so a fresh checkout needs this once before first use.
#
# Idempotent — existing files are never touched. Run from anywhere:
#   sh bin/init-state.sh [app-dir]
#
# The Docker entrypoint calls this too, so container and native installs get
# exactly the same bootstrap.

set -e
APP_DIR="${1:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
cd "$APP_DIR"

# 1. Seed state files from their shipped templates.
for f in users.json notifications.json customer_assets.json whitelist.txt; do
    if [ ! -f "$f" ] && [ -f "$f.example" ]; then
        cp "$f.example" "$f"
        echo "  seeded  $f"
    fi
done

# 2. Create the writable files the app appends to but will not create itself.
for f in blacklist.txt domain_combined.txt cyberwebeyeosblacklist.txt \
         audit.log ip_blocklist.log conflict_log.txt; do
    if [ ! -f "$f" ]; then
        : > "$f"
        echo "  created $f"
    fi
done

# 3. Runtime directories.
for d in lists_dyn domain_dyn usom enrichment_cache cve_cache \
         cve_cache/greynoise cve_cache/shodan warninglists; do
    if [ ! -d "$d" ]; then
        mkdir -p "$d"
        echo "  mkdir   $d"
    fi
done

echo "init-state: ready"
