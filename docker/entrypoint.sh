#!/bin/sh
set -e

# Create runtime directories (may be missing on fresh volume)
mkdir -p \
    /var/www/html/domain_dyn \
    /var/www/html/lists_dyn \
    /var/www/html/cve_cache/greynoise \
    /var/www/html/cve_cache/shodan \
    /var/www/html/enrichment_cache \
    /var/www/html/usom \
    /var/www/html/warninglists \
    /var/log/cyberwebeyeos

# Touch writable runtime files so www-data can write them on first request
for f in blacklist.txt whitelist.txt domain_combined.txt cyberwebeyeosblacklist.txt \
          audit.log ip_blocklist.log conflict_log.txt; do
    [ -f "/var/www/html/$f" ] || touch "/var/www/html/$f"
done

chown -R www-data:www-data /var/www/html /var/log/cyberwebeyeos

exec "$@"
