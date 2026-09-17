#!/bin/bash
# ONE cron entry for all data fetching across every use case.
#
# Renews the Kerberos ticket once, then calls each use case's own,
# unmodified tools/daily_update.py in turn. All the actual export/caching
# logic still lives in exactly one place per use case (their own
# daily_update.py) — this script does not duplicate any of it, it only
# sequences the calls and renews the ticket once for both.
#
# Adding a new use case later: add one more "cd .. && cd usecases/<name> &&
# python3.9 tools/daily_update.py ... || log ..." block below. Nothing else
# changes.
#
# One-time setup:
#   chmod +x tools/run_daily_update.sh
#   crontab -e
#   15 6 * * * /path/to/ps-core-ops-dashboard/tools/run_daily_update.sh

# ClickHouse: tools/clickhouse_io.py defaults to 127.0.0.1:8123, user
# "default", no password, database "ps_core_ops" — matching the ClickHouse
# already running on this box. Override any of these here if yours differs:
# export CLICKHOUSE_HOST=127.0.0.1
# export CLICKHOUSE_PORT=8123
# export CLICKHOUSE_DATABASE=ps_core_ops
# export CLICKHOUSE_RETENTION_DAYS=30

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="$REPO_ROOT/tools/daily_update.log"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"; }

log "===== starting run ====="

kinit -kt "/etc/security/keytabs/ossuser.keytab" ossuser@HADOOP.COM >> "$LOG" 2>&1
if [ $? -ne 0 ]; then
    log "kinit FAILED — check keytab path/permissions and network to the KDC"
    exit 1
fi

STATUS=0

log "--- network_degradation ---"
( cd "$REPO_ROOT/usecases/network_degradation" && python3.9 tools/daily_update.py ) >> "$LOG" 2>&1
if [ $? -ne 0 ]; then
    log "network_degradation daily_update.py FAILED"
    STATUS=1
fi

log "--- free_rg_smart_care ---"
( cd "$REPO_ROOT/usecases/free_rg_smart_care" && \
  FREE_RG_CONFIG=config/config.server.yaml python3.9 tools/daily_update.py ) >> "$LOG" 2>&1
if [ $? -ne 0 ]; then
    log "free_rg_smart_care daily_update.py FAILED"
    STATUS=1
fi

kdestroy 2>/dev/null

log "===== run finished with status $STATUS ====="
exit $STATUS
