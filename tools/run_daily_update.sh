#!/bin/bash
# ONE cron entry for all daily data work on this server (Linux, no .bat files).
#
#   - renews the Kerberos ticket once
#   - Network Degradation : etl.py daily  = Hive -> ClickHouse raw tables,
#                           then every dashboard table is rebuilt INSIDE ClickHouse
#   - Free RGs Smart Care : its own tools/daily_update.py (unchanged)
#
# One-time setup:
#   chmod +x tools/run_daily_update.sh
#   crontab -e
#   15 6 * * * /path/to/ps-core-ops-dashboard/tools/run_daily_update.sh
#
# ClickHouse defaults (127.0.0.1:8123, user default, no password, database
# ps_core_ops) live in tools/clickhouse_io.py; override here if needed:
# export CLICKHOUSE_HOST=127.0.0.1
# export CLICKHOUSE_DATABASE=ps_core_ops

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="$REPO_ROOT/tools/daily_update.log"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"; }

log "===== starting run ====="

kinit -kt "/etc/security/keytabs/ossuser.keytab" ossuser@HADOOP.COM >> "$LOG" 2>&1
if [ $? -ne 0 ]; then
    log "kinit FAILED - check keytab path/permissions and network to the KDC"
    exit 1
fi

STATUS=0

log "--- network_degradation ---"
( cd "$REPO_ROOT/usecases/network_degradation" && python3.9 etl.py daily ) >> "$LOG" 2>&1
if [ $? -ne 0 ]; then
    log "network_degradation etl.py daily FAILED (details: usecases/network_degradation/etl.log)"
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
