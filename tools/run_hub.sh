#!/bin/bash
# Quick foreground/background launcher for manual testing.
# For production, use the systemd unit (tools/ps-core-ops-dashboard.service)
# instead — it gives you auto-restart on crash and on server reboot, which
# this script does not.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# If a Kerberos ticket cache is already set up for this shell (e.g. via
# `kinit`), it'll be picked up automatically. Otherwise set KRB5CCNAME here
# to match whatever cache tools/run_daily_update.sh uses.

python3.9 hub.py --host 0.0.0.0 --port 8820
