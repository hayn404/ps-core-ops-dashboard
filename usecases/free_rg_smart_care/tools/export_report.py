#!/usr/bin/env python3
"""Headless export of the management report (multi-sheet Excel) to a folder.

Server approach: run this on cron after tools/daily_update.py — no dashboard,
no open port required. The workbook lands in the output folder (default:
config.yaml -> report.output_dir), ready to be shared with management.

    python tools/export_report.py                 # last 7 days, default output dir
    python tools/export_report.py --days 30
    python tools/export_report.py --out-dir /shared/reports
    python tools/export_report.py --rg "RG 1192 - NTRA & Governmental"

Uses the same builder as the dashboard's Download Report button (report.py),
so both approaches produce identical workbooks.
"""

import argparse
import os
import sys
from datetime import datetime

import pandas as pd

# Windows consoles default to cp1252; keep log messages from crashing print().
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from dashboard import load_all_data, load_config
from report import build_report_workbook


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", default=os.path.join(REPO_ROOT, "data"),
                    help="root data folder (default: <repo>/data)")
    ap.add_argument("--out-dir", default=None,
                    help="report output folder (default: config.yaml -> report.output_dir)")
    ap.add_argument("--days", type=int, default=7,
                    help="cover the newest N days of data (default 7; 0 = all days)")
    ap.add_argument("--rg", default="",
                    help="comma-separated rating_group_name filter (default: all)")
    ap.add_argument("--apn", default="",
                    help="comma-separated APN filter (default: config apn_filter, else all)")
    args = ap.parse_args()

    config = load_config()
    out_dir = args.out_dir or config.get("report", {}).get("output_dir", "reports")
    if not os.path.isabs(out_dir):
        out_dir = os.path.join(REPO_ROOT, out_dir)

    print(f"Loading data from {args.csv} ...")
    traffic_df, users_df, top_users_df = load_all_data(args.csv)
    if traffic_df.empty:
        raise SystemExit("No data found — run tools/daily_update.py first.")

    # Filters
    selected_rgs = [r.strip() for r in args.rg.split(",") if r.strip()] or None
    if args.apn.strip():
        selected_apns = [a.strip() for a in args.apn.split(",") if a.strip()]
    else:
        apn_raw = config.get("apn_filter", "")
        selected_apns = ([a.strip() for a in apn_raw.split(",") if a.strip()]
                         if apn_raw else None)

    # Date range: newest N days of available data
    date_max = traffic_df["myday"].max()
    if args.days > 0 and pd.notna(date_max):
        start_ts = date_max - pd.Timedelta(days=args.days - 1)
        start_date = start_ts.strftime("%Y-%m-%d")
    else:
        start_ts = traffic_df["myday"].min()
        start_date = start_ts.strftime("%Y-%m-%d") if pd.notna(start_ts) else None
    end_date = date_max.strftime("%Y-%m-%d") if pd.notna(date_max) else None

    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(out_dir, f"free_rg_report_{ts}.xlsx")

    with open(out_path, "wb") as f:
        build_report_workbook(
            f, traffic_df, users_df, top_users_df,
            selected_rgs=selected_rgs, selected_apns=selected_apns,
            start_date=start_date, end_date=end_date)

    size_kb = os.path.getsize(out_path) / 1024
    print(f"Report written: {out_path} ({size_kb:,.0f} KB, "
          f"days {start_date} → {end_date})")


if __name__ == "__main__":
    main()
