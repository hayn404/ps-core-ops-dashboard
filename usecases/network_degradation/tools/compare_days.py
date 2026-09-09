#!/usr/bin/env python3
"""Compare subnet/site performance between a day and its baselines.

For every entity (subnet prefix or site) reports the KPI for a target day
(default: yesterday) side by side with:
  - the previous day        (e.g. Sunday vs Saturday)
  - the same weekday -7d    (e.g. Sunday vs last Sunday)

Reads the CSVs produced by tools/daily_update.py (or manual DBeaver exports
in the same format) — no database connection needed.

Examples:
  python tools/compare_days.py --data data/data_ipv6
  python tools/compare_days.py --data data/data_ipv4 data/data_ipv6 data/data_site
  python tools/compare_days.py --data data/data_site --day 2026-07-25 --top 30
"""

import argparse
import glob
import os
import sys
from datetime import datetime, timedelta

import pandas as pd

# KPI columns by pipeline. direction: +1 = higher is worse (FR),
# -1 = lower is worse (SR). Deltas are reported as "degradation":
# positive means the target day is WORSE than the baseline.
_METRICS = {
    "tcp_sr":   {"label": "TCP SR %",  "direction": -1},
    "tcp_fr2":  {"label": "TCP FR2 %", "direction": +1},
    "tcp_2_fr": {"label": "TCP FR2 %", "direction": +1},
    "tcp_3_fr": {"label": "TCP FR3 %", "direction": +1},
}

_ENTITY_COLS = ("ipv6_prefix_48", "ipv4_prefix_24", "subnet_prefix",
                "prefix", "site")


def load_csvs(paths) -> pd.DataFrame:
    files = []
    for raw in paths:
        p = os.path.abspath(raw)
        if os.path.isdir(p):
            files.extend(sorted(glob.glob(os.path.join(p, "*.csv"))))
        elif os.path.isfile(p):
            files.append(p)
        else:
            raise SystemExit(f"Path not found: {p}")
    if not files:
        raise SystemExit(f"No CSV files found under: {paths}")

    frames = []
    for f in files:
        d = pd.read_csv(f)
        d.columns = d.columns.str.strip('"').str.lower()
        frames.append(d)
    df = pd.concat(frames, ignore_index=True)
    print(f"loaded {len(df):,} rows from {len(files)} file(s)")
    return df


def entity_column(df: pd.DataFrame) -> str:
    for c in _ENTITY_COLS:
        if c in df.columns:
            return c
    raise SystemExit(f"No entity column ({_ENTITY_COLS}) in CSV columns: "
                     f"{list(df.columns)}")


def compare(df: pd.DataFrame, target_day, top: int):
    ent = entity_column(df)
    metrics = [m for m in _METRICS if m in df.columns]
    if not metrics:
        raise SystemExit(f"No known KPI columns in CSV: {list(df.columns)}")
    if "session_count" not in df.columns:
        df["session_count"] = 1

    df = df.copy()
    df["day"] = pd.to_datetime(df["hour"], format="%Y/%m/%d %H:%M").dt.date
    days_available = sorted(df["day"].unique())
    print(f"days in data: {days_available[0]} .. {days_available[-1]} "
          f"({len(days_available)} day(s))")

    prev_day = target_day - timedelta(days=1)
    week_day = target_day - timedelta(days=7)
    wanted = {target_day: "target", prev_day: "prev", week_day: "week_ago"}
    missing = [d for d in wanted if d not in days_available]
    if missing:
        print(f"WARNING: no data for: "
              f"{', '.join(str(d) for d in missing)} "
              f"({' vs '.join(str(d) for d in missing)} baseline(s) will be NaN)")

    # Session-weighted mean of each KPI per (entity, day) — vectorized
    # (groupby.apply on multi-million-row IPv4 data caused MemoryError).
    group_cols = [ent] + (["ugw"] if "ugw" in df.columns else [])
    agg_frames = []
    for m in metrics:
        sub = df.dropna(subset=[m])
        w = (
            sub.assign(_weighted=sub[m] * sub["session_count"])
               .groupby(group_cols + ["day"])
               .agg(_weighted=("_weighted", "sum"),
                    _sessions=("session_count", "sum"))
        )
        w[m] = w["_weighted"] / w["_sessions"]
        agg_frames.append(w[m])
    sessions = (df.groupby(group_cols + ["day"])["session_count"]
                  .sum().rename("sessions"))
    daily = pd.concat(agg_frames + [sessions], axis=1).reset_index()

    def per_day(day, suffix):
        d = daily[daily["day"] == day][group_cols + metrics + ["sessions"]]
        return d.rename(columns={m: f"{m}_{suffix}" for m in metrics}
                        | {"sessions": f"sessions_{suffix}"})

    out = per_day(target_day, "target")
    for day, suffix in ((prev_day, "prev"), (week_day, "week_ago")):
        out = out.merge(per_day(day, suffix), on=group_cols, how="left")

    # Degradation columns: positive = target day worse than baseline.
    for m in metrics:
        direction = _METRICS[m]["direction"]
        for suffix in ("prev", "week_ago"):
            out[f"{m}_deg_vs_{suffix}"] = (
                direction * (out[f"{m}_target"] - out[f"{m}_{suffix}"]))

    # Rank by the worst degradation across metrics vs the week-ago baseline.
    deg_cols = [f"{m}_deg_vs_week_ago" for m in metrics]
    out["worst_deg_vs_week_ago"] = out[deg_cols].max(axis=1)
    out = out.sort_values("worst_deg_vs_week_ago", ascending=False)

    return out, metrics, ent, (target_day, prev_day, week_day)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", nargs="+", required=True,
                    help="CSV file(s) or folder(s), e.g. data/data_ipv6")
    ap.add_argument("--day", default=None,
                    help="target day YYYY-MM-DD (default: yesterday)")
    ap.add_argument("--top", type=int, default=30,
                    help="rows to print (default 30; full result goes to --out)")
    ap.add_argument("--out", default=None,
                    help="output CSV path (default: compare_<day>.csv next to "
                         "the first --data path)")
    args = ap.parse_args()

    target = (datetime.strptime(args.day, "%Y-%m-%d").date() if args.day
              else (datetime.now() - timedelta(days=1)).date())

    df = load_csvs(args.data)
    result, metrics, ent, (target, prev, week) = compare(df, target, args.top)

    out_path = args.out or f"compare_{target}.csv"
    result.to_csv(out_path, index=False)

    pd.set_option("display.width", 250)
    pd.set_option("display.max_columns", 50)
    show_cols = ([ent] + (["ugw"] if "ugw" in result.columns else []))
    for m in metrics:
        show_cols += [f"{m}_target", f"{m}_prev", f"{m}_week_ago"]
    show_cols += ["sessions_target", "worst_deg_vs_week_ago"]
    show_cols = [c for c in show_cols if c in result.columns]

    print(f"\nTarget day: {target}  |  prev day: {prev}  |  week ago: {week}")
    print(f"Top {args.top} by degradation vs week ago "
          f"(full table -> {out_path}, {len(result)} entities):\n")
    print(result[show_cols].head(args.top).to_string(index=False))
    print(f"\nNote: *_deg_vs_* columns are degradation points — positive means "
          f"the target day is WORSE (SR lower / FR higher).")


if __name__ == "__main__":
    main()
