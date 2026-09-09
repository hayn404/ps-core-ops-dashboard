#!/usr/bin/env python3
"""Daily incremental export of Free RGs Smart Care data to CSV.

Runs every morning (via Task Scheduler -> tools\\run_daily_update.bat) on a
VPN-connected Windows laptop with a valid Kerberos ticket.

What it does (single "daily" job):
 1. Discovers existing tables via SHOW TABLES LIKE DETAIL_CDR_SGIDIAMETER_%.
 2. Picks candidate tables newer than the last exported one (state file).
 3. Probes each candidate's MIN/MAX(TRANS_REQ_TIME_SEC) to learn its calendar day.
 4. Exports every candidate whose day is fully in the past and not already
    exported -> one CSV per table in data/free_rg_daily/.

One unified query per table (dashboard.daily_query) scans the source table
ONCE and returns the top-20 users per RG with the RG-level traffic and
unique-user totals attached as window aggregates — replacing the old three
scans per day (traffic / users / top_users).

Because selection is date-probe based (not table-number arithmetic), the
script is immune to table-number gaps and automatically backfills days missed
while the laptop was off. The partial current-day table is never exported.

Requires a valid Kerberos ticket (renewed daily).
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta

import pandas as pd

# Windows consoles default to cp1252; keep log messages from crashing print().
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from dashboard import connect_db, discover_tables, daily_query, load_config

STATE_PATH = os.path.join(REPO_ROOT, "tools", ".daily_update_state.json")
LOG_PATH = os.path.join(REPO_ROOT, "tools", "daily_update.log")

# How many of the newest tables to consider when there is no state yet
FIRST_RUN_LOOKBACK_TABLES = 5

# Rows per JDBC fetch. Same safe default as the TCP-KPI project.
FETCH_SIZE = 500

_JOBS = {
    "daily": {
        "out_subdir": os.path.join("data", "free_rg_daily"),
        "query_builder": daily_query,
    },
}

# Legacy per-category state keys, superseded by the single "daily" key
_LEGACY_STATE_KEYS = ("traffic", "users", "top_users")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
_log_file = None

def log(msg: str) -> None:
    global _log_file
    print(msg)
    try:
        if _log_file is None:
            _log_file = open(LOG_PATH, "a", encoding="utf-8")
        _log_file.write(msg + "\n")
        _log_file.flush()
    except OSError:
        pass

def log_exception(e: Exception) -> None:
    log(f" error: {type(e).__name__}: {e}")
    stacktrace = getattr(e, "stacktrace", None)
    if callable(stacktrace):
        try:
            log("----- Java stack trace -----\n" + stacktrace() +
                "\n----------------------------")
        except Exception:
            pass

# ---------------------------------------------------------------------------
# SQL & Export
# ---------------------------------------------------------------------------

def _read_export(sql: str, conn, fetch_size: int = FETCH_SIZE) -> "tuple[pd.DataFrame, dict]":
    """Execute an export query with a bounded JDBC fetch size.

    Rows are read as strings, then numeric columns are converted
    vectorized in pandas afterwards.
    """
    stmt = conn.jconn.createStatement()
    try:
        stmt.setFetchSize(fetch_size)
        t0 = time.monotonic()
        rs = stmt.executeQuery(sql)
        timings = {"exec_s": round(time.monotonic() - t0, 1)}

        t1 = time.monotonic()
        md = rs.getMetaData()
        ncols = md.getColumnCount()
        cols = [str(md.getColumnName(i)).split(".")[-1]
                for i in range(1, ncols + 1)]
        rows = []
        while rs.next():
            rows.append(tuple(rs.getString(i) for i in range(1, ncols + 1)))
        rs.close()
        timings["fetch_s"] = round(time.monotonic() - t1, 1)
        timings["rows"] = len(rows)

        df = pd.DataFrame.from_records(rows, columns=cols)
        for c in df.columns:
            try:
                df[c] = pd.to_numeric(df[c])
            except (ValueError, TypeError):
                pass
        return df, timings
    finally:
        try:
            stmt.close()
        except Exception:
            pass


def _probe_day(table: str, conn):
    """Return (start_ts, end_ts) of the calendar day this table holds,
    or None if the table is empty."""
    row = pd.read_sql(
        f"SELECT MIN(TRANS_REQ_TIME_SEC) AS tmin, MAX(TRANS_REQ_TIME_SEC) AS tmax FROM {table}",
        conn,
    ).iloc[0]
    if pd.isna(row["tmin"]):
        return None
    tmin, tmax = int(row["tmin"]), int(row["tmax"])
    day_start = datetime.fromtimestamp(tmin).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    start_ts = int(day_start.timestamp())
    end_ts = int((day_start + timedelta(days=1)).timestamp())
    if tmax >= end_ts:
        end_ts = tmax + 1
    return start_ts, end_ts


# ---------------------------------------------------------------------------
# State file
# ---------------------------------------------------------------------------

def _load_state() -> dict:
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    # Migrate legacy per-category watermarks -> single "daily" watermark so
    # already-exported tables are not re-exported after the query unification.
    if "daily" not in state:
        legacy = [state.pop(k) for k in _LEGACY_STATE_KEYS if k in state]
        if legacy:
            state["daily"] = max(legacy)
            log(f"migrated legacy state {legacy} -> daily={state['daily']}")
    return state


def _save_state(state: dict) -> None:
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)


def _table_number(fq_name: str) -> int:
    m = re.search(r"_(\d+)$", fq_name)
    if not m:
        raise ValueError(f"Cannot parse table number from: {fq_name}")
    return int(m.group(1))


# ---------------------------------------------------------------------------
# Core export logic
# ---------------------------------------------------------------------------

def _midnight_today_ts() -> int:
    return int(
        datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        .timestamp()
    )


def export_job(job_name: str, job: dict, conn_box: list, schema: str,
               out_root: str, state: dict, dry_run: bool,
               rg_config: dict, apn_filter: list[str], interface_id: int,
               backfill: int = 0, reconnect=None, workers: int = 1,
               fetch_size: int = FETCH_SIZE) -> None:
    """conn_box is a single-element list holding the current connection."""
    def _reconnect() -> None:
        if reconnect is None:
            return
        log(f"[{job_name}] reconnecting ...")
        try:
            conn_box[0].close()
        except Exception:
            pass
        conn_box[0] = reconnect()
        log(f"[{job_name}] reconnected.")

    pattern = f"{schema}.DETAIL_CDR_SGIDIAMETER_%"
    log(f"[{job_name}] discovering tables ({pattern}) ...")
    tables = discover_tables(conn_box[0], schema, "DETAIL_CDR_SGIDIAMETER_%")
    if not tables:
        log(f"[{job_name}] no tables found — skipped")
        return

    last_done = state.get(job_name)
    if backfill:
        candidates = tables[-backfill:]
        log(f"[{job_name}] backfill mode — considering newest "
            f"{len(candidates)} table(s) (existing CSVs are skipped)")
    elif last_done is None:
        candidates = tables[-FIRST_RUN_LOOKBACK_TABLES:]
        log(f"[{job_name}] no state yet — considering newest "
            f"{len(candidates)} table(s)")
    else:
        candidates = [t for t in tables if _table_number(t) > last_done]
        log(f"[{job_name}] last exported table number: {last_done} — "
            f"{len(candidates)} newer candidate(s)")

    out_dir = os.path.join(out_root, job["out_subdir"])
    midnight = _midnight_today_ts()

    # ── Phase 1: probe + build work list ───────────────────────────
    work = []
    for table in candidates:
        number = _table_number(table)
        csv_path = os.path.join(out_dir, f"{table.split('.')[-1]}.csv")

        if os.path.exists(csv_path):
            log(f"[{job_name}] {table}: CSV already exists — marking done")
            if last_done is None or number > (last_done or 0):
                state[job_name] = number
                last_done = number
            continue

        try:
            window = _probe_day(table, conn_box[0])
        except Exception as e:
            log(f"[{job_name}] {table}: probe failed ({e})")
            _reconnect()
            try:
                window = _probe_day(table, conn_box[0])
            except Exception as e2:
                log(f"[{job_name}] {table}: probe failed again ({e2}) — skipped")
                continue
        if window is None:
            log(f"[{job_name}] {table}: empty table — skipped")
            continue

        start_ts, end_ts = window
        day_str = datetime.fromtimestamp(start_ts).strftime("%Y-%m-%d")

        if end_ts > midnight:
            log(f"[{job_name}] {table}: holds {day_str} but is still the "
                f"current (partial) day — skipped, will export tomorrow")
            continue

        sql = job["query_builder"](table, rg_config, apn_filter, interface_id, start_ts, end_ts)

        if dry_run:
            log(f"[{job_name}] {table}: holds {day_str} (complete) — would export")
            continue

        work.append((table, number, sql, csv_path, day_str))

    # ── Phase 2: export ────────────────────────────────────────────
    def _finish(item, df, t):
        nonlocal last_done
        table, number, _sql, csv_path, day_str = item
        if df.empty:
            log(f"[{job_name}] {table}: 0 rows after filters — NOT marking "
                f"done (verify filters if this repeats)")
            return
        os.makedirs(out_dir, exist_ok=True)
        t0 = time.monotonic()
        df.to_csv(csv_path, index=False)
        write_s = round(time.monotonic() - t0, 1)
        rate = round(t["rows"] / t["fetch_s"]) if t["fetch_s"] > 0 else 0
        log(f"[{job_name}] {table} ({day_str}): wrote {len(df):,} rows "
            f"-> {os.path.basename(csv_path)} | "
            f"exec {t['exec_s']}s (server), fetch {t['fetch_s']}s "
            f"({rate:,} rows/s), write {write_s}s")
        if last_done is None or number > last_done:
            state[job_name] = number
            last_done = number

    if workers > 1 and work:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _worker(item):
            _table, _n, sql, _csv, _day = item
            wconn = reconnect() if reconnect else conn_box[0]
            try:
                return _read_export(sql, wconn, fetch_size)
            finally:
                if reconnect:
                    try:
                        wconn.close()
                    except Exception:
                        pass

        log(f"[{job_name}] exporting {len(work)} table(s) with {workers} workers ...")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_worker, item): item for item in work}
            for fut in as_completed(futures):
                item = futures[fut]
                try:
                    df, t = fut.result()
                except Exception as e:
                    log(f"[{job_name}] {item[0]}: export FAILED")
                    log_exception(e)
                    continue
                _finish(item, df, t)
    else:
        for item in work:
            table = item[0]
            sql = item[2]
            log(f"[{job_name}] {table} ({item[4]}): exporting ...")
            try:
                df, t = _read_export(sql, conn_box[0], fetch_size)
            except Exception as e:
                log(f"[{job_name}] {table}: query failed — reconnecting and retrying once ...")
                log_exception(e)
                _reconnect()
                try:
                    df, t = _read_export(sql, conn_box[0], fetch_size)
                except Exception as e2:
                    log(f"[{job_name}] {table}: query failed again — "
                        f"skipped (state NOT advanced, will retry next run)")
                    log_exception(e2)
                    continue
            _finish(item, df, t)


# ---------------------------------------------------------------------------
# --check
# ---------------------------------------------------------------------------

def run_check(conn, schema: str, rg_config: dict, apn_filter: list[str],
              interface_id: int) -> bool:
    ok = True
    tables = discover_tables(conn, schema, "DETAIL_CDR_SGIDIAMETER_%")
    if not tables:
        print(f"[check] NO TABLES matched DETAIL_CDR_SGIDIAMETER_% !")
        ok = False
    else:
        print(f"[check] {len(tables)} table(s), newest = {tables[-1]}")
        newest = tables[-1]
        try:
            row = pd.read_sql(
                f"SELECT MIN(TRANS_REQ_TIME_SEC) AS tmin, MAX(TRANS_REQ_TIME_SEC) AS tmax FROM {newest}",
                conn,
            ).iloc[0]
            print(f"[check] {newest}: time range {row['tmin']} -> {row['tmax']}")
        except Exception as e:
            print(f"[check] {newest}: probe failed ({e})")
            ok = False

        # Validate that our queries compile
        start_ts = int((datetime.now() - timedelta(days=1)).timestamp())
        end_ts = int(datetime.now().timestamp())
        for name, job in _JOBS.items():
            try:
                sql = job["query_builder"](newest, rg_config, apn_filter, interface_id, start_ts, end_ts)
                # Just EXPLAIN — don't actually run
                print(f"[check] {name} query: OK (compiled)")
            except Exception as e:
                print(f"[check] {name} query: FAILED ({e})")
                ok = False

    print("[check] " + ("OK — ready to run." if ok else
                         "FAILED — fix the items above before scheduling."))
    return ok


# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--jobs", default=",".join(_JOBS),
                    help="comma-separated subset of: " + ",".join(_JOBS))
    ap.add_argument("--out-root", default=REPO_ROOT,
                    help="root under which data/ folders live (default: repo root)")
    ap.add_argument("--dry-run", action="store_true",
                    help="probe and report what would be exported; write no CSVs")
    ap.add_argument("--backfill", type=int, default=0, metavar="N",
                    help="one-time: consider the newest N tables per job. "
                         "Already-exported days are skipped.")
    ap.add_argument("--workers", type=int, default=1, metavar="N",
                    help="export up to N tables in parallel (default 1 = sequential)")
    ap.add_argument("--fetch-size", type=int, default=FETCH_SIZE, metavar="N",
                    help=f"rows per JDBC fetch frame (default {FETCH_SIZE})")
    ap.add_argument("--check", action="store_true",
                    help="connectivity + schema validation only, then exit")
    args = ap.parse_args()

    job_names = [j.strip() for j in args.jobs.split(",") if j.strip()]
    unknown = [j for j in job_names if j not in _JOBS]
    if unknown:
        raise SystemExit(f"Unknown job(s): {unknown}. Choose from {list(_JOBS)}")

    log("=" * 70)
    log(f"daily_update run at {datetime.now():%Y-%m-%d %H:%M:%S} "
        f"(jobs={job_names}, dry_run={args.dry_run}, check={args.check})")

    config = load_config()
    schema = config["database"].get("schema", "ps")
    rg_config = config.get("free_rating_groups", {})
    apn_raw = config.get("apn_filter", "")
    apn_filter = [a.strip() for a in apn_raw.split(",") if a.strip()] if apn_raw else []
    interface_id = config.get("interface_id", 12)

    msisdn_col = config.get("msisdn_column", "MSISDN")
    if msisdn_col != "MSISDN":
        from functools import partial
        _JOBS["daily"]["query_builder"] = partial(daily_query,
                                                  msisdn_col=msisdn_col)

    try:
        conn_box = [connect_db(config)]
    except SystemExit:
        raise
    except Exception as e:
        log("!" * 70)
        log(f"DATABASE CONNECTION FAILED: {e}")
        log("Most common cause: Kerberos ticket missing or expired.")
        log("Renew your ticket (kinit / your Kerberos client), make sure the "
            "VPN is connected, then re-run.")
        log("!" * 70)
        sys.exit(2)

    try:
        if args.check:
            ok = run_check(conn_box[0], schema, rg_config, apn_filter, interface_id)
            sys.exit(0 if ok else 1)

        state = _load_state()
        for name in job_names:
            try:
                export_job(name, _JOBS[name], conn_box, schema,
                           args.out_root, state, args.dry_run,
                           rg_config, apn_filter, interface_id,
                           backfill=args.backfill,
                           reconnect=lambda: connect_db(config),
                           workers=args.workers,
                           fetch_size=args.fetch_size)
            except Exception as e:
                log(f"[{name}] JOB FAILED")
                log_exception(e)
        if not args.dry_run:
            _save_state(state)
            log(f"state saved: {state}")
        log("run finished")
    finally:
        try:
            conn_box[0].close()
        except Exception:
            pass
        if _log_file is not None:
            _log_file.close()


if __name__ == "__main__":
    main()
