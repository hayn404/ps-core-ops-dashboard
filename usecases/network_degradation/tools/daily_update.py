#!/usr/bin/env python3
"""Daily incremental export of TCP-KPI tables to CSV.

Runs every morning (via Task Scheduler -> tools\\run_daily_update.bat) on a
VPN-connected Windows laptop with a valid Kerberos ticket.

What it does, per job (ipv6 subnets / ipv4 subnets / site-level FR2&FR3):
  1. Discovers existing tables via SHOW TABLES LIKE <pattern>.
  2. Picks candidate tables newer than the last exported one (state file).
  3. Probes each candidate's MIN/MAX(timecolumn) to learn its calendar date.
  4. Exports every candidate whose day is fully in the past and not already
     exported -> one CSV per table in the job's data folder.

Because selection is date-probe based (not table-number arithmetic), the
script is immune to table-number gaps and automatically backfills days missed
while the laptop was off. The partial current-day table is never exported.

Requires a valid Kerberos ticket (renewed daily) — the script exits with a
clear message if the ticket is missing/expired.
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

# Repo root on sys.path so we can reuse dashboard.py's Kerberos/DB stack.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from dashboard import connect_db, discover_tables, _query, _GW_CASE_SQL  # noqa: E402

STATE_PATH = os.path.join(REPO_ROOT, "tools", ".daily_update_state.json")
LOG_PATH = os.path.join(REPO_ROOT, "tools", "daily_update.log")

# How many of the newest tables to consider when there is no state yet
# (first run / new laptop). After that, the state file governs.
FIRST_RUN_LOOKBACK_TABLES = 5

# Columns the site query depends on — verified by --check before first use.
SITE_REQUIRED_COLS = (
    "cgisai",
    "rat",
    "timecolumn",
    "ide_total_tcp_conn_times",
    "ide_total_tcp_conn_2_failed_times",
    "ide_total_tcp_conn_3_failed_times",
)
CELLMAP_REQUIRED_COLS = ("cgisai", "site", "Cell_Name")

_JOBS = {
    "ipv6": {
        "pattern": "sdr_dyn_ide_soc_tcp_user_15m_%",
        "out_subdir": os.path.join("data", "data_ipv6"),
        "kind": "subnet",
        "ip_family": "ipv6",
    },
    "ipv4": {
        "pattern": "sdr_dyn_ide_soc_tcp_user_15m_%",
        "out_subdir": os.path.join("data", "data_ipv4"),
        "kind": "subnet",
        "ip_family": "ipv4",
    },
    "site": {
        "pattern": "SDR_DYN_IDE_SOC_TCP_CELL_USER_15m_%",
        "out_subdir": os.path.join("data", "data_site"),
        "kind": "site",
    },
    "site_cells": {
        "pattern": "SDR_DYN_IDE_SOC_TCP_CELL_USER_15m_%",
        "out_subdir": os.path.join("data", "data_site_cells"),
        "kind": "site_cells",
    },
}


# ---------------------------------------------------------------------------
# Logging: stdout + append to tools/daily_update.log
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
        pass  # logging must never break the run


def log_exception(e: Exception) -> None:
    """Log an exception, including the Java stack trace when it is a jpype
    wrapped Java exception — the one-line str(e) is usually useless."""
    log(f"    error: {type(e).__name__}: {e}")
    stacktrace = getattr(e, "stacktrace", None)
    if callable(stacktrace):
        try:
            log("----- Java stack trace -----\n" + stacktrace() +
                "\n----------------------------")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------
_HOUR_EXPR = (
    "FROM_UNIXTIME((a.timecolumn - (a.timecolumn % 3600)) + 2 * 3600, "
    "'yyyy/MM/dd HH:00')"
)
# FR formula exactly as the manager's scripts: numerator and denominator
# only count rows where attempts > 0. Same denominator for FR2 and FR3.
_FR_DENOM = ("SUM(CASE WHEN a.IDE_TOTAL_TCP_CONN_TIMES > 0 "
             "THEN a.IDE_TOTAL_TCP_CONN_TIMES ELSE NULL END)")
_FR2_EXPR = (
    "CAST(SUM(CASE WHEN a.IDE_TOTAL_TCP_CONN_TIMES > 0 "
    "THEN a.IDE_TOTAL_TCP_CONN_2_FAILED_TIMES ELSE 0 END) * 100.0 "
    f"/ NULLIF({_FR_DENOM}, 0) AS DECIMAL(20,2))"
)
_FR3_EXPR = (
    "CAST(SUM(CASE WHEN a.IDE_TOTAL_TCP_CONN_TIMES > 0 "
    "THEN a.IDE_TOTAL_TCP_CONN_3_FAILED_TIMES ELSE 0 END) * 100.0 "
    f"/ NULLIF({_FR_DENOM}, 0) AS DECIMAL(20,2))"
)


def _site_query(table: str, map_table: str, start_ts: int, end_ts: int) -> str:
    """Site-level FR2/FR3 for one cell-level table.

    Per the manager's source scripts (see project-summary.md): FR2 and FR3
    share the same denominator, SUM(ide_total_tcp_conn_times); site comes from
    the cell-mapping-table join; filter is rat = 6. Deliberately no single-site
    filter and no HAVING floor — all sites are needed for peer comparison.
    """
    return f"""
        SELECT
            {_HOUR_EXPR}                                                 AS hour,
            {_GW_CASE_SQL}                                               AS ugw,
            b.site                                                       AS site,
            COUNT(*)                                                     AS session_count,
            {_FR2_EXPR}                                                  AS tcp_2_fr,
            {_FR3_EXPR}                                                  AS tcp_3_fr
        FROM {table} a
        JOIN {map_table} b ON a.cgisai = b.cgisai
        WHERE a.rat = 6
          AND a.timecolumn >= {start_ts}
          AND a.timecolumn < {end_ts}
        GROUP BY
            {_HOUR_EXPR},
            {_GW_CASE_SQL},
            b.site
    """


def _site_cells_query(table: str, map_table: str, start_ts: int,
                      end_ts: int) -> str:
    """Cell-level FR2/FR3 — same formula as _site_query but one row per
    cell (cgisai / Cell_Name), feeding the dashboard's site drill-down."""
    return f"""
        SELECT
            {_HOUR_EXPR}                                                 AS hour,
            {_GW_CASE_SQL}                                               AS ugw,
            b.site                                                       AS site,
            b.Cell_Name                                                  AS cell_name,
            a.cgisai                                                     AS cgisai,
            COUNT(*)                                                     AS session_count,
            {_FR2_EXPR}                                                  AS tcp_2_fr,
            {_FR3_EXPR}                                                  AS tcp_3_fr
        FROM {table} a
        JOIN {map_table} b ON a.cgisai = b.cgisai
        WHERE a.rat = 6
          AND a.timecolumn >= {start_ts}
          AND a.timecolumn < {end_ts}
        GROUP BY
            {_HOUR_EXPR},
            {_GW_CASE_SQL},
            b.site,
            b.Cell_Name,
            a.cgisai
    """


# Rows per thrift fetch batch (pyhive Cursor.arraysize). 500 is a reasonable
# middle ground between round-trip overhead (too small) and holding a huge
# batch in memory at once (too large). Override with --fetch-size if needed.
FETCH_SIZE = 500


def _read_export(sql: str, conn,
                 fetch_size: int = FETCH_SIZE) -> "tuple[pd.DataFrame, dict]":
    """Execute an export query via the DB-API cursor (server SASL/thrift
    connection) and time server vs. client phases.

    Note: the local/Windows dev version of this function used a JDBC-specific
    trick (`conn.jconn.createStatement()` with a manual `setFetchSize`) to
    work around that driver's fetch-size corruption bug. That bug is JDBC
    driver-specific and doesn't apply to the SASL/thrift connection used on
    the Linux server, so this uses the plain DB-API cursor instead.

    Returns (dataframe, timings) where timings splits server-side compute
    (exec_s: until the query returns) from client-side transmission
    (fetch_s: pulling the rows) — that split tells you whether slowness is
    the query or the network."""
    cur = conn.cursor()
    try:
        cur.arraysize = fetch_size
        t0 = time.monotonic()
        cur.execute(sql)
        timings = {"exec_s": round(time.monotonic() - t0, 1)}

        t1 = time.monotonic()
        rows = cur.fetchall()
        cols = [d[0].split(".")[-1] for d in cur.description]
        timings["fetch_s"] = round(time.monotonic() - t1, 1)
        timings["rows"] = len(rows)

        df = pd.DataFrame.from_records(rows, columns=cols)
        for c in df.columns:
            try:
                df[c] = pd.to_numeric(df[c])
            except (ValueError, TypeError):
                pass  # genuinely string column (hour, ugw, site, cgisai)
        return df, timings
    finally:
        try:
            cur.close()
        except Exception:
            pass


def _probe_day(table: str, conn):
    """Return (start_ts, end_ts) of the calendar day this table holds,
    or None if the table is empty. Probe is one lightweight scan."""
    row = pd.read_sql(
        f"SELECT MIN(timecolumn) AS tmin, MAX(timecolumn) AS tmax FROM {table}",
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
    # Sanity: a rotated per-day table should sit inside one calendar day.
    # If it spills past midnight, clamp the window to the probe range instead.
    if tmax >= end_ts:
        end_ts = tmax + 1
    return start_ts, end_ts


# ---------------------------------------------------------------------------
# State file
# ---------------------------------------------------------------------------
def _load_state() -> dict:
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


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


def _reconnect_with_retries(reconnect, job_name: str, attempts: int = 3,
                            delay_s: float = 15.0):
    """Call `reconnect()`, retrying a few times with a short delay.

    A Spark Thrift Server restart (the underlying service, not just a
    dropped socket) can take a minute or two to come back up — a single
    immediate retry right after the failure often just hits the same
    still-restarting server. Spacing attempts out gives it a real chance
    to recover before we give up on the whole run.
    """
    last_err = None
    for attempt in range(1, attempts + 1):
        try:
            conn = reconnect()
            if attempt > 1:
                log(f"[{job_name}] reconnected on attempt {attempt}.")
            else:
                log(f"[{job_name}] reconnected.")
            return conn
        except Exception as e:
            last_err = e
            log(f"[{job_name}] reconnect attempt {attempt}/{attempts} "
                f"failed: {e}")
            if attempt < attempts:
                time.sleep(delay_s)
    raise last_err


def export_job(job_name: str, job: dict, conn_box: list, schema: str,
               out_root: str, state: dict, dry_run: bool, map_table: str,
               backfill: int = 0, reconnect=None, workers: int = 1,
               fetch_size: int = FETCH_SIZE) -> None:
    """conn_box is a single-element list holding the current connection —
    mutable so a mid-run reconnect is visible to main() (which closes it).
    `reconnect` (optional) is a zero-arg callable returning a fresh
    connection; on a transient failure (read timeout, connection reset)
    the failing probe/query is retried once on a new connection before the
    table is skipped."""
    def _reconnect() -> None:
        if reconnect is None:
            return
        log(f"[{job_name}] reconnecting ...")
        try:
            conn_box[0].close()
        except Exception:
            pass
        # Retry with backoff rather than raising on the first failure — if
        # this raises anyway (server still down after all attempts), the
        # caller's except block handles it and conn_box[0] is left as the
        # already-closed connection, which main() will refresh before the
        # next job runs.
        conn_box[0] = _reconnect_with_retries(reconnect, job_name)

    log(f"[{job_name}] discovering tables ({job['pattern']}) ...")
    try:
        tables = discover_tables(conn_box[0], schema, job["pattern"])
    except Exception as e:
        log(f"[{job_name}] table discovery failed ({e}) — reconnecting "
            f"and retrying once ...")
        _reconnect()
        tables = discover_tables(conn_box[0], schema, job["pattern"])
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

    # ── Phase 1: probe + build the work list (sequential, probes are cheap)
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
                log(f"[{job_name}] {table}: probe failed again ({e2}) "
                    f"— skipped")
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

        if dry_run:
            log(f"[{job_name}] {table}: holds {day_str} (complete) — "
                f"would export")
            continue

        if job["kind"] == "subnet":
            sql = _query(table, start_ts, job["ip_family"], end_ts=end_ts)
        elif job["kind"] == "site_cells":
            sql = _site_cells_query(table, map_table, start_ts, end_ts)
        else:
            sql = _site_query(table, map_table, start_ts, end_ts)

        work.append((table, number, sql, csv_path, day_str))

    # ── Phase 2: export (sequential, or parallel with --workers)
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
            # Each worker gets its OWN connection — thrift/SASL connections
            # are not thread-safe, so sharing one across threads would
            # corrupt concurrent reads.
            wconn = reconnect() if reconnect else conn_box[0]
            try:
                return _read_export(sql, wconn, fetch_size)
            finally:
                if reconnect:
                    try:
                        wconn.close()
                    except Exception:
                        pass

        log(f"[{job_name}] exporting {len(work)} table(s) with "
            f"{workers} workers ...")
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
                log(f"[{job_name}] {table}: query failed — reconnecting "
                    f"and retrying once ...")
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
# --check: connectivity + schema validation before first real run
# ---------------------------------------------------------------------------
def run_check(conn, schema: str, map_table: str) -> bool:
    ok = True
    for job_name, job in _JOBS.items():
        tables = discover_tables(conn, schema, job["pattern"])
        if not tables:
            print(f"[check] {job_name}: NO TABLES matched {job['pattern']} !")
            ok = False
            continue
        print(f"[check] {job_name}: {len(tables)} table(s), "
              f"newest = {tables[-1]}")

    site_tables = discover_tables(conn, schema, _JOBS["site"]["pattern"])
    if site_tables:
        newest = site_tables[-1]
        cols = set(pd.read_sql(f"DESCRIBE {newest}", conn).iloc[:, 0].astype(str))
        missing = [c for c in SITE_REQUIRED_COLS if c not in cols]
        if missing:
            print(f"[check] site table {newest}: MISSING columns {missing}")
            print("        -> fix SITE_REQUIRED_COLS / _site_query to match "
                  "the real schema")
            ok = False
        else:
            print(f"[check] site table {newest}: all required columns present")

    if _check_map_table(conn, map_table):
        print(f"[check] cell mapping table {map_table}: cgisai + site present")
    else:
        ok = False
        print(f"[check] configured mapping table {map_table} NOT usable.")
        _sweep_for_map_table(conn, schema)

    print("[check] " + ("OK — ready to run." if ok else
                        "FAILED — fix the items above before scheduling."))
    return ok


def _check_map_table(conn, map_table: str) -> bool:
    try:
        cols = set(pd.read_sql(f"DESCRIBE {map_table}", conn)
                   .iloc[:, 0].astype(str))
        return all(c in cols for c in CELLMAP_REQUIRED_COLS)
    except Exception:
        return False


def _sweep_for_map_table(conn, schema: str) -> None:
    """The configured mapping table wasn't found — search every schema for
    tables with 'cellmap' in the name and report which ones have the
    required cgisai/site columns."""
    print("[check] searching all schemas for a cell-mapping table ...")
    try:
        dbs = (pd.read_sql("SHOW DATABASES", conn).iloc[:, 0]
               .astype(str).tolist())
    except Exception as e:
        print(f"[check]   SHOW DATABASES failed ({e}) — cannot search")
        return
    for db in dbs:
        try:
            hits = [t for t in discover_tables(conn, db, "%cellmap%")
                    if "_bak" not in t.lower()]
        except Exception:
            continue
        for t in hits:
            usable = _check_map_table(conn, t)
            print(f"[check]   candidate: {t}  "
                  f"-> {'USABLE (has cgisai + site)' if usable else 'missing required columns'}")
            if usable:
                print(f"[check]   => set site_map_table: \"{t}\" in "
                      f"config/config.yaml")


# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--jobs", default=",".join(_JOBS),
                    help="comma-separated subset of: " + ",".join(_JOBS))
    ap.add_argument("--out-root", default=REPO_ROOT,
                    help="root under which data/<subdir> folders live "
                         "(default: repo root)")
    ap.add_argument("--dry-run", action="store_true",
                    help="probe and report what would be exported; "
                         "write no CSVs and do not touch the state file")
    ap.add_argument("--backfill", type=int, default=0, metavar="N",
                    help="one-time: consider the newest N tables per job "
                         "(instead of only new ones) to pull older days. "
                         "Tables whose CSV already exists are skipped, so "
                         "this never re-exports. e.g. --backfill 10 for "
                         "week-before comparisons")
    ap.add_argument("--workers", type=int, default=1, metavar="N",
                    help="export up to N tables in parallel, each on its "
                         "own DB connection (default 1 = sequential). Try "
                         "3-4 for backfills; watch the per-table timing "
                         "log to see if the server keeps up")
    ap.add_argument("--fetch-size", type=int, default=FETCH_SIZE, metavar="N",
                    help=f"rows per thrift fetch batch (default {FETCH_SIZE}). "
                         "Larger can be faster but uses more memory per "
                         "batch; lower it if you see connection resets on "
                         "very wide/heavy exports")
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

    from dashboard import load_config
    config = load_config()
    schema = config["database"].get("schema", "sdr_nethouse")
    map_table = config["database"].get("site_map_table",
                                       f"{schema}.cellmappingtest")

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
            ok = run_check(conn_box[0], schema, map_table)
            sys.exit(0 if ok else 1)

        state = _load_state()
        for name in job_names:
            try:
                export_job(name, _JOBS[name], conn_box, schema,
                           args.out_root, state, args.dry_run, map_table,
                           backfill=args.backfill,
                           reconnect=lambda: connect_db(config),
                           workers=args.workers,
                           fetch_size=args.fetch_size)
            except Exception as e:
                # One job failing must not kill the others. Try to leave
                # conn_box[0] holding a live connection before the next
                # job runs, so a mid-run server outage doesn't cascade
                # into every remaining job failing instantly.
                log(f"[{name}] JOB FAILED")
                log_exception(e)
                try:
                    conn_box[0].close()
                except Exception:
                    pass
                try:
                    conn_box[0] = _reconnect_with_retries(
                        lambda: connect_db(config), name)
                except Exception as e2:
                    log(f"[{name}] could not restore a DB connection after "
                        f"the failure ({e2}); remaining jobs will likely "
                        f"fail too until the server recovers.")
        if not args.dry_run:
            _save_state(state)
            log(f"state saved: {state}")
        log("run finished")
    finally:
        try:
            conn_box[0].close()
        except Exception:
            # Closing a dead connection (e.g. after a server-side reset)
            # throws a cosmetic SQLException — don't mask the real results.
            pass
        if _log_file is not None:
            _log_file.close()


if __name__ == "__main__":
    main()
