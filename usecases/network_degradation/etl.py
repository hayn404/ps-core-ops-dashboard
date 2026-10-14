#!/usr/bin/env python3
"""
etl.py - the ONLY data script for the Network Degradation dashboard.

Everything the dashboard shows is computed here, inside ClickHouse, and stored
in ready-to-read tables. The dashboard itself only runs simple SELECTs.

    Hive (sdr_nethouse)                                         ClickHouse (ps_core_ops)
    -------------------                                         ------------------------
    15-minute TCP tables  --fetch-->  RAW  network_degradation_ipv6 / _ipv4 / _site / _site_cells
                                        |
                                        |  transform (pure SQL, one day at a time, idempotent)
                                        v
                                      DERIVED (what the dashboard reads)
                                        nd_subnet_hourly   IPv6 rolled up to /48 + IPv4 /24, with
                                                           peer baselines and sr_drop already computed
                                        nd_pool_hourly     TCP SR / FR2 per IP pool per hour + baselines
                                        nd_pool_daily      one TCP FR2 / SR number per pool per day
                                        nd_site_hourly     site-level FR3 per hour
                                        nd_site_baseline   each site's own "normal" level
                                        nd_cell_daily      per-cell FR3 for the site drill-down
                                      DIMENSIONS
                                        dim_pool           the pools from config/ip_pools.csv
                                        nd_subnet_pool_map subnet -> pool(s) (built once per new subnet)
                                        nd_ingest_log      which Hive tables were already loaded

Commands (run from this folder, python3.9):
    python3.9 etl.py daily                # what cron runs: fetch new days + build derived tables
    python3.9 etl.py fetch --backfill 10  # pull older days from Hive that are missing
    python3.9 etl.py fetch --check        # test Hive connection / tables only
    python3.9 etl.py transform --days 30 --rebuild   # rebuild derived tables from RAW data
    python3.9 etl.py pools                # reload config/ip_pools.csv (run when the sheet changes)
    python3.9 etl.py status               # what is in the database

A valid Kerberos ticket is only needed for `fetch`/`daily` (tools/run_daily_update.sh
does the kinit). `transform`, `pools` and `status` only talk to ClickHouse.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import os
import re
import sys
import time
from collections import defaultdict, namedtuple
from datetime import datetime, timedelta

import pandas as pd
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config", "config.yaml")
POOLS_CSV = os.path.join(HERE, "config", "ip_pools.csv")
LOG_PATH = os.path.join(HERE, "etl.log")

_TOP_TOOLS = os.path.join(os.path.dirname(os.path.dirname(HERE)), "tools")
if _TOP_TOOLS not in sys.path:
    sys.path.insert(0, _TOP_TOOLS)
from clickhouse_io import RETENTION_DAYS, get_client, write_dataframe  # noqa: E402

# Tunables ---------------------------------------------------------------------
BASELINE_DAYS = 10          # window for each site's "own normal" level
MIN_POOL_SESSIONS = 50_000  # pools below this per hour are not used as peers
DEAD_SR_MAX_PCT = 1.0       # a subnet whose SR never exceeds this across its
                             # whole history is permanently dead/broken, not
                             # real traffic (small, nonzero noise like 0.01%
                             # or 0.08% still counts as "dead" — only an
                             # exact 0.0 would, which real noise never is;
                             # keep in sync with dashboard.py's DEAD_SR_MAX_PCT)
FIRST_RUN_LOOKBACK_TABLES = 5

RAW = {
    "ipv6": "network_degradation_ipv6",
    "ipv4": "network_degradation_ipv4",
    "site": "network_degradation_site",
    "site_cells": "network_degradation_site_cells",
}
# ReplacingMergeTree dedup key of the RAW tables - must identify every real row.
_CH_ORDER_BY = {
    "ipv6": ["report_date", "hour", "ugw", "ipv6_prefix_48"],
    "ipv4": ["report_date", "hour", "ugw", "ipv4_prefix_24"],
    "site": ["report_date", "hour", "ugw", "site"],
    "site_cells": ["report_date", "hour", "ugw", "site", "cell_name"],
}

_JOBS = {
    "ipv6": {"pattern": "sdr_dyn_ide_soc_tcp_user_15m_%", "kind": "subnet", "ip_family": "ipv6"},
    "ipv4": {"pattern": "sdr_dyn_ide_soc_tcp_user_15m_%", "kind": "subnet", "ip_family": "ipv4"},
    "site": {"pattern": "SDR_DYN_IDE_SOC_TCP_CELL_USER_15m_%", "kind": "site"},
    "site_cells": {"pattern": "SDR_DYN_IDE_SOC_TCP_CELL_USER_15m_%", "kind": "site_cells"},
}

SITE_REQUIRED_COLS = (
    "cgisai", "rat", "timecolumn", "ide_total_tcp_conn_times",
    "ide_total_tcp_conn_2_failed_times", "ide_total_tcp_conn_3_failed_times",
)
CELLMAP_REQUIRED_COLS = ("cgisai", "site", "Cell_Name")

_log_file = None


def log(msg: str) -> None:
    global _log_file
    print(msg, flush=True)
    try:
        if _log_file is None:
            _log_file = open(LOG_PATH, "a", encoding="utf-8")
        _log_file.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}\n")
        _log_file.flush()
    except OSError:
        pass  # logging must never break a run


def log_exception(e: Exception) -> None:
    """Log an exception, including the Java stack trace for jpype errors."""
    log(f"    error: {type(e).__name__}: {e}")
    st = getattr(e, "stacktrace", None)
    if callable(st):
        try:
            log("----- Java stack trace -----\n" + st() + "\n----------------------------")
        except Exception:
            pass


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


# =============================================================================
# 1. HIVE ACCESS  (Kerberos / SASL / thrift - unchanged from the proven version)
# =============================================================================

GATEWAY_MAP = {
    27:     "RamsisPost_PDG25",  200036: "RamsisPost_PDG25",
    20:     "Aburawash_R1DG28",  200042: "Aburawash_R1DG28",
    19:     "Banisuif_FGG13",    200019: "Banisuif_FGG13",
    41:     "SV_UDG01",          200053: "SV_UDG01",
    26:     "AlexPost_ODG21",    200028: "AlexPost_ODG21",
    1:      "AlexAuto_XGG09",    200015: "AlexAuto_XGG09",
    # --- Added for the ip_pools.xlsx / "TCP FR2 per pool" request ---
    # Confirmed via sdr_nethouse.dim_loc_ggsn_pgw (GGSN_PGW_ID -> GGSN_PGW_NAME),
    # not the earlier IP-sampling heuristic in discover_gw_ids_v2.py. Each
    # gateway has two active ggsn_pgw_ids in Hive (base + _PGW_U/_PGWU
    # user-plane variant); both map to the same name here, same as the
    # existing entries above.
    200031: "Aburawash_R1DG18", 30: "Telemisr_YDG29", 200039: "Telemisr_YDG29",
    31:     "Telemisr_YDG30",  200044: "Telemisr_YDG30",
    200022: "Tanta_TGG14",
}


GW_IDS_SQL = ", ".join(str(g) for g in GATEWAY_MAP)


class _PureSASLAdapter:
    """Adapts pure-sasl's SASLClient API to the one thrift_sasl expects.

    thrift_sasl calls .start(mechanism), .step(challenge), .encode/.decode,
    .getError() and .dispose() — the old python-sasl interface. pure-sasl
    uses choose_mechanism() / process() / wrap() / unwrap() — different
    method names and return shapes. This wrapper bridges the two.
    """

    def __init__(self, host, service):
        from puresasl.client import SASLClient
        # qops=['auth'] forces "authentication only" — no message encryption
        # or integrity wrapping. This is critical: pure-sasl's GSSAPI wrap()
        # produces bytes that some Hadoop deployments (e.g. Huawei FusionInsight)
        # silently refuse, causing the connection to hang forever after the
        # SASL handshake. With qops=['auth'], wrap/unwrap become pass-throughs.
        self._sasl = SASLClient(host=host, service=service, qops=[b"auth"])
        self._error = ""

    def start(self, mechanism):
        try:
            self._sasl.choose_mechanism([mechanism], allow_anonymous=False)
            response = self._sasl.process() or b""
            return True, mechanism, response
        except Exception as e:
            self._error = str(e)
            return False, mechanism, b""

    def step(self, challenge):
        try:
            response = self._sasl.process(challenge) or b""
            return True, response
        except Exception as e:
            self._error = str(e)
            return False, b""

    def encode(self, data):
        # thrift_sasl expects (success_bool, encoded_bytes). pure-sasl's
        # wrap() returns raw bytes (or raises). Adapt accordingly.
        try:
            wrapped = self._sasl.wrap(data)
            return True, wrapped if wrapped is not None else b""
        except Exception as e:
            self._error = str(e)
            return False, b""

    def decode(self, data):
        try:
            unwrapped = self._sasl.unwrap(data)
            return True, unwrapped if unwrapped is not None else b""
        except Exception as e:
            self._error = str(e)
            return False, b""

    def getError(self):
        return self._error

    def dispose(self):
        try:
            self._sasl.dispose()
        except Exception:
            pass


def connect_db(config: dict):
    # Server (Linux) connection path — SASL/thrift over Kerberos. Left exactly
    # as the version already proven working on the Linux server; the JDBC
    # (Windows/DBeaver-style) path from the local dev version is intentionally
    # not carried over here.
    try:
        from pyhive import hive
        from thrift.transport.TSocket import TSocket
        from thrift_sasl import TSaslClientTransport
    except ImportError as e:
        raise SystemExit(
            f"Missing import for live-DB mode: {e}\n"
            "Required packages: pyhive, thrift, thrift_sasl, pure-sasl\n"
            "Or use offline mode: python dashboard.py --csv your_file_or_folder"
        )

    db = config["database"]
    host      = db["host"]
    port      = int(db["port"])
    service   = db["kerberos_service_name"]
    schema    = db.get("schema", "sdr_nethouse")
    # The Kerberos SPN is almost always registered against a hostname (FQDN),
    # not an IP — so use a dedicated `kerberos_host` field if provided; fall
    # back to `host` only if not set.
    krb_host  = db.get("kerberos_host", host)
    print(f"Connecting to Hive at {host}:{port} "
          f"(Kerberos SPN: {service}/{krb_host}) ...")

    # Prefer the C-based `sasl` module — it's what every Hadoop deployment
    # actually uses, and it's the only library that reliably implements
    # GSSAPI auth-conf (the encrypted wrap that Huawei FusionInsight requires).
    # Pure-sasl is kept as a fallback for environments where the C module
    # isn't available.
    try:
        import sasl as _csasl
        def sasl_factory():
            c = _csasl.Client()
            c.setAttr("host",       krb_host)
            c.setAttr("service",    service)
            # Increase the SASL layer max buffer size. Default 64KB; setting
            # it explicitly to 1MB sometimes bypasses a cyrus-sasl code path
            # that requires a CANON_USER callback (which the python-sasl
            # bindings don't register), showing up as
            # "Unable to find a callback: 32775".
            c.setAttr("maxbufsize", 1_048_576)
            c.init()
            return c
        print("  using C sasl library (cyrus-sasl)")
    except ImportError:
        sasl_factory = lambda: _PureSASLAdapter(krb_host, service)
        print("  using pure-sasl adapter (fallback)")

    socket = TSocket(host, port)
    # 20-minute socket timeout. Per-day aggregations on the 15m tables
    # can take several minutes when the day has real matching data
    # (thousands of subnets * hours * gateways combinations). We proved
    # earlier that 5 minutes is not enough for busy days.
    socket.setTimeout(1_200_000)  # milliseconds

    transport = TSaslClientTransport(sasl_factory, "GSSAPI", socket)
    conn = hive.connect(thrift_transport=transport, database=schema)
    print("Connected successfully.")
    return conn


_GW_CASE_SQL = "CASE ggsn_pgw_id\n" + "\n".join(
    f"        WHEN {gid} THEN '{name}'" for gid, name in GATEWAY_MAP.items()
) + "\n        ELSE CAST(ggsn_pgw_id AS STRING)\n    END"


_IPV6_PREFIX_SQL = (
    "CASE WHEN SIZE(SPLIT(ms_ip_pa,':')) >= 4 "
    "THEN CONCAT(SPLIT(ms_ip_pa,':')[0],':',SPLIT(ms_ip_pa,':')[1],':',"
    "SPLIT(ms_ip_pa,':')[2],':',SPLIT(ms_ip_pa,':')[3]) "
    "WHEN SIZE(SPLIT(ms_ip_pa,':')) >= 3 "
    "THEN CONCAT(SPLIT(ms_ip_pa,':')[0],':',SPLIT(ms_ip_pa,':')[1],':',SPLIT(ms_ip_pa,':')[2]) "
    "ELSE ms_ip_pa END"
)


_IPV4_PREFIX_SQL = "SUBSTRING_INDEX(ms_ip_pa, '.', 3)"


_IPV6_FILTER = (
    "ms_ip_type_pa = 'IPV6' "
    "AND (ms_ip_pa LIKE '2c0f:fc89:%' OR ms_ip_pa LIKE '2c0f:fc88:%')"
)


_IPV4_FILTER = (
    "ms_ip_type_pa = 'IPV4' "
    "AND ms_ip_pa <> '0.0.0.0' "
    "AND ( ms_ip_pa LIKE '10.%' "
    "  OR ms_ip_pa RLIKE '^172\\\\.(1[6-9]|2[0-9]|3[01])\\\\.' "
    "  OR ms_ip_pa RLIKE '^100\\\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\\\.' )"
)


def _query(table: str, cutoff_ts: int, ip_family: str = "ipv6",
           end_ts: "int | None" = None) -> str:
    """SQL for one 15-minute table.

    `end_ts` (optional) adds an upper bound `timecolumn < end_ts` — used by
    tools/daily_update.py to export exactly one completed day. The live-DB
    dashboard path never passes it.

    We aggregate at the subnet-prefix level *in SQL* (not in pandas). This
    matches what `tools/generate_data_sql.py` produces for the CSV-export
    workflow and keeps each table's result set in the thousands of rows
    instead of the tens of millions that the old raw-per-IP query returned.
    That was the root cause of the BrokenPipe crashes on busy days.

    Columns emitted match the CSV export format so `prepare()` auto-detects
    it as the aggregated path (fast — no per-IP rollup in Python).
    """
    if ip_family.lower() == "ipv4":
        prefix_sql   = _IPV4_PREFIX_SQL
        prefix_col   = "ipv4_prefix_24"
        ip_filter    = _IPV4_FILTER
    else:
        prefix_sql   = _IPV6_PREFIX_SQL
        prefix_col   = "ipv6_prefix_48"
        ip_filter    = _IPV6_FILTER

    return f"""
        SELECT
            FROM_UNIXTIME(
                CAST(timecolumn AS BIGINT) - (CAST(timecolumn AS BIGINT) % 3600),
                'yyyy/MM/dd HH:00'
            )                                                       AS hour,
            {_GW_CASE_SQL}                                          AS ugw,
            {prefix_sql}                                            AS {prefix_col},
            COUNT(*)                                                AS session_count,
            SUM(ide_total_tcpconnsucccount) * 100.0
                / NULLIF(SUM(ide_total_tcpconncount), 0)            AS tcp_sr,
            SUM(ide_total_tcp_conn_2_failed_times) * 100.0
                / NULLIF(SUM(ide_total_tcp_conn_times), 0)          AS tcp_fr2
        FROM {table}
        WHERE timecolumn >= {cutoff_ts}
          {"AND timecolumn < " + str(end_ts) if end_ts is not None else ""}
          AND {ip_filter}
          AND apn IN ('ETISALAT', 'INTERNET.ETISALAT', 'ETISALAT.ROAMING',
                       'INTERNET.ETISALAT.CC2', 'FWA.ETISALAT',
                       'ETISALAT.ROAMING.VIP')
          AND ggsn_pgw_id IN ({GW_IDS_SQL})
        GROUP BY
            FROM_UNIXTIME(
                CAST(timecolumn AS BIGINT) - (CAST(timecolumn AS BIGINT) % 3600),
                'yyyy/MM/dd HH:00'
            ),
            ggsn_pgw_id,
            {prefix_sql}
        HAVING COUNT(*) >= 200
    """


def discover_tables(conn, schema: str, pattern: str) -> list[str]:
    """Ask Hive/Spark which tables currently exist matching the pattern.
    Returns fully-qualified names like 'sdr_nethouse.sdr_dyn_ide_soc_tcp_user_15m_20627'.

    The config accepts SQL-LIKE syntax (`%`), but spark2x's `SHOW TABLES LIKE`
    uses shell-glob wildcards (`*`). Translate before sending. We leave `_`
    alone because it appears literally in our table names — it must not be
    treated as a wildcard.
    """
    spark_pattern = pattern.replace("%", "*")
    sql = f"SHOW TABLES IN {schema} LIKE '{spark_pattern}'"
    print(f"  Discovering tables: {sql}")
    raw = pd.read_sql(sql, conn)
    # Result shape depends on the engine:
    #   - Native Hive: 1 column called 'tab_name' (just the table name)
    #   - Spark SQL  : 3 columns: namespace, tableName, isTemporary
    # We want the table-name column specifically. Pick by name with fallbacks;
    # never blindly trust raw.columns[0] — on Spark that's the namespace.
    candidates = ("tableName", "tab_name", "table_name", "name")
    name_col = next((c for c in candidates if c in raw.columns), None)
    if name_col is None:
        # Fallback: assume table name is in the *last* column (true for both
        # Hive's single-column shape and Spark's [namespace, tableName, isTemporary]
        # — though Spark's last is isTemporary, hence prefer the named lookup above)
        name_col = "tableName" if "tableName" in raw.columns else raw.columns[-2 if len(raw.columns) >= 3 else 0]
    names = raw[name_col].astype(str).tolist()
    # Exclude backup tables — anything containing '_bak'
    names = [n for n in names if "_bak" not in n.lower()]
    fq = sorted(f"{schema}.{n}" for n in names)
    print(f"    -> {len(fq)} table(s) found")
    return fq

# NOTE: IPv6 is stored at /64 (4 hextets) in RAW because pool matching needs it;
# the dashboard tables roll it up to /48 (see build_subnet_day).



_HOUR_EXPR = (
    "FROM_UNIXTIME((a.timecolumn - (a.timecolumn % 3600)) + 2 * 3600, "
    "'yyyy/MM/dd HH:00')"
)


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


def _table_number(fq_name: str) -> int:
    m = re.search(r"_(\d+)$", fq_name)
    if not m:
        raise ValueError(f"Cannot parse table number from: {fq_name}")
    return int(m.group(1))


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



# =============================================================================
# 2. IP POOLS  (config/ip_pools.csv -> subnet-to-pool attribution)
# =============================================================================
# Pools overlap in the sheet (primary pools vs their LOCKed `red_p` twins,
# `new_*_to_rp_*` routing pools, and sessions using another gateway's
# addresses), so every subnet is attributed like this:
#   members : every pool whose range contains the subnet (same gateway first,
#             other gateways only if the gateway has none) -> per-pool KPIs
#   owner   : ONE most-specific pool (ties: not-LOCKed, not-overlay, name)
#             -> use owner_sessions whenever you add pools together
# UPF gateways are out of scope (the request covers the 7 non-UPF gateways).


OVERLAY_RE = re.compile(r"red_p|^new_")


Attribution = namedtuple("Attribution", "members owner cluster cross_gw")


def pool_id(gw: str, pool_name: str) -> str:
    return f"{gw}:{pool_name}"


def is_overlay(pool_name: str) -> bool:
    return bool(OVERLAY_RE.search(pool_name))


def gw_short_code(ugw_label: str) -> str:
    """'AlexPost_ODG21' -> 'ODG21'. Unlabeled numeric ids ('200067') come
    back unchanged and simply won't be in scope."""
    return ugw_label.rsplit("_", 1)[-1] if "_" in ugw_label else ugw_label


def _ipv4_prefixes(start_ip: str, end_ip: str) -> "list[str]":
    s = int(ipaddress.IPv4Address(start_ip))
    e = int(ipaddress.IPv4Address(end_ip))
    out = []
    for top in range(s >> 8, (e >> 8) + 1):
        out.append(".".join(str((top >> sh) & 0xFF) for sh in (16, 8, 0)))
    return out


def _hextets_no_pad(addr_int: int, n: int) -> str:
    """First n groups, lowercase, NOT zero-padded -- matches Spark's raw
    SPLIT() on the textual address, which is what the Hive query stores."""
    return ":".join(format((addr_int >> ((7 - i) * 16)) & 0xFFFF, "x")
                    for i in range(n))


def _ipv6_keys(start_ip: str, end_ip: str) -> "dict[tuple[int, str], int]":
    """{(depth, prefix): num_addresses_in_that_block}."""
    s = ipaddress.IPv6Address(start_ip)
    e = ipaddress.IPv6Address(end_ip)
    keys = {}
    for net in ipaddress.summarize_address_range(s, e):
        if net.prefixlen % 16 == 0 and net.prefixlen > 0:
            depth = min(net.prefixlen // 16, 4)
        else:
            depth = 3  # unaligned: coarsest safe assumption (/48)
        k = (depth, _hextets_no_pad(int(net.network_address), depth))
        keys[k] = max(keys.get(k, 0), net.num_addresses)
    return keys


def load_pools(csv_path: str = POOLS_CSV) -> "list[dict]":
    """One dict per CSV row (= one pool *section*)."""
    sections = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            start, end = (row["start_ip"] or "").strip(), (row["end_ip"] or "").strip()
            if not start or not end:
                continue
            family = "ipv6" if ":" in start else "ipv4"
            try:
                if family == "ipv4":
                    entry = {"prefixes": _ipv4_prefixes(start, end),
                             "size": int(ipaddress.IPv4Address(end))
                                     - int(ipaddress.IPv4Address(start)) + 1}
                else:
                    entry = {"keys": _ipv6_keys(start, end)}
            except ValueError as e:
                print(f"  [pool_matcher] skipping {row['pool_name']} "
                      f"section {row['section']}: {e}")
                continue
            entry.update({
                "pool_name": row["pool_name"], "gw": row["gw"],
                "pool_id": pool_id(row["gw"], row["pool_name"]),
                "path": row["path"], "apn": row["apn"],
                "vpn_instance": row["vpn_instance"], "family": family,
                # optional column (added when re-exported from the xlsx)
                "locked": (row.get("lock") or "").strip().upper() == "LOCK",
            })
            sections.append(entry)
    return sections


class PoolIndex:
    """Lookup structure built once from load_pools()."""

    def __init__(self, sections: "list[dict] | None" = None,
                 include_upf: bool = False):
        sections = sections if sections is not None else load_pools()
        if not include_upf:
            sections = [s for s in sections if "UPF" not in s["gw"].upper()]
        # prefix -> {(gw, pool_name): smallest containing-section size}
        self.v4 = defaultdict(dict)
        self.v6 = defaultdict(dict)   # (depth, prefix) -> same
        self.pool_meta = {}           # pool_id -> {gw, pool_name, path, apn, family, locked}
        self.gateways = set()
        for s in sections:
            self.gateways.add(s["gw"])
            m = self.pool_meta.setdefault(s["pool_id"], {
                "gw": s["gw"], "pool_name": s["pool_name"], "path": s["path"],
                "apn": s["apn"], "family": s["family"], "locked": True})
            # a pool counts as locked only if ALL its sections are LOCK
            m["locked"] = m["locked"] and s["locked"]
            key = (s["gw"], s["pool_name"])
            if s["family"] == "ipv4":
                for p in s["prefixes"]:
                    cur = self.v4[p].get(key)
                    self.v4[p][key] = s["size"] if cur is None else min(cur, s["size"])
            else:
                for k, size in s["keys"].items():
                    cur = self.v6[k].get(key)
                    self.v6[k][key] = size if cur is None else min(cur, size)

    # -- lookups ----------------------------------------------------------
    def _candidates(self, prefix: str) -> "dict[tuple[str, str], int]":
        if ":" in prefix:
            cands = {}
            n = prefix.count(":") + 1
            if n >= 4:
                cands.update(self.v6.get((4, prefix), {}))
                p3 = prefix.rsplit(":", 1)[0] if n == 4 else ":".join(prefix.split(":")[:3])
            else:
                p3 = prefix
            for k, size in self.v6.get((3, p3), {}).items():
                cands[k] = min(size, cands.get(k, size))
            return cands
        return self.v4.get(prefix, {})

    def attribute(self, ugw: str, prefix: str) -> "Attribution | None":
        """None -> the row's gateway isn't one of the sheet's gateways
        (out of scope, e.g. SV_UDG01) or the subnet is in no pool."""
        gw = gw_short_code(ugw)
        if gw not in self.gateways:
            return None
        cands = self._candidates(prefix)
        if not cands:
            return None
        same = {k: v for k, v in cands.items() if k[0] == gw}
        cross_gw = not same
        pool = same or cands
        members = tuple(sorted(pool_id(g, n) for (g, n) in pool))
        ranked = sorted(pool.items(),
                        key=lambda kv: (kv[1],
                                        self.pool_meta[pool_id(*kv[0])]["locked"],
                                        is_overlay(kv[0][1]),
                                        pool_id(*kv[0])))
        smallest = ranked[0][1]
        owner = pool_id(*ranked[0][0])
        cluster = tuple(sorted(pool_id(g, n) for (g, n), v in pool.items()
                               if v == smallest))
        return Attribution(members, owner, cluster, cross_gw)


def pool_type_of(pool_name: str) -> str:
    n = pool_name.lower()
    return "internet" if "internet" in n else ("roaming" if "roaming" in n else "etisalat")


# =============================================================================
# 3. CLICKHOUSE: tables, staging, transforms
# =============================================================================
def _esc(s: str) -> str:
    return str(s).replace("\\", "\\\\").replace("'", "\\'")


def _rows(c, sql: str) -> list:
    return c.query(sql).result_rows


def _scalar(c, sql: str, default=None):
    rows = _rows(c, sql)
    return rows[0][0] if rows and rows[0] else default


def _days_in(c, table: str, col: str = "report_date") -> set:
    try:
        return {r[0] for r in _rows(c, f"SELECT DISTINCT toString(toDate({col})) FROM {table}")}
    except Exception:
        return set()  # table not created yet


def _ttl(col: str = "report_date") -> str:
    return f"TTL {col} + INTERVAL {int(RETENTION_DAYS)} DAY"


def _ddl() -> dict:
    return {
        "nd_ingest_log": """
            CREATE TABLE IF NOT EXISTS nd_ingest_log (
                job String, table_no UInt32, day Date, rows UInt64,
                ingested_at DateTime DEFAULT now())
            ENGINE = MergeTree ORDER BY (job, table_no)""",
        "dim_pool": """
            CREATE TABLE IF NOT EXISTS dim_pool (
                pool_id String, gw String, pool_name String, family String,
                pool_type String, path String, apn String, locked UInt8)
            ENGINE = MergeTree ORDER BY pool_id""",
        "nd_subnet_pool_map": f"""
            CREATE TABLE IF NOT EXISTS nd_subnet_pool_map (
                ugw String, prefix String, pool_id String,
                is_owner UInt8, cross_gw UInt8, n_members UInt8,
                mapped_at Date DEFAULT today())
            ENGINE = MergeTree ORDER BY (ugw, prefix, pool_id)
            {_ttl('mapped_at')}""",
        "nd_subnet_pool": """
            CREATE TABLE IF NOT EXISTS nd_subnet_pool (
                ugw String, ip_version String, prefix String,
                pool_id String, n_pools UInt32)
            ENGINE = MergeTree ORDER BY (ugw, prefix)""",
        "nd_subnet_hourly": f"""
            CREATE TABLE IF NOT EXISTS nd_subnet_hourly (
                report_date Date, hour DateTime, ugw String, ip_version String,
                prefix String, session_count UInt64,
                tcp_sr Nullable(Float64), tcp_fr2 Nullable(Float64),
                baseline_sr Nullable(Float64), baseline_fr2 Nullable(Float64),
                sr_drop Nullable(Float64), fr2_rise Nullable(Float64))
            ENGINE = MergeTree PARTITION BY report_date
            ORDER BY (ip_version, ugw, prefix, hour)
            {_ttl()}""",
        "nd_pool_hourly": f"""
            CREATE TABLE IF NOT EXISTS nd_pool_hourly (
                report_date Date, hour DateTime, pool_id String, gw String,
                pool_name String, family String, pool_type String, locked UInt8,
                session_count UInt64, owner_sessions UInt64,
                cross_gw_sessions UInt64, n_subnets UInt32, shared UInt8,
                tcp_sr Nullable(Float64), tcp_fr2 Nullable(Float64),
                baseline_sr Nullable(Float64), baseline_fr2 Nullable(Float64),
                sr_drop Nullable(Float64), fr2_rise Nullable(Float64))
            ENGINE = MergeTree PARTITION BY report_date
            ORDER BY (pool_id, hour)
            {_ttl()}""",
        "nd_pool_daily": f"""
            CREATE TABLE IF NOT EXISTS nd_pool_daily (
                report_date Date, pool_id String, gw String, pool_name String,
                family String, pool_type String, locked UInt8,
                session_count UInt64, owner_sessions UInt64,
                cross_gw_sessions UInt64, max_hourly_subnets UInt32, shared UInt8,
                tcp_sr Nullable(Float64), tcp_fr2 Nullable(Float64))
            ENGINE = MergeTree PARTITION BY report_date
            ORDER BY (pool_id, report_date)
            {_ttl()}""",
        "nd_site_hourly": f"""
            CREATE TABLE IF NOT EXISTS nd_site_hourly (
                report_date Date, hour DateTime, ugw String, site String,
                session_count UInt64,
                tcp_2_fr Nullable(Float64), tcp_3_fr Nullable(Float64))
            ENGINE = MergeTree PARTITION BY report_date
            ORDER BY (site, hour)
            {_ttl()}""",
        "nd_site_baseline": """
            CREATE TABLE IF NOT EXISTS nd_site_baseline (
                site String, baseline_sr Nullable(Float64),
                baseline_fr2 Nullable(Float64))
            ENGINE = MergeTree ORDER BY site""",
        "nd_cell_daily": f"""
            CREATE TABLE IF NOT EXISTS nd_cell_daily (
                report_date Date, site String, cell_name String, cgisai String,
                session_count UInt64, fr3_sum Float64, fr3_n UInt32)
            ENGINE = MergeTree PARTITION BY report_date
            ORDER BY (site, report_date, cell_name)
            {_ttl()}""",
    }


def ensure_tables(c) -> None:
    for ddl in _ddl().values():
        c.command(ddl)


def _drop_day(c, table: str, day: str) -> None:
    """Remove one day from a day-partitioned derived table (idempotent)."""
    try:
        c.command(f"ALTER TABLE {table} DROP PARTITION ID '{day.replace('-', '')}'")
    except Exception:
        c.command(f"ALTER TABLE {table} DROP PARTITION '{day}'")


def _final_retry(c, sql: str) -> None:
    """Run an INSERT..SELECT that reads a RAW table. {FINAL} guarantees
    de-duplicated rows; if the server refuses for memory, retry without."""
    try:
        c.command(sql.replace("{FINAL}", " FINAL"))
    except Exception as e:
        if "emory limit" in str(e) or "code: 241" in str(e).lower():
            log("    FINAL exceeded the memory limit - retrying without FINAL")
            c.command(sql.replace("{FINAL}", ""))
        else:
            raise


def _wavg(v: str, w: str) -> str:
    """Weighted average that is NULL when nothing is measurable."""
    return (f"if(sumIf({w}, isNotNull({v})) > 0, "
            f"sumIf({v} * {w}, isNotNull({v})) / sumIf({w}, isNotNull({v})), NULL)")


def _qlin(a: str, q: float) -> str:
    """q-quantile of the sorted array expression `a` with LINEAR interpolation
    - the same definition pandas' .quantile() uses, so baselines match the
    numbers the dashboard produced before."""
    pos = f"({q} * (length({a}) - 1))"
    lo = f"toUInt32(floor({pos})) + 1"
    hi = f"toUInt32(ceil({pos})) + 1"
    return (f"if(length({a}) = 0, NULL, arrayElement({a}, {lo}) + "
            f"({pos} - floor({pos})) * (arrayElement({a}, {hi}) - arrayElement({a}, {lo})))")


_STAGE = {
    "nd_stage_raw": """(day Date, hour DateTime, ugw String, ip_version String,
        prefix String, sc Int64, tcp_sr Nullable(Float64), tcp_fr2 Nullable(Float64))
        ENGINE = MergeTree ORDER BY (ugw, prefix, hour)""",
    "nd_stage_subnet": """(day Date, hour DateTime, ugw String, ip_version String,
        prefix String, session_count Int64, tcp_sr Nullable(Float64),
        tcp_fr2 Nullable(Float64)) ENGINE = MergeTree ORDER BY (ugw, ip_version, hour)""",
    "nd_stage_pool": """(day Date, hour DateTime, pool_id String, session_count Int64,
        owner_sessions Int64, cross_gw_sessions Int64, n_subnets UInt32, shared UInt8,
        tcp_sr Nullable(Float64), tcp_fr2 Nullable(Float64))
        ENGINE = MergeTree ORDER BY (pool_id, hour)""",
    "nd_stage_pool_meta": """(day Date, hour DateTime, pool_id String, gw String,
        pool_name String, family String, pool_type String, locked UInt8,
        session_count Int64, owner_sessions Int64, cross_gw_sessions Int64,
        n_subnets UInt32, shared UInt8, tcp_sr Nullable(Float64),
        tcp_fr2 Nullable(Float64)) ENGINE = MergeTree ORDER BY (family, pool_type, hour)""",
}


def _reset_stage(c) -> None:
    for name, cols in _STAGE.items():
        c.command(f"DROP TABLE IF EXISTS {name}")
        c.command(f"CREATE TABLE {name} {cols}")


def _drop_stage(c) -> None:
    for name in _STAGE:
        c.command(f"DROP TABLE IF EXISTS {name}")


# ---- pools: dimension + subnet map -----------------------------------------
def load_pool_dimension(c, index: "PoolIndex") -> int:
    rows = [{"pool_id": pid, "gw": m["gw"], "pool_name": m["pool_name"],
             "family": m["family"], "pool_type": pool_type_of(m["pool_name"]),
             "path": m["path"], "apn": m["apn"], "locked": int(m["locked"])}
            for pid, m in sorted(index.pool_meta.items())]
    c.command("TRUNCATE TABLE dim_pool")
    c.insert_df("dim_pool", pd.DataFrame(rows))
    return len(rows)


def update_pool_map(c, index: "PoolIndex", day: str) -> int:
    """Attribute every (gateway, subnet) seen on `day` that is not in the map
    yet. Each subnet is resolved once, ever (until the sheet is reloaded)."""
    codes = "[" + ",".join(f"'{g}'" for g in sorted(index.gateways)) + "]"
    sql = f"""
        SELECT DISTINCT ugw, prefix FROM nd_stage_raw
        WHERE has({codes}, arrayElement(splitByChar('_', ugw), -1))
          AND (ugw, prefix) NOT IN (
                SELECT ugw, prefix FROM nd_subnet_pool_map
                WHERE (ugw, prefix) IN (SELECT ugw, prefix FROM nd_stage_raw))"""
    pairs = _rows(c, sql)
    recs = []
    for ugw, prefix in pairs:
        a = index.attribute(ugw, prefix)
        if a is None:
            continue
        for pid in a.members:
            recs.append((ugw, prefix, pid, int(pid == a.owner), int(a.cross_gw),
                         min(len(a.members), 255)))
    if recs:
        df = pd.DataFrame(recs, columns=["ugw", "prefix", "pool_id",
                                         "is_owner", "cross_gw", "n_members"])
        for i in range(0, len(df), 500_000):
            c.insert_df("nd_subnet_pool_map", df.iloc[i:i + 500_000])
    return len(recs)


# ---- one day of transforms ---------------------------------------------------
def _stage_raw(c, day: str) -> None:
    for job, ipv, pcol in (("ipv6", "IPv6", "ipv6_prefix_48"), ("ipv4", "IPv4", "ipv4_prefix_24")):
        _final_retry(c, f"""
            INSERT INTO nd_stage_raw
            SELECT toDate(report_date),
                   toDateTime(concat(replaceAll(hour, '/', '-'), ':00')),
                   ugw, '{ipv}', {pcol}, toInt64(ifNull(session_count, 0)),
                   toFloat64(tcp_sr), toFloat64(tcp_fr2)
            FROM {RAW[job]}{{FINAL}}
            WHERE toDate(report_date) = toDate('{day}')""")


def build_subnet_day(c, day: str) -> int:
    """IPv6 /64 -> /48, IPv4 /24 as is; keep >=200 sessions/hour; add the
    peer baseline (75th pct SR / 25th pct FR2 of the same gateway+family+hour)."""
    c.command("INSERT INTO nd_stage_subnet " + f"""
        SELECT day, hour, ugw, ip_version, p48, sum(sc) AS n,
               {_wavg('tcp_sr', 'sc')}, {_wavg('tcp_fr2', 'sc')}
        FROM (SELECT day, hour, ugw, ip_version, sc, tcp_sr, tcp_fr2,
                     if(ip_version = 'IPv6',
                        arrayStringConcat(arraySlice(splitByChar(':', prefix), 1, 3), ':'),
                        prefix) AS p48
              FROM nd_stage_raw)
        GROUP BY day, hour, ugw, ip_version, p48
        HAVING n >= 200""")
    _drop_day(c, "nd_subnet_hourly", day)
    c.command("""
        INSERT INTO nd_subnet_hourly
        SELECT day, hour, ugw, ip_version, prefix, session_count, tcp_sr, tcp_fr2,
               baseline_sr, baseline_fr2,
               round(baseline_sr - tcp_sr, 2), round(tcp_fr2 - baseline_fr2, 2)
        FROM nd_stage_subnet
        ANY LEFT JOIN (
            SELECT ugw, ip_version, hour,
                   """ + _qlin("sr_a", 0.75) + """ AS baseline_sr,
                   """ + _qlin("fr_a", 0.25) + """ AS baseline_fr2
            FROM (SELECT ugw, ip_version, hour,
                         arraySort(groupArrayIf(tcp_sr, isNotNull(tcp_sr))) AS sr_a,
                         arraySort(groupArrayIf(tcp_fr2, isNotNull(tcp_fr2))) AS fr_a
                  FROM nd_stage_subnet GROUP BY ugw, ip_version, hour)
        ) AS b USING (ugw, ip_version, hour)""")
    return int(_scalar(c, f"SELECT count() FROM nd_subnet_hourly WHERE report_date = toDate('{day}')", 0))


def build_pool_day(c, index: "PoolIndex", day: str) -> int:
    """Per-pool KPIs. A subnet counts toward every pool that contains it;
    owner_sessions counts it once (see section 2)."""
    update_pool_map(c, index, day)
    c.command("INSERT INTO nd_stage_pool " + f"""
        SELECT day, hour, pool_id, sum(sc), sumIf(sc, is_owner = 1),
               sumIf(sc, cross_gw = 1), uniqExact(prefix), max(n_members > 1),
               {_wavg('tcp_sr', 'sc')}, {_wavg('tcp_fr2', 'sc')}
        FROM nd_stage_raw
        INNER JOIN (
            SELECT ugw, prefix, pool_id, is_owner, cross_gw, n_members
            FROM nd_subnet_pool_map
            WHERE (ugw, prefix) IN (SELECT ugw, prefix FROM nd_stage_raw)
        ) AS m USING (ugw, prefix)
        GROUP BY day, hour, pool_id""")
    c.command("""
        INSERT INTO nd_stage_pool_meta
        SELECT day, hour, pool_id, gw, pool_name, family, pool_type, locked,
               session_count, owner_sessions, cross_gw_sessions, n_subnets, shared,
               tcp_sr, tcp_fr2
        FROM nd_stage_pool ANY LEFT JOIN dim_pool USING (pool_id)""")
    _drop_day(c, "nd_pool_hourly", day)
    c.command(f"""
        INSERT INTO nd_pool_hourly
        SELECT day, hour, pool_id, gw, pool_name, family, pool_type, locked,
               session_count, owner_sessions, cross_gw_sessions, n_subnets, shared,
               tcp_sr, tcp_fr2, baseline_sr, baseline_fr2,
               round(baseline_sr - tcp_sr, 2), round(tcp_fr2 - baseline_fr2, 2)
        FROM nd_stage_pool_meta
        ANY LEFT JOIN (
            SELECT family, pool_type, hour,
                   {_qlin("sr_a", 0.75)} AS baseline_sr,
                   {_qlin("fr_a", 0.25)} AS baseline_fr2
            FROM (SELECT family, pool_type, hour,
                         arraySort(groupArrayIf(tcp_sr, isNotNull(tcp_sr))) AS sr_a,
                         arraySort(groupArrayIf(tcp_fr2, isNotNull(tcp_fr2))) AS fr_a
                  FROM nd_stage_pool_meta
                  WHERE locked = 0 AND session_count >= {MIN_POOL_SESSIONS}
                  GROUP BY family, pool_type, hour)
        ) AS b USING (family, pool_type, hour)""")
    _drop_day(c, "nd_pool_daily", day)
    c.command(f"""
        INSERT INTO nd_pool_daily
        SELECT report_date, pool_id, any(gw), any(pool_name), any(family),
               any(pool_type), any(locked), sum(session_count), sum(owner_sessions),
               sum(cross_gw_sessions), max(n_subnets), max(shared),
               {_wavg('tcp_sr', 'session_count')}, {_wavg('tcp_fr2', 'session_count')}
        FROM nd_pool_hourly WHERE report_date = toDate('{day}')
        GROUP BY report_date, pool_id""")
    return int(_scalar(c, f"SELECT count() FROM nd_pool_hourly WHERE report_date = toDate('{day}')", 0))


def refresh_subnet_pool(c) -> int:
    """Which pool does each dashboard subnet (IPv4 /24, IPv6 /48) belong to?
    Built from the subnet map (owner pool of every /64 or /24). If the /64s of
    one /48 sit in different pools, the most frequent one is shown and
    n_pools tells you there are more. This is what lets the dashboard say
    'these 12 degraded subnets are all in pool X'."""
    c.command("TRUNCATE TABLE nd_subnet_pool")
    c.command("""
        INSERT INTO nd_subnet_pool
        SELECT ugw, ip_version, p, arrayElement(topK(1)(pool_id), 1), uniqExact(pool_id)
        FROM (
            SELECT ugw, pool_id,
                   if(position(prefix, ':') > 0, 'IPv6', 'IPv4') AS ip_version,
                   if(position(prefix, ':') > 0,
                      arrayStringConcat(arraySlice(splitByChar(':', prefix), 1, 3), ':'),
                      prefix) AS p
            FROM nd_subnet_pool_map WHERE is_owner = 1)
        GROUP BY ugw, ip_version, p""")
    return int(_scalar(c, "SELECT count() FROM nd_subnet_pool", 0))


def build_site_day(c, day: str) -> int:
    _drop_day(c, "nd_site_hourly", day)
    _final_retry(c, f"""
        INSERT INTO nd_site_hourly
        SELECT toDate(report_date),
               toDateTime(concat(replaceAll(hour, '/', '-'), ':00')),
               ugw, site, toInt64(ifNull(session_count, 0)),
               toFloat64(tcp_2_fr), toFloat64(tcp_3_fr)
        FROM {RAW['site']}{{FINAL}}
        WHERE toDate(report_date) = toDate('{day}') AND ifNull(session_count, 0) >= 200""")
    return int(_scalar(c, f"SELECT count() FROM nd_site_hourly WHERE report_date = toDate('{day}')", 0))


def build_cells_day(c, day: str) -> int:
    _drop_day(c, "nd_cell_daily", day)
    c.command(f"""
        INSERT INTO nd_cell_daily
        SELECT toDate(report_date), site, cell_name, toString(cgisai),
               sum(toInt64(ifNull(session_count, 0))),
               sum(ifNull(toFloat64(tcp_3_fr), 0)), countIf(isNotNull(tcp_3_fr))
        FROM {RAW['site_cells']}
        WHERE toDate(report_date) = toDate('{day}')
        GROUP BY toDate(report_date), site, cell_name, toString(cgisai)""")
    return int(_scalar(c, f"SELECT count() FROM nd_cell_daily WHERE report_date = toDate('{day}')", 0))


def refresh_site_baseline(c) -> None:
    """A site is degraded when FR3 rises above ITS OWN normal level = its
    best-quarter hours over the last BASELINE_DAYS days."""
    c.command("TRUNCATE TABLE nd_site_baseline")
    c.command(f"""
        INSERT INTO nd_site_baseline
        SELECT site, {_qlin("sr_a", 0.75)}, {_qlin("fr_a", 0.25)}
        FROM (SELECT site, arraySort(groupArrayIf(100 - tcp_3_fr, isNotNull(tcp_3_fr))) AS sr_a,
                     arraySort(groupArrayIf(tcp_3_fr, isNotNull(tcp_3_fr))) AS fr_a
              FROM nd_site_hourly
              WHERE report_date >= today() - {int(BASELINE_DAYS)}
              GROUP BY site)""")


def purge_dead_subnets(c) -> int:
    """Permanently remove subnets that have NEVER once carried meaningful
    traffic (tcp_sr never above DEAD_SR_MAX_PCT) anywhere in their recorded
    history from nd_subnet_hourly. These are dead/decommissioned/
    misconfigured subnets, not real service degradation — they always sit
    "below healthy peers" and would otherwise flood every consumer of this
    table (dashboard, exports, ad-hoc SQL) with noise rather than
    actionable anomalies.

    A strict "== 0" check is NOT enough: real measurement noise can put a
    permanently-broken subnet at 0.008% or 0.08% on some hours instead of an
    exact 0.0, which would otherwise let it slip through this filter. Using
    "<= DEAD_SR_MAX_PCT" instead catches those too, while a subnet that was
    genuinely healthy before a real, recent outage still has a high max
    (its pre-outage SR) and is correctly left alone.

    max(tcp_sr) is NULL (not 0) for a subnet with no non-null SR at all, so
    this never matches a subnet that simply has no SR data yet. Self-healing:
    run on every `transform` call (including the daily cron job), so a
    subnet is purged the moment enough history confirms it's permanently
    dead, and nothing needs to be run by hand.
    """
    dead = _rows(c, f"""
        SELECT ugw, ip_version, prefix
        FROM nd_subnet_hourly
        GROUP BY ugw, ip_version, prefix
        HAVING max(tcp_sr) <= {DEAD_SR_MAX_PCT}""")
    if not dead:
        return 0
    for i in range(0, len(dead), 5000):
        batch = dead[i:i + 5000]
        tuples = ",".join(
            "(" + ",".join(f"'{_esc(x)}'" for x in row) + ")" for row in batch)
        c.command(f"""
            ALTER TABLE nd_subnet_hourly
            DELETE WHERE (ugw, ip_version, prefix) IN ({tuples})""")
    return len(dead)


def transform_days(c, days_net: list, days_site: list, parts: set, index: "PoolIndex") -> None:
    """Build derived tables for the given days. Idempotent: re-running a day
    replaces that day's rows."""
    if days_net and parts & {"subnet", "pool"}:
        for day in sorted(days_net):
            t0 = time.monotonic()
            _reset_stage(c)
            _stage_raw(c, day)
            msg = []
            if "subnet" in parts:
                msg.append(f"subnets={build_subnet_day(c, day):,}")
            if "pool" in parts:
                msg.append(f"pool-hours={build_pool_day(c, index, day):,}")
            log(f"[transform] {day}: " + ", ".join(msg) + f" ({time.monotonic() - t0:.0f}s)")
        _drop_stage(c)
        if "pool" in parts:
            log(f"[transform] subnet -> pool lookup: {refresh_subnet_pool(c):,} subnets")
        if "subnet" in parts:
            n_dead = purge_dead_subnets(c)
            if n_dead:
                log(f"[transform] purged {n_dead:,} subnet(s) permanently stuck "
                    f"at ~0% SR (never above {DEAD_SR_MAX_PCT}%) from nd_subnet_hourly")
    if days_site and parts & {"site", "cells"}:
        for day in sorted(days_site):
            msg = []
            if "site" in parts:
                msg.append(f"site-hours={build_site_day(c, day):,}")
            if "cells" in parts and _days_in(c, RAW["site_cells"]):
                msg.append(f"cells={build_cells_day(c, day):,}")
            log(f"[transform] {day}: " + ", ".join(msg))
    if "site" in parts:
        refresh_site_baseline(c)


def missing_days(c) -> "tuple[list, list]":
    """Days present in RAW but not yet in the derived tables (self-healing)."""
    net = (_days_in(c, RAW["ipv6"]) & _days_in(c, RAW["ipv4"])) - _days_in(c, "nd_subnet_hourly")
    site = _days_in(c, RAW["site"]) - _days_in(c, "nd_site_hourly")
    return sorted(net), sorted(site)


# =============================================================================
# 4. FETCH: Hive -> RAW tables (state lives in nd_ingest_log, not in a file)
# =============================================================================
def _reconnect(conn_box: list, config: dict, job: str) -> None:
    try:
        conn_box[0].close()
    except Exception:
        pass
    conn_box[0] = _reconnect_with_retries(lambda: connect_db(config), job)


def fetch_job(job_name: str, conn_box: list, config: dict, c, dry_run: bool,
              backfill: int) -> list:
    """Load every complete, not-yet-loaded day of one job into its RAW table.
    Returns the list of days loaded."""
    job = _JOBS[job_name]
    schema = config["database"].get("schema", "sdr_nethouse")
    map_table = config["database"].get("site_map_table", f"{schema}.cellmappingtest")

    log(f"[{job_name}] discovering tables ({job['pattern']}) ...")
    try:
        tables = discover_tables(conn_box[0], schema, job["pattern"])
    except Exception as e:
        log(f"[{job_name}] discovery failed ({e}) - reconnecting once ...")
        _reconnect(conn_box, config, job_name)
        tables = discover_tables(conn_box[0], schema, job["pattern"])
    if not tables:
        log(f"[{job_name}] no tables found - skipped")
        return []

    done_nos = {r[0] for r in _rows(c, f"SELECT table_no FROM nd_ingest_log WHERE job = '{job_name}'")}
    if backfill:
        candidates = tables[-backfill:]
    elif not done_nos:
        candidates = tables[-FIRST_RUN_LOOKBACK_TABLES:]
    else:
        newest = max(done_nos)
        candidates = [t for t in tables if _table_number(t) > newest]
    candidates = [t for t in candidates if _table_number(t) not in done_nos]
    log(f"[{job_name}] {len(candidates)} candidate table(s)")

    raw_days = _days_in(c, RAW[job_name])
    midnight = _midnight_today_ts()
    loaded = []
    for table in candidates:
        no = _table_number(table)
        try:
            window = _probe_day(table, conn_box[0])
        except Exception as e:
            log(f"[{job_name}] {table}: probe failed ({e}) - reconnecting")
            _reconnect(conn_box, config, job_name)
            try:
                window = _probe_day(table, conn_box[0])
            except Exception as e2:
                log(f"[{job_name}] {table}: probe failed again ({e2}) - skipped")
                continue
        if window is None:
            log(f"[{job_name}] {table}: empty - skipped")
            continue
        start_ts, end_ts = window
        day = datetime.fromtimestamp(start_ts).strftime("%Y-%m-%d")
        if end_ts > midnight:
            log(f"[{job_name}] {table}: {day} is still the current (partial) day - later")
            continue
        if day in raw_days:
            log(f"[{job_name}] {table}: {day} already in ClickHouse - marked done")
            if not dry_run:
                c.command(f"INSERT INTO nd_ingest_log (job, table_no, day, rows) "
                          f"VALUES ('{job_name}', {no}, '{day}', 0)")
            continue
        if dry_run:
            log(f"[{job_name}] {table}: {day} complete - would load")
            continue

        if job["kind"] == "subnet":
            sql = _query(table, start_ts, job["ip_family"], end_ts=end_ts)
        elif job["kind"] == "site_cells":
            sql = _site_cells_query(table, map_table, start_ts, end_ts)
        else:
            sql = _site_query(table, map_table, start_ts, end_ts)

        log(f"[{job_name}] {table} ({day}): exporting ...")
        try:
            df, t = _read_export(sql, conn_box[0])
        except Exception as e:
            log_exception(e)
            _reconnect(conn_box, config, job_name)
            try:
                df, t = _read_export(sql, conn_box[0])
            except Exception as e2:
                log_exception(e2)
                log(f"[{job_name}] {table}: failed twice - will retry next run")
                continue
        if df.empty:
            log(f"[{job_name}] {table}: 0 rows after filters - NOT marked done")
            continue
        df["report_date"] = pd.to_datetime(day)
        n = write_dataframe(df, table=RAW[job_name], date_column="report_date",
                            order_by=_CH_ORDER_BY[job_name], client=c)
        c.command(f"INSERT INTO nd_ingest_log (job, table_no, day, rows) "
                  f"VALUES ('{job_name}', {no}, '{day}', {n})")
        raw_days.add(day)
        loaded.append(day)
        log(f"[{job_name}] {table} ({day}): {n:,} rows -> `{RAW[job_name]}` "
            f"(hive exec {t['exec_s']}s, fetch {t['fetch_s']}s)")
    return loaded


def run_fetch(args, c) -> list:
    config = load_config()
    try:
        conn_box = [connect_db(config)]
    except Exception as e:
        log("!" * 60)
        log(f"HIVE CONNECTION FAILED: {e}")
        log("Most common cause: Kerberos ticket missing/expired (kinit) or VPN down.")
        log("!" * 60)
        raise SystemExit(2)
    try:
        if getattr(args, "check", False):
            schema = config["database"].get("schema", "sdr_nethouse")
            map_table = config["database"].get("site_map_table", f"{schema}.cellmappingtest")
            raise SystemExit(0 if run_check(conn_box[0], schema, map_table) else 1)
        names = [j.strip() for j in args.jobs.split(",") if j.strip()]
        bad = [j for j in names if j not in _JOBS]
        if bad:
            raise SystemExit(f"Unknown job(s) {bad}; choose from {list(_JOBS)}")
        loaded = []
        for name in names:
            try:
                loaded += fetch_job(name, conn_box, config, c, args.dry_run, args.backfill)
            except Exception as e:  # one job failing must not stop the others
                log(f"[{name}] JOB FAILED")
                log_exception(e)
                try:
                    _reconnect(conn_box, config, name)
                except Exception as e2:
                    log(f"[{name}] could not restore the Hive connection: {e2}")
        return loaded
    finally:
        try:
            conn_box[0].close()
        except Exception:
            pass


# =============================================================================
# 5. COMMANDS
# =============================================================================
def _index() -> "PoolIndex":
    return PoolIndex()


def cmd_pools(args, c) -> None:
    index = _index()
    n = load_pool_dimension(c, index)
    c.command("TRUNCATE TABLE nd_subnet_pool_map")
    log(f"[pools] {n} pools loaded from {os.path.basename(POOLS_CSV)} "
        f"({len(index.gateways)} gateways); subnet map cleared")
    days = sorted(_days_in(c, RAW["ipv6"]) & _days_in(c, RAW["ipv4"]))
    if days and not args.no_rebuild:
        log(f"[pools] rebuilding pool tables for {len(days)} day(s) ...")
        transform_days(c, days, [], {"pool"}, index)


def cmd_transform(args, c) -> None:
    index = _index()
    if not _rows(c, "SELECT 1 FROM dim_pool LIMIT 1"):
        load_pool_dimension(c, index)
    parts = set(args.parts.split(",")) if args.parts else {"subnet", "pool", "site", "cells"}
    all_net = sorted(_days_in(c, RAW["ipv6"]) & _days_in(c, RAW["ipv4"]))
    all_site = sorted(_days_in(c, RAW["site"]))
    if args.date:
        net, site = [d for d in all_net if d == args.date], [d for d in all_site if d == args.date]
    elif args.rebuild:
        net, site = all_net[-args.days:], all_site[-args.days:]
    else:
        net, site = missing_days(c)
    if not net and not site:
        log("[transform] nothing to do - derived tables are up to date")
        return
    transform_days(c, net, site, parts, index)


def cmd_daily(args, c) -> None:
    log("=" * 70)
    log(f"daily run {datetime.now():%Y-%m-%d %H:%M:%S}")
    args.jobs = ",".join(_JOBS)
    args.backfill = 0
    args.dry_run = False
    args.check = False
    try:
        run_fetch(args, c)
    except SystemExit as e:
        log(f"fetch stopped (exit {e.code}) - still transforming whatever is in ClickHouse")
    cmd_transform(argparse.Namespace(parts=None, days=0, rebuild=False, date=None), c)
    log("daily run finished")


def cmd_status(args, c) -> None:
    for t in ("network_degradation_ipv6", "network_degradation_ipv4",
              "network_degradation_site", "network_degradation_site_cells",
              "nd_subnet_hourly", "nd_pool_hourly", "nd_pool_daily",
              "nd_site_hourly", "nd_site_baseline", "nd_cell_daily",
              "nd_subnet_pool", "dim_pool", "nd_subnet_pool_map", "nd_ingest_log"):
        try:
            n = _scalar(c, f"SELECT count() FROM {t}", 0)
            col = "report_date" if "report_date" in {r[0] for r in _rows(
                c, f"SELECT name FROM system.columns WHERE database = currentDatabase() AND table = '{t}'")} else None
            rng = ""
            if col and n:
                lo, hi = _rows(c, f"SELECT toString(min(toDate({col}))), toString(max(toDate({col}))) FROM {t}")[0]
                rng = f"  days {lo} .. {hi}"
            print(f"{t:34s} {n:>14,} rows{rng}")
        except Exception:
            print(f"{t:34s} (not created yet)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("daily", help="fetch new days from Hive + build derived tables (cron)")
    f = sub.add_parser("fetch", help="Hive -> RAW tables only")
    f.add_argument("--jobs", default=",".join(_JOBS))
    f.add_argument("--backfill", type=int, default=0, metavar="N",
                   help="consider the newest N Hive tables per job (skips days already loaded)")
    f.add_argument("--dry-run", action="store_true")
    f.add_argument("--check", action="store_true", help="test Hive connectivity/schema and exit")
    t = sub.add_parser("transform", help="RAW -> derived tables (ClickHouse only)")
    t.add_argument("--days", type=int, default=30, help="with --rebuild: newest N days")
    t.add_argument("--date", help="one day, YYYY-MM-DD (always rebuilt)")
    t.add_argument("--rebuild", action="store_true", help="rebuild even days already done")
    t.add_argument("--parts", help="comma list of subnet,pool,site,cells (default all)")
    p = sub.add_parser("pools", help="reload config/ip_pools.csv")
    p.add_argument("--no-rebuild", action="store_true")
    sub.add_parser("status", help="show what is in the database")
    sub.add_parser("clean", help="purge subnets permanently stuck near 0%% SR "
                                 "from nd_subnet_hourly (also runs automatically "
                                 "on every transform)")
    args = ap.parse_args()
    if not args.cmd:
        args = ap.parse_args(["daily"])

    c = get_client()
    try:
        ensure_tables(c)
        if args.cmd == "fetch":
            run_fetch(args, c)
        elif args.cmd == "transform":
            cmd_transform(args, c)
        elif args.cmd == "pools":
            cmd_pools(args, c)
        elif args.cmd == "status":
            cmd_status(args, c)
        elif args.cmd == "clean":
            n = purge_dead_subnets(c)
            log(f"[clean] purged {n:,} subnet(s) permanently stuck near 0% SR"
                if n else "[clean] nothing to purge - no subnets permanently stuck near 0% SR")
        else:
            cmd_daily(args, c)
    finally:
        c.close()


if __name__ == "__main__":
    main()
