"""
TCP KPI Anomaly Detection Dashboard
=====================================
Detects IPv6 subnets with significant TCP Success Rate drops
compared to their own rolling 24-hour baseline.

Usage:
  Live DB (Kerberos ticket required):
      python dashboard.py

  Offline from exported CSV:
      python dashboard.py --csv path/to/file.csv

  Custom lookback (default 7 days):
      python dashboard.py --lookback 14
"""

from __future__ import annotations

import argparse
import os
import warnings
from datetime import datetime, timedelta

import pandas as pd
import plotly.graph_objects as go
import yaml
from dash import Dash, Input, Output, State, callback, ctx, dash_table, dcc, html, no_update
from dash import ALL

warnings.filterwarnings("ignore")

# Day-compare logic lives in tools/compare_days.py (shared with the CLI tool).
try:
    from tools.compare_days import compare as _compare_days
except Exception:  # tools/ missing or broken — the compare panel degrades gracefully
    _compare_days = None

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config", "config.yaml")

GATEWAY_MAP = {
    27:     "RamsisPost_PDG25",  200036: "RamsisPost_PDG25",
    20:     "Aburawash_R1DG28",  200042: "Aburawash_R1DG28",
    19:     "Banisuif_FGG13",    200019: "Banisuif_FGG13",
    41:     "SV_UDG01",          200053: "SV_UDG01",
    26:     "AlexPost_ODG21",    200028: "AlexPost_ODG21",
    1:      "AlexAuto_XGG09",    200015: "AlexAuto_XGG09",
}
GW_IDS_SQL = ", ".join(str(g) for g in GATEWAY_MAP)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# Database connection
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

_GW_CASE_SQL = """CASE ggsn_pgw_id
        WHEN 27 THEN 'RamsisPost_PDG25' WHEN 200036 THEN 'RamsisPost_PDG25'
        WHEN 20 THEN 'Aburawash_R1DG28' WHEN 200042 THEN 'Aburawash_R1DG28'
        WHEN 19 THEN 'Banisuif_FGG13'   WHEN 200019 THEN 'Banisuif_FGG13'
        WHEN 41 THEN 'SV_UDG01'         WHEN 200053 THEN 'SV_UDG01'
        WHEN 26 THEN 'AlexPost_ODG21'   WHEN 200028 THEN 'AlexPost_ODG21'
        WHEN 1  THEN 'AlexAuto_XGG09'   WHEN 200015 THEN 'AlexAuto_XGG09'
        ELSE CAST(ggsn_pgw_id AS STRING)
    END"""

# IPv6: /48 = first three ":"-separated segments of the address.
# Bounds-safe: Spark's SPLIT drops trailing empty strings, so an address like
# "2c0f:fc89::" yields a 2-element array and SPLIT(...)[2] throws
# "array index out of bounds" server-side (it did on table 20652).
_IPV6_PREFIX_SQL = (
    "CASE WHEN SIZE(SPLIT(ms_ip_pa,':')) >= 3 "
    "THEN CONCAT(SPLIT(ms_ip_pa,':')[0],':',SPLIT(ms_ip_pa,':')[1],':',SPLIT(ms_ip_pa,':')[2]) "
    "ELSE ms_ip_pa END"
)
# IPv4: /24 = the first three "."-separated octets. SPLIT() is regex-based
# in Hive so '.' would match anything — use SUBSTRING_INDEX instead.
_IPV4_PREFIX_SQL = "SUBSTRING_INDEX(ms_ip_pa, '.', 3)"

_IPV6_FILTER = (
    "ms_ip_type_pa = 'IPV6' "
    "AND (ms_ip_pa LIKE '2c0f:fc89:%' OR ms_ip_pa LIKE '2c0f:fc88:%')"
)
# IPv4 CGNAT ranges used by Etisalat: 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10.
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
          AND apn IN ('ETISALAT', 'INTERNET.ETISALAT')
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


def load_from_db(config: dict, lookback_days: int) -> pd.DataFrame:
    conn = connect_db(config)
    cutoff = int((datetime.utcnow() - timedelta(days=lookback_days)).timestamp())

    # Discover tables dynamically if a pattern is provided; otherwise fall back
    # to the legacy explicit list under `tables:`.
    schema    = config["database"].get("schema", "sdr_nethouse")
    pattern   = config.get("table_pattern")
    # Which IP family to query. Default IPv6 for backwards compatibility;
    # set database.ip_family: "ipv4" in config.yaml to switch.
    ip_family = config["database"].get("ip_family", "ipv6").lower()
    print(f"  IP family: {ip_family.upper()}")
    if pattern:
        tables = discover_tables(conn, schema, pattern)
    else:
        tables = config.get("tables", [])

    if not tables:
        conn.close()
        raise SystemExit(
            "No tables to query. Set `table_pattern` (e.g. "
            "'sdr_dyn_ide_soc_tcp_user_15m_%') or an explicit `tables:` list "
            "in config/config.yaml.")

    # The 15-minute tables rotate daily (numbers increment monotonically with
    # date), so for a `lookback_days`-day window we only need the most recent
    # ~lookback_days+2 tables. Without this slice we'd scan every table back
    # to project start — most return 0 rows, but each scan still costs time.
    if pattern:
        keep = lookback_days + 2
        if len(tables) > keep:
            print(f"  Trimming {len(tables)} discovered tables to most-recent "
                  f"{keep} (lookback_days={lookback_days} + buffer)")
            tables = tables[-keep:]

    frames = []
    for table in tables:
        print(f"  Querying {table} ...")
        try:
            df = pd.read_sql(_query(table, cutoff, ip_family), conn)
            df.columns = [c.split(".")[-1] for c in df.columns]
            frames.append(df)
            print(f"    -> {len(df):,} rows")
        except Exception as e:
            print(f"    !  Skipped {table}: {e}")

    conn.close()
    if not frames:
        raise SystemExit("No data returned from any table.")
    return pd.concat(frames, ignore_index=True)


def _normalize_subnet_csv(df: pd.DataFrame) -> pd.DataFrame:
    """Lower-case headers and unify the various prefix-column variants
    (ipv4_prefix_24 / subnet_prefix / prefix) into a single canonical
    `ipv6_prefix_48` column, so IPv4 and IPv6 CSVs can be concatenated
    without one stack's rows ending up with a NaN prefix."""
    df.columns = df.columns.str.strip('"').str.lower()
    for c in ("ipv6_prefix_48", "ipv4_prefix_24", "subnet_prefix", "prefix"):
        if c in df.columns:
            if c != "ipv6_prefix_48":
                df = df.rename(columns={c: "ipv6_prefix_48"})
            break
    return df


def load_from_csv(paths) -> pd.DataFrame:
    """
    Load one or more CSV files / folders into a single dataframe.
    `paths` may be a string or a list of strings; each path may be a file
    or a folder of CSVs.
    """
    if isinstance(paths, str):
        paths = [paths]

    import glob
    frames = []
    for raw_path in paths:
        p = os.path.abspath(raw_path)
        if os.path.isdir(p):
            files = sorted(glob.glob(os.path.join(p, "*.csv")))
            if not files:
                raise SystemExit(f"No .csv files found in folder: {p}")
            print(f"  -> reading {len(files)} CSV(s) from {p}")
            for f in files:
                d = _normalize_subnet_csv(pd.read_csv(f))
                frames.append(d)
                print(f"     {os.path.basename(f):<60}  {len(d):>10,} rows")
        elif os.path.isfile(p):
            print(f"  -> reading {p}")
            frames.append(_normalize_subnet_csv(pd.read_csv(p)))
        else:
            raise SystemExit(f"CSV path not found: {p}")

    if not frames:
        raise SystemExit("No CSV data loaded.")
    return pd.concat(frames, ignore_index=True)


def load_ip_csv(path: str) -> pd.DataFrame:
    """
    Load a per-IP CSV (or folder of CSVs) — one row per hour per subscriber IP —
    and collapse it to one row per (gateway, /48 prefix, subscriber_ip) with
    session-weighted average SR/FR2.
    """
    p = os.path.abspath(path)
    if os.path.isdir(p):
        import glob
        files = sorted(glob.glob(os.path.join(p, "*.csv")))
        if not files:
            raise SystemExit(f"No .csv files found in folder: {p}")
        df = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)
    else:
        df = pd.read_csv(p)
    df.columns = df.columns.str.strip('"').str.lower()
    df = df.rename(columns={"ipv6_prefix_48": "prefix", "ms_ip_pa": "subscriber_ip"})

    df["tcp_sr"]        = pd.to_numeric(df["tcp_sr"],        errors="coerce")
    df["tcp_fr2"]       = pd.to_numeric(df["tcp_fr2"],       errors="coerce")
    df["session_count"] = pd.to_numeric(df["session_count"], errors="coerce").fillna(0)

    df["_sr_x_n"]  = df["tcp_sr"]  * df["session_count"]
    df["_fr2_x_n"] = df["tcp_fr2"] * df["session_count"]

    agg = (
        df.groupby(["ugw", "prefix", "subscriber_ip"], as_index=False)
          .agg(sessions=("session_count", "sum"),
               _sr_sum=("_sr_x_n", "sum"),
               _fr2_sum=("_fr2_x_n", "sum"))
    )
    n = agg["sessions"].clip(lower=1)
    agg["tcp_sr"]  = (agg["_sr_sum"]  / n).round(2)
    agg["tcp_fr2"] = (agg["_fr2_sum"] / n).round(2)
    return agg[["ugw", "prefix", "subscriber_ip", "sessions", "tcp_sr", "tcp_fr2"]]


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def prepare(raw: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Returns:
      subnet_df — hourly KPIs per /48 subnet with rolling baseline and sr_drop
      ip_df     — per individual IP with average tcp_sr / tcp_fr2
    """

    # ---- Detect which CSV format we received ----
    # Treat any of these as the subnet-prefix column (handles both IPv6 /48
    # and IPv4 /24 exports — the detection logic is IP-version-agnostic).
    cols = set(raw.columns)
    prefix_col = next(
        (c for c in ("ipv6_prefix_48", "ipv4_prefix_24", "subnet_prefix", "prefix")
         if c in cols),
        None,
    )

    if prefix_col is not None:
        raw = raw.rename(columns={prefix_col: "ipv6_prefix_48"})
        cols = set(raw.columns)
        # Already-aggregated format from our previous queries.
        # The time column is one of:
        #   "hour"           — string  "2026/05/13 00:00"
        #   "day"            — string  "2026/05/13"
        #   "day"            — int     daypartition like 20414 (days-since-epoch)
        subnet_df = raw.rename(columns={"ipv6_prefix_48": "prefix"}).copy()
        time_col = "hour" if "hour" in subnet_df.columns else "day"

        time_numeric = pd.to_numeric(subnet_df[time_col], errors="coerce")
        is_daypartition = (
            time_numeric.notna().all()
            and time_numeric.between(15000, 30000).all()
        )
        if is_daypartition:
            # Anchor the max daypartition value to today's date so the
            # chart shows real calendar dates relative to "now".
            anchor_int = int(time_numeric.max())
            anchor_date = pd.Timestamp(pd.Timestamp.now().date())
            subnet_df["hour_dt"] = anchor_date - pd.to_timedelta(
                anchor_int - time_numeric, unit="D"
            )
        else:
            subnet_df["hour_dt"] = pd.to_datetime(subnet_df[time_col], errors="coerce")
        subnet_df["hour_ts"] = subnet_df["hour_dt"].astype("int64") // 10**9
        subnet_df["tcp_sr"]  = pd.to_numeric(subnet_df["tcp_sr"],  errors="coerce")
        subnet_df["tcp_fr2"] = pd.to_numeric(subnet_df["tcp_fr2"], errors="coerce")
        ip_df = pd.DataFrame()   # no per-IP data in this format

    else:
        # Raw per-IP format from live DB or matching query output
        raw = raw.copy()
        ip_col = "subscriber_ip" if "subscriber_ip" in cols else "ms_ip_pa"
        raw = raw.rename(columns={ip_col: "subscriber_ip"})

        for c in ["succ", "total", "fr2_fail", "fr2_total", "ggsn_pgw_id"]:
            raw[c] = pd.to_numeric(raw[c], errors="coerce").fillna(0)

        raw["ugw"]    = pd.to_numeric(raw["ggsn_pgw_id"], errors="coerce") \
                          .map(GATEWAY_MAP).fillna("other")
        raw["prefix"] = raw["subscriber_ip"].str.split(":").str[:3].str.join(":")

        # -- IP level --
        ip_df = (
            raw.groupby(["ugw", "prefix", "subscriber_ip"], as_index=False)
               .agg(sessions=("total", "sum"), succ=("succ", "sum"),
                    total=("total", "sum"), fr2_fail=("fr2_fail", "sum"),
                    fr2_total=("fr2_total", "sum"))
        )
        ip_df["tcp_sr"]  = ip_df["succ"]     * 100.0 / ip_df["total"].replace(0, pd.NA)
        ip_df["tcp_fr2"] = ip_df["fr2_fail"] * 100.0 / ip_df["fr2_total"].replace(0, pd.NA)
        ip_df = ip_df.round(2)

        # -- Subnet level --
        subnet_df = (
            raw.groupby(["hour_ts", "ugw", "prefix"], as_index=False)
               .agg(session_count=("total", "count"),
                    succ=("succ", "sum"), total=("total", "sum"),
                    fr2_fail=("fr2_fail", "sum"), fr2_total=("fr2_total", "sum"))
        )
        subnet_df = subnet_df[subnet_df["total"] > 100]
        subnet_df["tcp_sr"]  = subnet_df["succ"]     * 100.0 / subnet_df["total"].replace(0, pd.NA)
        subnet_df["tcp_fr2"] = subnet_df["fr2_fail"] * 100.0 / subnet_df["fr2_total"].replace(0, pd.NA)
        subnet_df["hour_dt"] = pd.to_datetime(subnet_df["hour_ts"], unit="s")

    # Drop low-volume subnets — too few sessions makes SR noisy and unreliable.
    return _finalize_subnet_df(subnet_df), ip_df


def _finalize_subnet_df(subnet_df: pd.DataFrame) -> pd.DataFrame:
    """Shared tail of prepare()/prepare_sites(): session floor, IP-family
    tagging, and the peer-based baseline columns. Kept byte-for-byte the
    same logic as before — plain columns, default groupby behavior."""
    if "session_count" in subnet_df.columns:
        subnet_df = subnet_df[subnet_df["session_count"] >= 200].copy()

    # Tag each row's IP family from its prefix so IPv4 and IPv6 are compared
    # against their own peers (IPv4 baseline is naturally lower than IPv6 due
    # to CGNAT, so mixing them weakens detection on both sides).
    # prepare_sites() sets this column itself ("Site") — don't overwrite.
    if "ip_version" not in subnet_df.columns:
        subnet_df["ip_version"] = subnet_df["prefix"].apply(
            lambda p: "IPv6" if isinstance(p, str) and ":" in p else "IPv4"
        )

    # ---- Peer-based baseline ----
    # At each (gateway, ip_version, timepoint), use the 75th-percentile SR
    # across all subnets as the "healthy peer" reference — i.e. what working
    # subnets achieve right now. Flag any subnet well below that reference.
    # Implemented with groupby.quantile + merge instead of .transform():
    # transform re-sorts the full 36M-row result index and OOMs the laptop.
    subnet_df = subnet_df.sort_values(["ugw", "ip_version", "prefix", "hour_dt"])

    _keys = ["ugw", "ip_version", "hour_dt"]
    _base_sr = (subnet_df.groupby(_keys, sort=False)["tcp_sr"]
                         .quantile(0.75).rename("baseline_sr"))
    _base_fr = (subnet_df.groupby(_keys, sort=False)["tcp_fr2"]
                         .quantile(0.25).rename("baseline_fr2"))
    subnet_df = subnet_df.merge(_base_sr, left_on=_keys, right_index=True,
                                how="left", sort=False, copy=False)
    subnet_df = subnet_df.merge(_base_fr, left_on=_keys, right_index=True,
                                how="left", sort=False, copy=False)

    subnet_df["sr_drop"]  = (subnet_df["baseline_sr"]  - subnet_df["tcp_sr"]).round(2)
    subnet_df["fr2_rise"] = (subnet_df["tcp_fr2"] - subnet_df["baseline_fr2"]).round(2)

    return subnet_df


def prepare_sites(raw: pd.DataFrame) -> pd.DataFrame:
    """Site-level CSVs (hour, site, session_count, tcp_2_fr, tcp_3_fr) ->
    the same frame schema prepare() returns for subnets, so the whole
    dashboard works unchanged:

      site              -> prefix
      ugw               -> constant "Sites" (single pseudo-gateway)
      tcp_sr            -> 100 - tcp_3_fr  (synthetic success rate: a "drop"
                           means FR3 is that many points above healthy peers)
      tcp_fr2           -> tcp_3_fr      (secondary "rise" metric, also FR3)
      ip_version        -> "Site"

    The Sites tab focuses on FR3 (per user decision); tcp_2_fr is kept on
    the frame but not displayed.
    """
    df = raw.rename(columns={"site": "prefix"}).copy()
    df["hour_dt"] = pd.to_datetime(df["hour"], errors="coerce")
    df["tcp_2_fr"] = pd.to_numeric(df["tcp_2_fr"], errors="coerce")
    df["tcp_3_fr"] = pd.to_numeric(df["tcp_3_fr"], errors="coerce")
    df["tcp_sr"]   = 100.0 - df["tcp_3_fr"]
    df["tcp_fr2"]  = df["tcp_3_fr"]
    # Newer exports carry the real gateway (ggsn_pgw_id mapped via the same
    # gateway CASE as subnets); older CSVs fall back to one pseudo-gateway.
    if "ugw" not in df.columns:
        df["ugw"] = "Sites"
    df["ip_version"] = "Site"
    df = _finalize_subnet_df(df)

    # Sites use an OWN-NORMAL baseline, not the peer group: a site is
    # degraded when its FR3 rises above what is normal *for that site*.
    # Normal = the site's own best-quarter hours over the loaded period
    # (75th pct of the 100-FR3 mirror == 25th pct of FR3), so it stays
    # sane even if the site was degraded for most of the window.
    df["baseline_sr"] = (df.groupby("prefix")["tcp_sr"]
                           .transform(lambda s: s.quantile(0.75)))
    df["baseline_fr2"] = (df.groupby("prefix")["tcp_fr2"]
                            .transform(lambda s: s.quantile(0.25)))
    df["sr_drop"]  = (df["baseline_sr"]  - df["tcp_sr"]).round(2)
    df["fr2_rise"] = (df["tcp_fr2"] - df["baseline_fr2"]).round(2)
    return df


def compute_contribution(subnet_df: pd.DataFrame, gateway: str, top_n: int = 30):
    """For one gateway, rank each subnet by how much the gateway's weighted SR
    would improve if that subnet were excluded. Approximation — uses
    session_count as the traffic weight."""
    g = subnet_df[subnet_df["ugw"] == gateway].copy()
    if g.empty:
        return pd.DataFrame(), 0.0

    g["_sr_x_n"]  = g["tcp_sr"]  * g["session_count"]
    g["_fr2_x_n"] = g["tcp_fr2"] * g["session_count"]
    per_subnet = (
        g.groupby(["prefix", "ip_version"], as_index=False)
         .agg(sessions=("session_count", "sum"),
              _sr_sum=("_sr_x_n", "sum"),
              _fr2_sum=("_fr2_x_n", "sum"))
    )

    total_n      = per_subnet["sessions"].sum()
    total_sr_sum = per_subnet["_sr_sum"].sum()
    if total_n == 0:
        return pd.DataFrame(), 0.0
    gateway_sr   = total_sr_sum / total_n

    per_subnet["subnet_sr"]      = per_subnet["_sr_sum"]  / per_subnet["sessions"].clip(lower=1)
    per_subnet["subnet_fr2"]     = per_subnet["_fr2_sum"] / per_subnet["sessions"].clip(lower=1)
    per_subnet["sessions_share"] = per_subnet["sessions"] * 100.0 / total_n
    per_subnet["sr_if_removed"]  = (
        (total_sr_sum - per_subnet["_sr_sum"])
        / (total_n - per_subnet["sessions"]).clip(lower=1)
    )
    per_subnet["sr_lift_pts"]    = per_subnet["sr_if_removed"] - gateway_sr

    per_subnet = (
        per_subnet[["prefix", "ip_version", "sessions", "sessions_share",
                    "subnet_sr", "subnet_fr2", "sr_if_removed", "sr_lift_pts"]]
        .round(2)
        .sort_values("sr_lift_pts", ascending=False)
        .head(top_n)
        .reset_index(drop=True)
    )
    return per_subnet, round(gateway_sr, 2)


def find_anomalies(subnet_df: pd.DataFrame, drop_threshold: float,
                   mode: str = "current", min_hours: int = 3,
                   min_history_days: float = 0.0) -> pd.DataFrame:
    """One row per subnet that matches the requested anomaly mode.

    mode:
      "current"     — only subnets STILL broken at the most recent observation
                      (default; matches what's actionable for the routing team)
      "historical"  — any subnet that crossed the threshold at any point in
                      the loaded data (includes subnets that later recovered)
      "recovered"   — subnets that WERE broken but whose latest observation
                      is now back at or above the healthy-peer reference
    min_hours: drop subnets that have fewer than this many observed hours in
               the loaded data — suppresses single-point/very-sparse subnets
               that otherwise produce false-positive flags on low-traffic
               gateways like AlexAuto_XGG09.
    """
    empty_cols = ["ugw", "ip_version", "prefix",
                  "current_sr", "normal_sr",
                  "max_sr_drop", "max_fr2_rise",
                  "first_seen", "worst_hour", "first_appeared"]
    if subnet_df.empty:
        return pd.DataFrame(columns=empty_cols)

    if "ip_version" not in subnet_df.columns:
        subnet_df = subnet_df.copy()
        subnet_df["ip_version"] = "IPv6"

    # Drop subnets that don't have enough observed hours to trust.
    if min_hours and min_hours > 1:
        hour_counts = (
            subnet_df.groupby(["ugw", "prefix"])["hour_dt"]
                     .nunique()
                     .reset_index()
                     .rename(columns={"hour_dt": "_n_hours"})
        )
        eligible = hour_counts[hour_counts["_n_hours"] >= min_hours][["ugw", "prefix"]]
        if eligible.empty:
            return pd.DataFrame(columns=empty_cols)
        subnet_df = subnet_df.merge(eligible, on=["ugw", "prefix"], how="inner")

    # Compute when each subnet first appeared in the loaded data — used both
    # for the (optional) "must have been around for >= N days" filter and for
    # the `first_appeared` column we surface in the UI / CSV report so the
    # operator can tell "this is a freshly-introduced subnet, treat with care".
    first_appeared = (
        subnet_df.groupby(["ugw", "prefix"], as_index=False)["hour_dt"]
                 .min()
                 .rename(columns={"hour_dt": "first_appeared"})
    )
    if min_history_days and min_history_days > 0:
        latest_overall = subnet_df["hour_dt"].max()
        cutoff = latest_overall - pd.Timedelta(days=float(min_history_days))
        old_enough = first_appeared[first_appeared["first_appeared"] <= cutoff][["ugw", "prefix"]]
        if old_enough.empty:
            return pd.DataFrame(columns=empty_cols)
        subnet_df = subnet_df.merge(old_enough, on=["ugw", "prefix"], how="inner")

    # All-time anomalies (any hour with sr_drop > threshold)
    anom_all = subnet_df[subnet_df["sr_drop"] > drop_threshold].copy()
    if anom_all.empty:
        return pd.DataFrame(columns=empty_cols)

    # Most recent observation per subnet — decides "still broken" vs "recovered"
    latest = (
        subnet_df.sort_values("hour_dt")
                 .groupby(["ugw", "prefix"], as_index=False)
                 .tail(1)
                 [["ugw", "prefix", "sr_drop", "tcp_sr", "baseline_sr", "hour_dt"]]
                 .rename(columns={"sr_drop": "latest_sr_drop",
                                  "tcp_sr":  "latest_sr",
                                  "baseline_sr": "latest_baseline",
                                  "hour_dt": "latest_hour"})
    )

    if mode == "current":
        keep = latest[latest["latest_sr_drop"] > drop_threshold][["ugw", "prefix"]]
        anom = anom_all.merge(keep, on=["ugw", "prefix"], how="inner")
    elif mode == "recovered":
        keep = latest[latest["latest_sr_drop"] <= drop_threshold][["ugw", "prefix"]]
        anom = anom_all.merge(keep, on=["ugw", "prefix"], how="inner")
    else:   # "historical"
        anom = anom_all

    if anom.empty:
        return pd.DataFrame(columns=empty_cols)

    worst = (
        anom.sort_values("sr_drop", ascending=False)
            .groupby(["ugw", "prefix"], as_index=False)
            .first()
        [["ugw", "ip_version", "prefix", "tcp_sr", "baseline_sr",
          "sr_drop", "fr2_rise", "hour_dt"]]
        .rename(columns={"tcp_sr": "current_sr", "baseline_sr": "normal_sr",
                         "sr_drop": "max_sr_drop", "fr2_rise": "max_fr2_rise",
                         "hour_dt": "worst_hour"})
        .sort_values("max_sr_drop", ascending=False)
        .reset_index(drop=True)
    )

    first_seen = (
        anom.groupby(["ugw", "prefix"])["hour_dt"].min()
            .reset_index().rename(columns={"hour_dt": "first_seen"})
    )
    out = worst.merge(first_seen, on=["ugw", "prefix"], how="left")
    out = out.merge(first_appeared, on=["ugw", "prefix"], how="left")
    return out


# ---------------------------------------------------------------------------
# Dashboard layout helpers
# ---------------------------------------------------------------------------

SEVERITY = {
    "critical": "#e74c3c",
    "high":     "#e67e22",
    "medium":   "#f39c12",
}


def _severity_color(drop: float) -> str:
    if drop > 30:
        return SEVERITY["critical"]
    if drop > 20:
        return SEVERITY["high"]
    return SEVERITY["medium"]


# ---------------------------------------------------------------------------
# UI theme (light executive)
# ---------------------------------------------------------------------------
C = {
    "bg":       "#f4f6fa",
    "card":     "#ffffff",
    "navy":     "#1f2a44",
    "navy2":    "#2f4b7c",
    "accent":   "#2f6fed",
    "text":     "#1f2a44",
    "muted":    "#8a94a6",
    "border":   "#e6eaf2",
    "critical": "#d64545",
    "high":     "#e8912d",
    "medium":   "#f2c94c",
    "ok":       "#2ea44f",
}
CARD_STYLE = {"background": C["card"], "borderRadius": "12px",
              "padding": "20px 22px",
              "boxShadow": "0 1px 3px rgba(31,42,68,0.08)"}
SECTION_TITLE = {"margin": "0 0 4px", "fontSize": "15px",
                 "fontWeight": "700", "color": C["text"]}
SECTION_SUB = {"margin": "0 0 14px", "fontSize": "12px", "color": C["muted"]}
LABEL_STYLE = {"fontWeight": "600", "fontSize": "11px", "color": C["muted"],
               "textTransform": "uppercase", "letterSpacing": "0.4px"}


def _chip(text: str, color: str) -> html.Span:
    return html.Span(text, style={
        "backgroundColor": color, "color": "white", "borderRadius": "10px",
        "padding": "3px 11px", "fontSize": "10.5px", "fontWeight": "700",
        "letterSpacing": "0.5px"})


def _stat_card(label: str, value: str, color: str, sub: str = "") -> html.Div:
    return html.Div(
        style={**CARD_STYLE, "flex": "1", "minWidth": "150px",
               "padding": "16px 20px"},
        children=[
            html.Div(label, style={**LABEL_STYLE, "marginBottom": "4px"}),
            html.Div(value, style={"fontSize": "30px", "fontWeight": "800",
                                   "color": color, "lineHeight": "1.1"}),
            html.Div(sub, style={"fontSize": "11px", "color": C["muted"],
                                 "marginTop": "2px", "minHeight": "13px"}),
        ])


def _severity_of(drop: float) -> tuple[str, str]:
    if drop > 30:
        return "CRITICAL", C["critical"]
    if drop > 20:
        return "HIGH", C["high"]
    return "MEDIUM", C["medium"]


# ---------------------------------------------------------------------------
# Build Dash app
# ---------------------------------------------------------------------------

def build_app(datasets: "dict[str, pd.DataFrame]", ip_df: pd.DataFrame,
              default_threshold: float,
              raw_datasets: "dict[str, pd.DataFrame] | None" = None,
              cells_df: "pd.DataFrame | None" = None,
              url_base_pathname: str = "/") -> Dash:
    """`datasets` maps a tab label ("IPv6", "IPv4", "Sites") to a fully
    prepared frame (same schema prepare() returns). The tab bar switches the
    whole view between them; every callback reads datasets[active_tab].
    `raw_datasets` (unprepared frames per tab) feeds the day-compare panel;
    `cells_df` feeds the per-site cell drill-down.
    `url_base_pathname` lets this app be mounted at a sub-path (e.g.
    "/network-degradation/") behind a hub/landing page instead of at "/";
    Dash needs this so its internal asset and callback URLs resolve
    correctly under the sub-path."""

    app = Dash(__name__, suppress_callback_exceptions=True,
               url_base_pathname=url_base_pathname)
    has_ip_data = not ip_df.empty
    raw_datasets = raw_datasets or {}
    cells_df = cells_df if cells_df is not None else pd.DataFrame()
    has_cell_data = not cells_df.empty

    first_tab   = next(iter(datasets))
    first_df    = datasets[first_tab]
    gateways    = ["All"] + sorted(first_df["ugw"].dropna().unique())
    all_anom    = find_anomalies(first_df, default_threshold)
    subnet_options = _build_subnet_options(all_anom)

    # find_anomalies is expensive on multi-million-row families (IPv4) and
    # was being recomputed on every click — cache per (tab, filter params).
    # Results are small summary tables, so keeping several is fine.
    _anom_cache: dict = {}

    def _cached_anomalies(tab, threshold, mode, min_hours, min_history_days):
        key = (tab, float(threshold), str(mode), int(min_hours),
               int(min_history_days))
        if key not in _anom_cache:
            df = datasets[tab] if tab in datasets else datasets[first_tab]
            _anom_cache[key] = find_anomalies(
                df, threshold, mode=mode, min_hours=min_hours,
                min_history_days=min_history_days)
        return _anom_cache[key]

    # One-line caption per tab explaining what "drop" means there.
    _TAB_CAPTIONS = {
        "IPv6":  "IPv6 /48 subnets — drop = TCP SR this many points below healthy peers (75th pct)",
        "IPv4":  "IPv4 /24 subnets — drop = TCP SR this many points below healthy peers (75th pct)",
        "Sites": "Sites (RAN) — drop = TCP FR3 this many points ABOVE the site's own normal level (its best-quarter hours)",
    }

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    app.layout = html.Div(
        style={"fontFamily": "Segoe UI, Arial, sans-serif",
               "backgroundColor": C["bg"], "minHeight": "100vh",
               "paddingBottom": "40px"},
        children=[

            # ── Header ─────────────────────────────────────────────────
            html.Div(
                style={"background": f"linear-gradient(135deg,{C['navy']},{C['navy2']})",
                       "color": "white", "padding": "20px 32px",
                       "display": "flex", "alignItems": "center",
                       "justifyContent": "space-between",
                       "flexWrap": "wrap", "gap": "12px"},
                children=[
                    html.Div([
                        html.H1("Network Degradation Monitor",
                                style={"margin": 0, "fontSize": "22px",
                                       "fontWeight": "700"}),
                        html.P("TCP KPI anomalies across subnets, gateways and "
                               "sites — peer-benchmarked, updated daily.",
                               style={"margin": "4px 0 0", "color": "#b9c6e4",
                                      "fontSize": "12.5px"}),
                    ]),
                    html.Div([
                        html.Button(
                            "Download Report", id="download-btn", n_clicks=0,
                            style={"background": "rgba(255,255,255,0.14)",
                                   "color": "white",
                                   "border": "1px solid rgba(255,255,255,0.35)",
                                   "borderRadius": "8px", "padding": "9px 18px",
                                   "fontWeight": "600", "fontSize": "13px",
                                   "cursor": "pointer", "whiteSpace": "nowrap"},
                        ),
                        dcc.Download(id="download-report"),
                    ]),
                ],
            ),

            html.Div(
                style={"padding": "16px 24px 0"},
                children=[

                    # ── Family tabs ─────────────────────────────────────
                    dcc.Tabs(
                        id="family-tabs",
                        value=first_tab,
                        style={"marginBottom": "6px"},
                        colors={"border": C["border"], "primary": C["accent"],
                                "background": C["bg"]},
                        children=[
                            dcc.Tab(
                                label=label, value=label,
                                style={"padding": "9px 20px",
                                       "fontWeight": "600", "fontSize": "13px"},
                                selected_style={"padding": "9px 20px",
                                                "fontWeight": "700",
                                                "fontSize": "13px",
                                                "borderBottom":
                                                    f"3px solid {C['accent']}",
                                                "color": C["navy"]},
                            )
                            for label in datasets
                        ],
                    ),
                    html.Div(
                        id="tab-caption",
                        children=_TAB_CAPTIONS.get(first_tab, ""),
                        style={"fontSize": "12px", "color": C["muted"],
                               "margin": "0 4px 14px"},
                    ),

                    # ── Executive summary band ──────────────────────────
                    html.Div(
                        id="kpi-cards",
                        style={"display": "flex", "gap": "14px",
                               "marginBottom": "18px", "flexWrap": "wrap"},
                    ),

                    # ── Main row ────────────────────────────────────────
                    html.Div(
                        style={"display": "flex", "gap": "16px",
                               "flexWrap": "wrap",
                               "alignItems": "flex-start"},
                        children=[

                            # Left: filters + clickable impacted list
                            html.Div(
                                style={"flex": "1", "minWidth": "320px",
                                       "maxWidth": "420px", "display": "flex",
                                       "flexDirection": "column",
                                       "gap": "16px"},
                                children=[
                                    html.Div(
                                        style=CARD_STYLE,
                                        children=[
                                            html.Div("Filters",
                                                     style=SECTION_TITLE),
                                            html.Div(style={"marginTop": "10px"}, children=[
                                                html.Label("Gateway",
                                                           style=LABEL_STYLE),
                                                dcc.Dropdown(
                                                    id="gw-filter",
                                                    options=[{"label": g, "value": g}
                                                             for g in gateways],
                                                    value="All", clearable=False,
                                                    style={"margin": "4px 0 12px",
                                                           "fontSize": "13px"}),
                                                html.Label("View",
                                                           style=LABEL_STYLE),
                                                dcc.Dropdown(
                                                    id="mode-dropdown",
                                                    options=[
                                                        {"label": "Currently Impacted (still broken)", "value": "current"},
                                                        {"label": "All Historical Drops (incl. resolved)", "value": "historical"},
                                                        {"label": "Recovered (was broken, now healthy)", "value": "recovered"},
                                                    ],
                                                    value="current",
                                                    clearable=False,
                                                    style={"margin": "4px 0 12px",
                                                           "fontSize": "13px"},
                                                ),
                                                html.Label(id="threshold-label",
                                                           style=LABEL_STYLE),
                                                dcc.Slider(
                                                    id="threshold-slider",
                                                    min=5, max=40, step=1,
                                                    value=int(default_threshold),
                                                    marks={5: "5", 10: "10", 15: "15",
                                                           20: "20", 30: "30", 40: "40"},
                                                    tooltip={"placement": "bottom",
                                                             "always_visible": False}),
                                                html.Label("Min Hours of History",
                                                           style={**LABEL_STYLE,
                                                                  "display": "block",
                                                                  "marginTop": "10px"}),
                                                dcc.Slider(
                                                    id="min-hours-slider",
                                                    min=1, max=24, step=1, value=3,
                                                    marks={1: "1", 6: "6",
                                                           12: "12", 24: "24"},
                                                    tooltip={"placement": "bottom",
                                                             "always_visible": False}),
                                                html.Label("Min Days Since First Appeared",
                                                           style={**LABEL_STYLE,
                                                                  "display": "block",
                                                                  "marginTop": "10px"}),
                                                dcc.Slider(
                                                    id="min-history-days-slider",
                                                    min=0, max=14, step=1, value=0,
                                                    marks={0: "0", 3: "3",
                                                           7: "7", 14: "14"},
                                                    tooltip={"placement": "bottom",
                                                             "always_visible": False}),
                                            ]),
                                        ],
                                    ),
                                    html.Div(
                                        style=CARD_STYLE,
                                        children=[
                                            html.Div("Impacted",
                                                     style=SECTION_TITLE),
                                            html.Div(
                                                "Click an item to see its trend "
                                                "and drill-down.",
                                                style=SECTION_SUB),
                                            dcc.Dropdown(
                                                id="subnet-selector",
                                                options=subnet_options,
                                                placeholder="Search a subnet / site ...",
                                                searchable=True,
                                                style={"marginBottom": "12px",
                                                       "fontSize": "13px"}),
                                            html.Div(
                                                id="subnet-list",
                                                style={"maxHeight": "560px",
                                                       "overflowY": "auto",
                                                       "paddingRight": "4px"},
                                            ),
                                        ],
                                    ),
                                ],
                            ),

                            # Right: trend chart + drill-down
                            html.Div(
                                style={"flex": "3", "minWidth": "420px",
                                       "display": "flex",
                                       "flexDirection": "column",
                                       "gap": "16px"},
                                children=[
                                    html.Div(
                                        style=CARD_STYLE,
                                        children=[
                                            html.H3(id="chart-title",
                                                    style=SECTION_TITLE),
                                            dcc.Graph(
                                                id="kpi-chart",
                                                style={"height": "360px"},
                                                config={"displayModeBar": False}),
                                        ],
                                    ),
                                    html.Div(
                                        id="ip-panel",
                                        style=CARD_STYLE,
                                        children=[
                                            html.H3(
                                                id="ip-panel-title",
                                                children="Affected Subscriber IPs",
                                                style=SECTION_TITLE),
                                            html.Div(id="ip-table"),
                                        ],
                                    ),
                                ],
                            ),
                        ],
                    ),

                    # ── Site heatmap (Sites tab only) ───────────────────
                    html.Div(
                        id="site-heatmap-panel",
                        style={"display": "none"},
                        children=[
                            html.Div(
                                style={**CARD_STYLE, "marginTop": "16px"},
                                children=[
                                    html.H3("Worst Sites — FR3 Heatmap",
                                            style=SECTION_TITLE),
                                    html.P("Top 25 sites by average TCP FR3 "
                                           "over the last 72 hours, hour by "
                                           "hour. Darker red = higher failure "
                                           "rate.",
                                           style=SECTION_SUB),
                                    dcc.Graph(id="site-heatmap",
                                              style={"height": "560px"},
                                              config={"displayModeBar": False}),
                                ],
                            ),
                        ],
                    ),

                    # ── Compare days ────────────────────────────────────
                    html.Div(
                        style={**CARD_STYLE, "marginTop": "16px"},
                        children=[
                            html.H3("Compare Days", style=SECTION_TITLE),
                            html.P("The picked day overlaid with the day "
                                   "before and the same weekday last week. "
                                   "Select an item above to scope the lines "
                                   "to it.",
                                   style=SECTION_SUB),
                            html.Div(
                                style={"maxWidth": "240px",
                                       "marginBottom": "10px"},
                                children=[
                                    dcc.DatePickerSingle(
                                        id="compare-date",
                                        date=(pd.Timestamp.now()
                                              - pd.Timedelta(days=1)).date(),
                                        display_format="YYYY-MM-DD",
                                    ),
                                ],
                            ),
                            dcc.Graph(id="compare-chart",
                                      style={"height": "300px"},
                                      config={"displayModeBar": False}),
                            html.Button(
                                "Show per-entity table",
                                id="compare-table-toggle",
                                n_clicks=0,
                                style={"background": "none",
                                       "border": f"1px solid {C['border']}",
                                       "borderRadius": "8px",
                                       "padding": "7px 14px",
                                       "fontSize": "12px",
                                       "fontWeight": "600",
                                       "color": C["accent"],
                                       "cursor": "pointer",
                                       "marginTop": "6px"},
                            ),
                            html.Div(
                                id="compare-table-wrap",
                                style={"marginTop": "12px",
                                       "display": "none"}),
                        ],
                    ),

                    # ── Gateway contribution ────────────────────────────
                    html.Div(
                        style={**CARD_STYLE, "marginTop": "16px"},
                        children=[
                            html.H3("Gateway Contribution Analysis",
                                    style=SECTION_TITLE),
                            html.P("Which entities drag the overall KPI down "
                                   "the most — removing the top one lifts it "
                                   "by the value shown.",
                                   style=SECTION_SUB),
                            html.Div(
                                style={"display": "flex", "gap": "16px",
                                       "alignItems": "flex-end",
                                       "marginBottom": "12px",
                                       "flexWrap": "wrap"},
                                children=[
                                    html.Div(
                                        style={"flex": "1",
                                               "minWidth": "220px"},
                                        children=[
                                            html.Label("Gateway",
                                                       style=LABEL_STYLE),
                                            dcc.Dropdown(
                                                id="contrib-gw",
                                                options=[{"label": g, "value": g}
                                                         for g in sorted(first_df["ugw"].dropna().unique())],
                                                placeholder="Select a gateway to analyse ...",
                                                clearable=False,
                                                style={"marginTop": "4px",
                                                       "fontSize": "13px"},
                                            ),
                                        ],
                                    ),
                                    html.Div(
                                        id="contrib-summary",
                                        style={"fontSize": "13px",
                                               "color": C["text"],
                                               "minWidth": "260px"},
                                    ),
                                ],
                            ),
                            html.Div(id="contrib-table"),
                        ],
                    ),
                ],
            ),
        ],
    )
    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    @callback(
        Output("gw-filter",       "options"),
        Output("gw-filter",       "value"),
        Output("contrib-gw",      "options"),
        Output("contrib-gw",      "value"),
        Output("tab-caption",     "children"),
        Input("family-tabs",      "value"),
    )
    def switch_tab(tab):
        """Tab switched -> rebuild gateway dropdowns for the new dataset.
        (subnet-selector.value is owned by select_entity below.)"""
        df = datasets[tab] if tab in datasets else datasets[first_tab]
        gws = sorted(df["ugw"].dropna().unique())
        return ([{"label": g, "value": g} for g in ["All"] + gws],
                "All",
                [{"label": g, "value": g} for g in gws],
                None,
                _TAB_CAPTIONS.get(tab, ""))

    @callback(
        Output("subnet-selector", "value"),
        Input("family-tabs", "value"),
        Input({"type": "anom-item", "index": ALL}, "n_clicks"),
        prevent_initial_call=True,
    )
    def select_entity(_tab, _clicks):
        """Single owner of the selection: tab switch clears it, clicking an
        impacted-list item sets it."""
        tid = ctx.triggered_id
        if tid == "family-tabs":
            return None
        if isinstance(tid, dict) and tid.get("type") == "anom-item":
            return tid["index"]
        return no_update

    @callback(
        Output("kpi-cards",        "children"),
        Output("subnet-list",      "children"),
        Output("subnet-selector",  "options"),
        Output("threshold-label",  "children"),
        Input("family-tabs",              "value"),
        Input("gw-filter",                "value"),
        Input("threshold-slider",         "value"),
        Input("mode-dropdown",            "value"),
        Input("min-hours-slider",         "value"),
        Input("min-history-days-slider",  "value"),
        Input("subnet-selector",          "value"),
    )
    def update_left_panel(tab, gw_filter, threshold, mode, min_hours,
                          min_history_days, selected):
        anom = _cached_anomalies(tab, threshold, mode, min_hours,
                                 min_history_days)
        if gw_filter != "All":
            anom = anom[anom["ugw"] == gw_filter]

        label = f"Sensitivity — drop greater than {threshold} pts vs healthy peers"

        n_total    = len(anom)
        n_critical = int((anom["max_sr_drop"] > 30).sum()) if not anom.empty else 0
        n_high     = int(((anom["max_sr_drop"] > 20) & (anom["max_sr_drop"] <= 30)).sum()) if not anom.empty else 0
        n_gw       = int(anom["ugw"].nunique()) if not anom.empty else 0
        worst      = float(anom["max_sr_drop"].max()) if not anom.empty else 0.0

        mode_label = {"current": "Currently Impacted",
                      "historical": "Historical Drops",
                      "recovered": "Recovered"}.get(mode, "Subnets")

        # ── Executive summary band ────────────────────────────────────
        if anom.empty:
            band = html.Div(
                style={**CARD_STYLE, "flex": "1.6", "minWidth": "280px",
                       "display": "flex", "alignItems": "center",
                       "gap": "14px"},
                children=[
                    _chip("ALL CLEAR", C["ok"]),
                    html.Div("Nothing beyond the sensitivity threshold "
                             "right now.",
                             style={"fontSize": "13px", "color": C["muted"]}),
                ])
        else:
            band = html.Div(
                style={**CARD_STYLE, "flex": "1.6", "minWidth": "280px"},
                children=[
                    html.Div(
                        style={"display": "flex", "alignItems": "center",
                               "gap": "12px"},
                        children=[
                            _chip("DEGRADED", C["critical"]),
                            html.Div(f"{n_total} impacted",
                                     style={"fontSize": "22px",
                                            "fontWeight": "800",
                                            "color": C["text"]}),
                        ]),
                    html.Div(f"{mode_label} · worst drop {worst:.1f} pts",
                             style={"fontSize": "11.5px",
                                    "color": C["muted"],
                                    "marginTop": "6px"}),
                ])

        cards = [
            band,
            _stat_card("Critical", str(n_critical), C["critical"],
                       sub="drop > 30 pts"),
            _stat_card("High", str(n_high), C["high"],
                       sub="drop 20–30 pts"),
            _stat_card("Sites affected" if tab == "Sites"
                       else "Gateways affected",
                       str(n_gw), C["accent"]),
        ]

        if anom.empty:
            msg = html.P("No anomalies found at this threshold.",
                         style={"color": C["muted"], "fontSize": "13px"})
            return cards, msg, [], label

        # ── Clickable impacted list ───────────────────────────────────
        items = [
            html.Div(
                f"{n_total} impacted · showing first {min(n_total, 60)}",
                style={"fontSize": "11px", "color": C["muted"],
                       "marginBottom": "8px"}),
        ]
        for _, r in anom.head(60).iterrows():
            sev, color = _severity_of(r["max_sr_drop"])
            value = f"{r['ugw']}|{r['prefix']}"
            is_sel = (value == selected)
            first = (r["first_seen"].strftime("%Y-%m-%d %H:%M")
                     if pd.notna(r.get("first_seen")) else "—")
            items.append(html.Div(
                id={"type": "anom-item", "index": value},
                n_clicks=0,
                style={"padding": "10px 12px", "marginBottom": "6px",
                       "borderRadius": "8px", "cursor": "pointer",
                       "border": f"2px solid {C['accent'] if is_sel else 'transparent'}",
                       "borderLeft": f"4px solid {color}",
                       "background": "#eef3ff" if is_sel else "#fafbfd"},
                children=[
                    html.Div(
                        style={"display": "flex",
                               "justifyContent": "space-between",
                               "alignItems": "center", "gap": "8px"},
                        children=[
                            html.Span(r["prefix"],
                                      style={"fontWeight": "700",
                                             "fontSize": "13px",
                                             "color": C["text"],
                                             "wordBreak": "break-all"}),
                            _chip(sev, color),
                        ]),
                    html.Div(
                        f"{r['ugw']} · drop {r['max_sr_drop']:.1f} pts "
                        f"· since {first}",
                        style={"fontSize": "11px", "color": C["muted"],
                               "marginTop": "4px"}),
                ],
            ))

        return cards, html.Div(items), _build_subnet_options(anom), label

    @callback(
        Output("compare-table-wrap",   "style"),
        Output("compare-table-toggle", "children"),
        Input("compare-table-toggle",  "n_clicks"),
        State("compare-table-wrap",    "style"),
        prevent_initial_call=True,
    )
    def toggle_compare_table(_n, style):
        currently_open = (style or {}).get("display") != "none"
        new_style = {"marginTop": "12px",
                     "display": "none" if currently_open else "block"}
        return new_style, ("Show per-entity table" if currently_open
                           else "Hide per-entity table")

    @callback(
        Output("contrib-summary", "children"),
        Output("contrib-table",   "children"),
        Input("family-tabs",      "value"),
        Input("contrib-gw",       "value"),
    )
    def update_contribution(tab, gateway):
        if not gateway:
            return "", ""
        subnet_df = datasets[tab] if tab in datasets else datasets[first_tab]
        df, gw_sr = compute_contribution(subnet_df, gateway, top_n=30)
        if df.empty:
            return f"No data for {gateway}.", ""

        top_lift = df.iloc[0]["sr_lift_pts"]
        top_subnet = df.iloc[0]["prefix"]
        cumulative_lift_top10 = df.head(10)["sr_lift_pts"].sum()
        summary = html.Div([
            html.Div(f"{gateway} current overall SR: {gw_sr:.2f}%",
                     style={"fontWeight": "600", "marginBottom": "4px"}),
            html.Div(f"Biggest single contributor: {top_subnet} → removing it lifts SR by "
                     f"{top_lift:.2f} pts.", style={"color": "#7f8c8d"}),
            html.Div(f"Removing the top 10 contributors lifts SR by "
                     f"~{cumulative_lift_top10:.2f} pts (rough sum, real combined effect differs).",
                     style={"color": "#7f8c8d"}),
        ])

        display = df.copy()
        display["subnet_sr"]     = display["subnet_sr"].round(1).astype(str) + " %"
        display["subnet_fr2"]    = display["subnet_fr2"].round(1).astype(str) + " %"
        display["sr_if_removed"] = display["sr_if_removed"].round(2).astype(str) + " %"
        display["sessions_share"] = display["sessions_share"].round(2).astype(str) + " %"

        table = dash_table.DataTable(
            data=display.to_dict("records"),
            columns=[
                {"name": "Subnet",             "id": "prefix"},
                {"name": "Family",             "id": "ip_version"},
                {"name": "Sessions",           "id": "sessions"},
                {"name": "Volume share",       "id": "sessions_share"},
                {"name": "Subnet SR",          "id": "subnet_sr"},
                {"name": "Subnet FR2",         "id": "subnet_fr2"},
                {"name": "Gateway SR if removed", "id": "sr_if_removed"},
                {"name": "SR lift (pts)",      "id": "sr_lift_pts"},
            ],
            sort_action="native",
            filter_action="native",
            page_size=15,
            export_format="csv",
            export_headers="display",
            style_table={"overflowX": "auto"},
            style_header={"backgroundColor": "#2c3e50", "color": "white",
                          "fontWeight": "bold", "fontSize": "13px"},
            style_cell={"padding": "8px 12px", "fontSize": "13px",
                        "border": "1px solid #f0f0f0"},
            style_data_conditional=[
                {"if": {"column_id": "sr_lift_pts", "filter_query": "{sr_lift_pts} > 5"},
                 "backgroundColor": "#fdecea", "color": "#c0392b", "fontWeight": "600"},
                {"if": {"column_id": "sr_lift_pts", "filter_query": "{sr_lift_pts} > 1"},
                 "backgroundColor": "#fef5e7", "color": "#e67e22"},
            ],
        )
        return summary, table

    @callback(
        Output("download-report", "data"),
        Input("download-btn",     "n_clicks"),
        State("family-tabs",      "value"),
        State("gw-filter",        "value"),
        State("threshold-slider",         "value"),
        State("mode-dropdown",            "value"),
        State("min-hours-slider",         "value"),
        State("min-history-days-slider",  "value"),
        prevent_initial_call=True,
    )
    def export_report(n_clicks, tab, gw_filter, threshold, mode, min_hours, min_history_days):
        anom = _cached_anomalies(tab, threshold, mode, min_hours,
                                 min_history_days)
        if gw_filter and gw_filter != "All":
            anom = anom[anom["ugw"] == gw_filter]

        if anom.empty:
            return no_update

        report = anom.copy()
        report["severity"] = report["max_sr_drop"].apply(
            lambda d: "Critical" if d > 30 else ("High" if d > 20 else "Medium")
        )
        if "ip_version" not in report.columns:
            report["ip_version"] = "IPv6"
        if "first_appeared" not in report.columns:
            report["first_appeared"] = pd.NaT

        if (tab or first_tab) == "Sites":
            # FR3 focus: current/peer FR3 derived from the synthetic mirror
            # (100 - SR); max_sr_drop IS the FR3 excess vs peers.
            report["Current FR3 (%)"]       = (100 - report["current_sr"]).round(2)
            report["Healthy Peer FR3 (%)"]  = (100 - report["normal_sr"]).round(2)
            report["FR3 Excess vs Peers (pts)"] = report["max_sr_drop"]
            report = report[[
                "severity", "ip_version", "prefix",
                "Current FR3 (%)", "Healthy Peer FR3 (%)",
                "FR3 Excess vs Peers (pts)",
                "first_appeared", "first_seen", "worst_hour",
            ]]
            report.columns = [
                "Severity", "IP Family", "Site",
                "Current FR3 (%)", "Healthy Peer FR3 (%)",
                "FR3 Excess vs Peers (pts)",
                "First Appeared", "First Seen", "Worst Hour",
            ]
        else:
            report = report[[
                "severity", "ip_version", "ugw", "prefix",
                "current_sr", "normal_sr", "max_sr_drop", "max_fr2_rise",
                "first_appeared", "first_seen", "worst_hour",
            ]]
            report.columns = [
                "Severity", "IP Family", "Gateway", "Subnet",
                "Current SR (%)", "Healthy Peer SR (%)", "SR Drop (pts)", "FR2 Rise (pts)",
                "First Appeared", "First Seen", "Worst Hour",
            ]
        for col in ("First Appeared", "First Seen", "Worst Hour"):
            report[col] = pd.to_datetime(report[col]).dt.strftime("%Y-%m-%d %H:%M")

        ts = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
        mode_tag = {"current": "currently_impacted",
                    "historical": "historical_drops",
                    "recovered": "recovered"}.get(mode or "current", "subnets")
        tab_tag = (tab or first_tab).lower()
        filename = f"tcp_kpi_{tab_tag}_{mode_tag}_{ts}.csv"
        return dcc.send_data_frame(report.to_csv, filename, index=False)

    @callback(
        Output("kpi-chart",      "figure"),
        Output("chart-title",    "children"),
        Output("ip-table",       "children"),
        Output("ip-panel-title", "children"),
        Input("family-tabs",     "value"),
        Input("subnet-selector", "value"),
    )
    def update_detail(tab, selected):
        subnet_df = datasets[tab] if tab in datasets else datasets[first_tab]
        is_sites = (tab == "Sites")
        panel_title = "Cells of Selected Site" if is_sites else "Affected Subscriber IPs"
        empty_fig = _empty_figure("← Select a subnet from the dropdown to see its trend")
        no_selection_msg = html.P(
            "Select a site to see its cells." if is_sites
            else "Select a subnet to see affected IPs.",
            style={"color": "#95a5a6", "fontSize": "13px"})

        if not selected:
            return empty_fig, "KPI Trend Over Time", no_selection_msg, panel_title

        try:
            ugw, prefix = selected.split("|", 1)
        except ValueError:
            return empty_fig, "KPI Trend Over Time", no_selection_msg, panel_title

        s = subnet_df[(subnet_df["ugw"] == ugw) & (subnet_df["prefix"] == prefix)].sort_values("hour_dt")

        if s.empty:
            return _empty_figure("No data for this subnet"), prefix, no_selection_msg, panel_title

        fig = go.Figure()
        x_vals = s["hour_dt"].tolist()

        if is_sites:
            # Sites tab: FR3 vs the site's OWN normal level (flat line).
            own_normal = 100.0 - s["baseline_sr"]
            base_y     = own_normal.round(1)
            base_name  = "Own normal FR3 (best-quarter)"
            upper      = (own_normal + 5).tolist()
            lower      = (own_normal - 5).clip(lower=0).tolist()
            main_y     = s["tcp_3_fr"]
            main_name  = "TCP FR3 (%)"
            sec_y      = None
            sec_name   = None
            same_axis  = True
        else:
            base_y     = s["baseline_sr"].round(1)
            base_name  = "Healthy peers (75th pct)"
            upper      = (s["baseline_sr"] + 5).tolist()
            lower      = (s["baseline_sr"] - 5).tolist()
            main_y     = s["tcp_sr"]
            main_name  = "TCP SR (%)"
            sec_y      = s["tcp_fr2"]
            sec_name   = "TCP FR2 (%)"
            same_axis  = False

        # Shaded normal range band around baseline
        fig.add_trace(go.Scatter(
            x=x_vals + x_vals[::-1],
            y=upper + lower[::-1],
            fill="toself",
            fillcolor="rgba(52,152,219,0.12)",
            line=dict(color="rgba(0,0,0,0)"),
            name="Healthy peer range",
            hoverinfo="skip",
        ))

        # Healthy-peer reference line
        fig.add_trace(go.Scatter(
            x=s["hour_dt"], y=base_y,
            mode="lines", name=base_name,
            line=dict(color="#3498db", width=2, dash="dot"),
        ))

        # Main metric
        fig.add_trace(go.Scatter(
            x=s["hour_dt"], y=main_y.round(1),
            mode="lines+markers", name=main_name,
            line=dict(color="#e74c3c", width=2),
            marker=dict(size=4),
        ))

        # Secondary metric (subnets only — the Sites tab shows FR3 alone)
        if sec_y is not None:
            fig.add_trace(go.Scatter(
                x=s["hour_dt"], y=sec_y.round(1),
                mode="lines", name=sec_name,
                line=dict(color="#e67e22", width=1.5, dash="dash"),
                yaxis="y" if same_axis else "y2",
            ))

        fig.update_layout(
            template="plotly_white",
            hovermode="x unified",
            legend=dict(orientation="h", y=-0.25, x=0),
            yaxis=dict(title=main_name, range=[0, 105], fixedrange=True),
            xaxis=dict(title="Hour"),
            margin=dict(t=10, b=40, l=50, r=50),
        )
        if not same_axis:
            fig.update_layout(
                yaxis2=dict(title=sec_name, overlaying="y", side="right",
                            range=[0, 105], fixedrange=True, showgrid=False),
            )

        title = f"{prefix}  ·  {ugw}"

        # ---- Drill-down table: cells (Sites tab) or subscriber IPs ----
        if is_sites:
            ip_content = _cell_drilldown(cells_df, prefix, has_cell_data)
        elif not has_ip_data:
            ip_content = html.P(
                "Per-IP breakdown not available for this view "
                "(subnet drill-down only, via --ip-csv).",
                style={"color": "#95a5a6", "fontSize": "13px"},
            )
        else:
            i = (
                ip_df[(ip_df["ugw"] == ugw) & (ip_df["prefix"] == prefix)]
                [["subscriber_ip", "sessions", "tcp_sr", "tcp_fr2"]]
                .sort_values("tcp_sr")
                .reset_index(drop=True)
            )
            if i.empty:
                ip_content = html.P("No individual IP data for this subnet.",
                                    style={"color": "#95a5a6", "fontSize": "13px"})
            else:
                ip_content = dash_table.DataTable(
                    data=i.to_dict("records"),
                    columns=[
                        {"name": "Subscriber IPv6 Address", "id": "subscriber_ip"},
                        {"name": "Sessions",                "id": "sessions"},
                        {"name": "Avg TCP SR (%)",          "id": "tcp_sr"},
                        {"name": "Avg TCP FR2 (%)",         "id": "tcp_fr2"},
                    ],
                    sort_action="native",
                    filter_action="native",
                    page_size=15,
                    style_table={"overflowX": "auto"},
                    style_header={
                        "backgroundColor": "#2c3e50", "color": "white",
                        "fontWeight": "bold", "fontSize": "13px",
                    },
                    style_cell={"padding": "8px 12px", "fontSize": "13px", "border": "1px solid #f0f0f0"},
                    style_data_conditional=[
                        {"if": {"filter_query": "{tcp_sr} < 30"},
                         "backgroundColor": "#fdecea", "color": "#c0392b"},
                        {"if": {"filter_query": "{tcp_sr} >= 30 && {tcp_sr} < 60"},
                         "backgroundColor": "#fef5e7", "color": "#e67e22"},
                    ],
                )

        return fig, title, ip_content, panel_title

    @callback(
        Output("site-heatmap",       "figure"),
        Output("site-heatmap-panel", "style"),
        Input("family-tabs",         "value"),
    )
    def update_site_heatmap(tab):
        hidden = {"display": "none"}
        shown = {"display": "block"}
        if tab != "Sites" or "Sites" not in datasets:
            return go.Figure(), hidden

        df = datasets["Sites"]
        # Top 25 worst sites by mean FR3, last 72 hours only — keeps the
        # grid readable (more rows/columns turns it into clutter).
        cutoff = df["hour_dt"].max() - pd.Timedelta(hours=72)
        df = df[df["hour_dt"] >= cutoff]
        worst = (df.groupby("prefix")["tcp_3_fr"].mean()
                   .nlargest(25).index.tolist())
        sub = df[df["prefix"].isin(worst)]
        pivot = (sub.groupby(["prefix", "hour_dt"])["tcp_3_fr"].mean()
                    .unstack("hour_dt"))
        # Order rows worst-first, columns chronological.
        pivot = pivot.loc[worst]
        pivot = pivot[sorted(pivot.columns)]

        fig = go.Figure(go.Heatmap(
            z=pivot.values,
            x=[pd.Timestamp(c).strftime("%Y-%m-%d %H:%M") for c in pivot.columns],
            y=pivot.index.tolist(),
            colorscale="Reds",
            colorbar={"title": "FR3 %"},
            hovertemplate="site=%{y}<br>hour=%{x}<br>FR3=%{z:.2f}%<extra></extra>",
        ))
        fig.update_layout(
            template="plotly_white",
            xaxis={"title": "Hour", "tickangle": -45},
            yaxis={"title": "", "autorange": "reversed"},
            margin={"t": 10, "b": 80, "l": 100, "r": 40},
        )
        return fig, shown

    @callback(
        Output("compare-table-wrap", "children"),
        Input("family-tabs",         "value"),
        Input("compare-date",        "date"),
    )
    def update_compare(tab, date_str):
        if _compare_days is None:
            return html.P("Day-compare unavailable (tools/compare_days.py "
                          "not found).", style={"color": "#95a5a6",
                                                "fontSize": "13px"})
        raw = raw_datasets.get(tab)
        if raw is None or raw.empty or not date_str:
            return html.P("No data for this view.",
                          style={"color": "#95a5a6", "fontSize": "13px"})

        target = pd.Timestamp(date_str).date()
        result, metrics, ent, (target, prev, week) = _compare_days(
            raw, target, top=None)

        show = pd.DataFrame()
        show[ent] = result[ent]
        if "ugw" in result.columns:
            show["ugw"] = result["ugw"]
        for m in metrics:
            show[f"{m} ({target:%m-%d})"] = result[f"{m}_target"].round(2)
            show[f"{m} ({prev:%m-%d})"] = result[f"{m}_prev"].round(2)
            show[f"{m} ({week:%m-%d})"] = result[f"{m}_week_ago"].round(2)
            show[f"{m} deg vs prev"] = result[f"{m}_deg_vs_prev"].round(2)
            show[f"{m} deg vs week"] = result[f"{m}_deg_vs_week_ago"].round(2)
        show["sessions"] = result["sessions_target"]

        show = show.head(200)  # cap rendered rows; full data via CSV export
        deg_cols = [c for c in show.columns if " deg vs " in c]
        return dash_table.DataTable(
            data=show.to_dict("records"),
            columns=[{"name": c, "id": c} for c in show.columns],
            sort_action="native",
            filter_action="native",
            page_size=15,
            export_format="csv",
            export_headers="display",
            style_table={"overflowX": "auto"},
            style_header={"backgroundColor": "#2c3e50", "color": "white",
                          "fontWeight": "bold", "fontSize": "12px"},
            style_cell={"padding": "6px 10px", "fontSize": "12px",
                        "border": "1px solid #f0f0f0"},
            style_data_conditional=(
                [{"if": {"column_id": c, "filter_query": f"{{{c}}} > 10"},
                  "backgroundColor": "#fdecea", "color": "#c0392b",
                  "fontWeight": "600"} for c in deg_cols] +
                [{"if": {"column_id": c, "filter_query": f"{{{c}}} > 3"},
                  "backgroundColor": "#fef5e7", "color": "#e67e22"} for c in deg_cols]
            ),
        )

    @callback(
        Output("compare-chart",  "figure"),
        Input("family-tabs",     "value"),
        Input("compare-date",    "date"),
        Input("subnet-selector", "value"),
    )
    def update_compare_chart(tab, date_str, selected):
        """Hour-of-day overlay: picked day vs day before vs same weekday last
        week. Session-weighted across all entities, or just the entity
        selected in the main dropdown when there is one."""
        raw = raw_datasets.get(tab)
        if raw is None or raw.empty or not date_str:
            return _empty_figure("No data for this view")

        target = pd.Timestamp(date_str).date()
        prev = target - timedelta(days=1)
        week = target - timedelta(days=7)

        df = raw.copy()
        ent_col = "site" if tab == "Sites" else "ipv6_prefix_48"
        entity = None
        if selected and "|" in selected:
            _, entity = selected.split("|", 1)
            df = df[df[ent_col] == entity]

        df["hour_dt"] = pd.to_datetime(df["hour"], format="%Y/%m/%d %H:%M",
                                       errors="coerce")
        df["day"] = df["hour_dt"].dt.date
        df["hod"] = df["hour_dt"].dt.hour

        metric = "tcp_3_fr" if tab == "Sites" else "tcp_fr2"
        metric_label = "TCP FR3 (%)" if tab == "Sites" else "TCP FR2 (%)"

        fig = go.Figure()
        for day, name, color, width in (
                (week,   f"{week} (week ago)",   "#95a5a6", 1.5),
                (prev,   f"{prev} (day before)", "#3498db", 1.5),
                (target, f"{target} (picked)",   "#e74c3c", 3.0)):
            d = df[df["day"] == day].dropna(subset=[metric])
            if d.empty:
                continue
            g = (
                d.assign(_w=d[metric] * d["session_count"])
                 .groupby("hod")
                 .agg(_w=("_w", "sum"), _s=("session_count", "sum"))
            )
            g = g["_w"] / g["_s"]
            fig.add_trace(go.Scatter(
                x=g.index.tolist(), y=g.values.round(2),
                mode="lines+markers", name=name,
                line=dict(color=color, width=width),
                marker=dict(size=5 if day == target else 3),
            ))

        scope = entity if entity else "all entities (session-weighted)"
        fig.update_layout(
            template="plotly_white",
            hovermode="x unified",
            title=dict(text=f"{metric_label} by hour — {scope}",
                       font=dict(size=13)),
            xaxis=dict(title="Hour of day", dtick=2, range=[-0.5, 23.5]),
            yaxis=dict(title=metric_label),
            legend=dict(orientation="h", y=-0.25, x=0),
            margin=dict(t=40, b=40, l=50, r=30),
        )
        return fig

    return app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cell_drilldown(cells_df: pd.DataFrame, site: str, has_cell_data: bool):
    """Right-panel content for the Sites tab: per-cell FR2/FR3 table for the
    selected site, worst cells first."""
    if not has_cell_data:
        return html.P(
            "Cell drill-down not available — export cell-level data first "
            "(tools/daily_update.py site_cells job -> data/data_site_cells).",
            style={"color": "#95a5a6", "fontSize": "13px"},
        )
    c = cells_df[cells_df["site"] == site]
    if c.empty:
        return html.P("No cell data for this site.",
                      style={"color": "#95a5a6", "fontSize": "13px"})
    g = (
        c.groupby(["cell_name", "cgisai"], as_index=False)
         .agg(sessions=("session_count", "sum"),
              tcp_3_fr=("tcp_3_fr", "mean"))
         .sort_values("tcp_3_fr", ascending=False)
         .reset_index(drop=True)
    )
    g["tcp_3_fr"] = g["tcp_3_fr"].round(2)
    return dash_table.DataTable(
        data=g.to_dict("records"),
        columns=[
            {"name": "Cell",        "id": "cell_name"},
            {"name": "CGI/SAI",     "id": "cgisai"},
            {"name": "Sessions",    "id": "sessions"},
            {"name": "Avg FR3 (%)", "id": "tcp_3_fr"},
        ],
        sort_action="native",
        filter_action="native",
        page_size=15,
        export_format="csv",
        export_headers="display",
        style_table={"overflowX": "auto"},
        style_header={"backgroundColor": "#2c3e50", "color": "white",
                      "fontWeight": "bold", "fontSize": "13px"},
        style_cell={"padding": "8px 12px", "fontSize": "13px",
                    "border": "1px solid #f0f0f0"},
        style_data_conditional=[
            {"if": {"filter_query": "{tcp_3_fr} > 20"},
             "backgroundColor": "#fdecea", "color": "#c0392b"},
            {"if": {"filter_query": "{tcp_3_fr} > 10 && {tcp_3_fr} <= 20"},
             "backgroundColor": "#fef5e7", "color": "#e67e22"},
        ],
    )


def _build_subnet_options(anom: pd.DataFrame) -> list[dict]:
    if anom.empty:
        return []
    return [
        {
            "label": f"{r['prefix']}  ({r['ugw']})  — drop {r['max_sr_drop']:.1f}%",
            "value": f"{r['ugw']}|{r['prefix']}",
        }
        for _, r in anom.iterrows()
    ]


def _empty_figure(msg: str) -> go.Figure:
    fig = go.Figure()
    fig.update_layout(
        template="plotly_white",
        annotations=[dict(text=msg, showarrow=False,
                          font=dict(size=14, color="#95a5a6"),
                          xref="paper", yref="paper", x=0.5, y=0.5)],
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
    )
    return fig


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def load_and_build(args, url_base_pathname: str = "/"):
    """Everything main() used to do except argparse and app.run() — loads
    data (CSV or live-DB fallback) and returns a ready-to-serve Dash app
    plus the (host, port) config wants. Split out so a hub/landing-page
    process can import this and mount the app at a sub-path instead of
    running it standalone."""
    config = load_config()

    csv_paths = [os.path.abspath(p) for p in args.csv] if args.csv else []
    # Keep only paths that exist AND (if a folder) contain at least one .csv —
    # an empty `data/` folder shouldn't block live-DB fallback.
    import glob as _glob
    def _has_data(p):
        if not os.path.exists(p):
            return False
        if os.path.isfile(p):
            return True
        return bool(_glob.glob(os.path.join(p, "*.csv")))

    usable = [p for p in csv_paths if _has_data(p)]
    if usable:
        print(f"Loading from CSV path(s): {usable}")
        raw = load_from_csv(usable)
    else:
        if csv_paths:
            print(f"  (No CSVs found in {csv_paths} — falling back to live DB)")
        raw = load_from_db(config, args.lookback)

    print(f"Loaded {len(raw):,} rows. Calculating peer baselines ...")
    subnet_df, ip_df = prepare(raw)

    if args.ip_csv:
        print(f"Loading per-IP CSV: {args.ip_csv}")
        ip_df = load_ip_csv(args.ip_csv)
        print(f"  -> {len(ip_df):,} unique subscriber IPs")

    # Split subnets into per-family datasets (one dashboard tab each).
    # raw_datasets keeps the unprepared frames (hour + entity + KPI columns)
    # for the day-compare panel.
    datasets = {}
    raw_datasets = {}
    if "ipv6_prefix_48" in raw.columns:
        for is_v6, label in ((True, "IPv6"), (False, "IPv4")):
            mask = raw["ipv6_prefix_48"].astype(str).str.contains(":") == is_v6
            part_raw = raw[mask]
            if not part_raw.empty:
                raw_datasets[label] = part_raw
    for family, label in (("IPv6", "IPv6"), ("IPv4", "IPv4")):
        part = subnet_df[subnet_df["ip_version"] == family]
        if not part.empty:
            datasets[label] = part

    # Site-level data (optional).
    site_paths = args.site_csv
    if site_paths is None:
        default_site = os.path.abspath(os.path.join("data", "data_site"))
        site_paths = [default_site] if _has_data(default_site) else []
    if site_paths:
        usable_site = [os.path.abspath(p) for p in site_paths if _has_data(p)]
        if usable_site:
            print(f"Loading site CSV path(s): {usable_site}")
            site_raw = load_from_csv(usable_site)
            site_df = prepare_sites(site_raw)
            if not site_df.empty:
                datasets["Sites"] = site_df
                raw_datasets["Sites"] = site_raw
                print(f"  -> {len(site_df):,} site rows, "
                      f"{site_df['prefix'].nunique()} sites")

    # Cell-level drill-down data (optional, Sites tab only).
    cells_df = pd.DataFrame()
    cells_paths = args.cells_csv
    if cells_paths is None:
        default_cells = os.path.abspath(os.path.join("data", "data_site_cells"))
        cells_paths = [default_cells] if _has_data(default_cells) else []
    if cells_paths:
        usable_cells = [os.path.abspath(p) for p in cells_paths if _has_data(p)]
        if usable_cells:
            print(f"Loading cell CSV path(s): {usable_cells}")
            cells_df = load_from_csv(usable_cells)
            cells_df.columns = cells_df.columns.str.strip('"').str.lower()
            for c in ("session_count", "tcp_2_fr", "tcp_3_fr"):
                cells_df[c] = pd.to_numeric(cells_df[c], errors="coerce")
            print(f"  -> {len(cells_df):,} cell rows, "
                  f"{cells_df['cell_name'].nunique()} cells")

    if not datasets:
        raise SystemExit("No usable data after preparation "
                         "(check session-count floor and CSV formats).")

    for label, d in datasets.items():
        n_anom = len(find_anomalies(d, args.threshold))
        print(f"[{label}] {d['prefix'].nunique()} entities, "
              f"{n_anom} impacted (SR drop > {args.threshold}%)")

    viz  = config.get("visualization", {})
    host = viz.get("host", "127.0.0.1")
    port = viz.get("port", 8888)

    app = build_app(datasets, ip_df, args.threshold,
                    raw_datasets=raw_datasets, cells_df=cells_df,
                    url_base_pathname=url_base_pathname)
    return app, host, port


def main():
    parser = argparse.ArgumentParser(description="TCP KPI Anomaly Detection Dashboard")
    parser.add_argument("--csv",       type=str,   nargs="+", default=["data"],
                        help="One or more CSV files/folders. e.g. --csv data_ipv6 data_ipv4")
    parser.add_argument("--ip-csv",    type=str,
                        help="Optional per-IP CSV file or folder (drill-down panel)")
    parser.add_argument("--site-csv",  type=str,   nargs="+", default=None,
                        help="Site-level CSV file(s)/folder(s) (hour, site, "
                             "session_count, tcp_2_fr, tcp_3_fr). Default: "
                             "data/data_site if it contains CSVs.")
    parser.add_argument("--cells-csv", type=str,   nargs="+", default=None,
                        help="Cell-level CSV file(s)/folder(s) for the site "
                             "drill-down (hour, site, cell_name, cgisai, "
                             "session_count, tcp_2_fr, tcp_3_fr). Default: "
                             "data/data_site_cells if it contains CSVs.")
    parser.add_argument("--lookback",  type=int,   default=7,    help="Days of history to fetch (default: 7)")
    parser.add_argument("--threshold", type=float, default=15.0, help="SR drop threshold in %% points (default: 15)")
    args = parser.parse_args()

    app, host, port = load_and_build(args)
    print(f"\nDashboard running -> open http://localhost:{port} in your browser")
    print("Press Ctrl+C to stop.\n")
    app.run(debug=False, host=host, port=port)


if __name__ == "__main__":
    main()
