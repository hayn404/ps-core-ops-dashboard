"""
clickhouse_io.py
-----------------
Shared helper for both use cases (network_degradation, free_rg_smart_care) to
write daily-fetched DataFrames into ClickHouse instead of (or in addition to)
CSV, and to read them back for the dashboards.

Drop this file at:  ps-core-ops-dashboard/tools/clickhouse_io.py
Both usecases/*/tools/daily_update.py and usecases/*/dashboard.py can import
it with:
    sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))
    from clickhouse_io import get_client, write_dataframe, read_last_n_days

Install (offline, on the server, using the wheels you already staged):
    pip install --no-index --find-links C:\\...\\clickhouse-connect-offline \
        clickhouse_connect backports.zstd certifi lz4 tzdata urllib3
"""

from __future__ import annotations

import os
import re
import logging
from datetime import date, timedelta
from typing import Optional

import pandas as pd
import clickhouse_connect

log = logging.getLogger("clickhouse_io")

# ---------------------------------------------------------------------------
# Connection config — override via environment variables so the same code
# works unchanged on your laptop (if you ever tunnel in) and on the server.
# ---------------------------------------------------------------------------
CH_HOST = os.environ.get("CLICKHOUSE_HOST", "127.0.0.1")
CH_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))  # HTTP port
CH_USER = os.environ.get("CLICKHOUSE_USER", "default")
CH_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
CH_DATABASE = os.environ.get("CLICKHOUSE_DATABASE", "ps_core_ops")

# Retention — single knob used everywhere a table is (re)created.
RETENTION_DAYS = int(os.environ.get("CLICKHOUSE_RETENTION_DAYS", "30"))

_IDENT_RE = re.compile(r"[^0-9a-zA-Z_]")


def _safe_ident(name: str) -> str:
    """Make a column/table name safe for ClickHouse (letters/digits/_ only)."""
    name = _IDENT_RE.sub("_", str(name).strip())
    if not name or name[0].isdigit():
        name = f"c_{name}"
    return name


def get_client(database: str = CH_DATABASE):
    """Return a clickhouse_connect client, creating the database if needed.

    compress=False: clickhouse-connect defaults to LZ4 over HTTP, but
    ClickHouse 20.8's HTTP interface only understands none/gzip/br for
    that setting ("Unknown compression method lz4", code 48) — LZ4-over-
    HTTP support came in a later ClickHouse version than this project runs.
    """
    root_client = clickhouse_connect.get_client(
        host=CH_HOST, port=CH_PORT, username=CH_USER, password=CH_PASSWORD,
        compress=False,
    )
    root_client.command(f"CREATE DATABASE IF NOT EXISTS `{database}`")
    return clickhouse_connect.get_client(
        host=CH_HOST, port=CH_PORT, username=CH_USER, password=CH_PASSWORD,
        database=database, compress=False,
    )


# ---------------------------------------------------------------------------
# pandas dtype -> ClickHouse type mapping
# ---------------------------------------------------------------------------
def _ch_type_for(series: pd.Series, nullable: bool = True) -> str:
    dt = series.dtype
    if pd.api.types.is_datetime64_any_dtype(dt):
        return "DateTime"  # never nullable — used for PARTITION BY/TTL
    if pd.api.types.is_bool_dtype(dt):
        return "UInt8"
    if pd.api.types.is_integer_dtype(dt):
        return "Nullable(Int64)" if nullable else "Int64"
    if pd.api.types.is_float_dtype(dt):
        return "Nullable(Float64)" if nullable else "Float64"
    return "Nullable(String)" if nullable else "String"


def _infer_date_column(df: pd.DataFrame, hint: Optional[str]) -> str:
    """Pick the column used for PARTITION BY / ORDER BY / TTL."""
    if hint and hint in df.columns:
        return hint
    candidates = [c for c in df.columns
                  if re.search(r"date|day|ts$|timestamp", c, re.I)]
    if candidates:
        return candidates[0]
    raise ValueError(
        "Could not infer a date column for partitioning/TTL. "
        "Pass date_column=... explicitly to write_dataframe()."
    )


def ensure_table(client, table: str, df: pd.DataFrame,
                  date_column: Optional[str] = None,
                  order_by: Optional[list] = None,
                  retention_days: int = RETENTION_DAYS) -> "tuple[str, list]":
    """Create `table` if it doesn't exist, shaped after df's columns.

    Uses ReplacingMergeTree so re-running a backfill for the same day is
    idempotent (dedup happens on ORDER BY key at merge time — use FINAL or
    `argMax`-style queries downstream if you need strict per-row freshness
    before a merge has happened).

    Columns used in the ORDER BY key are created NOT NULL — ClickHouse
    (this project runs 20.8) rejects Nullable columns inside a sorting key
    with "Code: 44". Returns (date_column, order_cols) so the caller can
    null-fill those same columns before insert.
    """
    table = _safe_ident(table)
    date_column = _safe_ident(_infer_date_column(df, date_column))
    order_cols = [_safe_ident(c) for c in (order_by or [date_column])]
    order_set = set(order_cols)

    cols_sql = []
    for col in df.columns:
        safe_col = _safe_ident(col)
        is_key = safe_col in order_set
        cols_sql.append(
            f"`{safe_col}` {_ch_type_for(df[col], nullable=not is_key)}")
    cols_sql.append("_inserted_at DateTime DEFAULT now()")

    ddl = f"""
    CREATE TABLE IF NOT EXISTS `{table}` (
        {', '.join(cols_sql)}
    )
    ENGINE = ReplacingMergeTree(_inserted_at)
    PARTITION BY toYYYYMM(`{date_column}`)
    ORDER BY ({', '.join(f'`{c}`' for c in order_cols)})
    TTL `{date_column}` + INTERVAL {int(retention_days)} DAY DELETE
    SETTINGS index_granularity = 8192
    """
    client.command(ddl)
    return date_column, order_cols


def write_dataframe(df: pd.DataFrame, table: str,
                     date_column: Optional[str] = None,
                     order_by: Optional[list] = None,
                     database: str = CH_DATABASE,
                     retention_days: int = RETENTION_DAYS,
                     client=None) -> int:
    """Write a DataFrame to ClickHouse, creating/retention-configuring the
    table on first use. Safe to call once per daily_update.py run, and safe
    to call repeatedly during a --backfill loop (one call per day chunk is
    fine, or pass the whole backfilled DataFrame in one call).

    Returns number of rows written.
    """
    if df is None or df.empty:
        log.info("write_dataframe(%s): empty DataFrame, nothing to write", table)
        return 0

    own_client = client is None
    client = client or get_client(database)
    try:
        # Sanitize column names to match what ensure_table created.
        df = df.rename(columns={c: _safe_ident(c) for c in df.columns})
        date_col, order_cols = ensure_table(
            client, table, df, date_column=date_column,
            order_by=order_by, retention_days=retention_days)

        # ORDER BY columns are created NOT NULL (ClickHouse 20.8 rejects
        # Nullable columns in a sorting key) — fill any real NaNs in those
        # columns so the insert doesn't fail on a genuinely missing value.
        for col in order_cols:
            if col not in df.columns or col == date_col:
                continue
            if pd.api.types.is_numeric_dtype(df[col]):
                df[col] = df[col].fillna(0)
            else:
                df[col] = df[col].fillna("").astype(str)

        client.insert_df(_safe_ident(table), df)
        log.info("write_dataframe(%s): inserted %d rows", table, len(df))
        return len(df)
    finally:
        if own_client:
            client.close()


def read_last_n_days(table: str, days: int = 7,
                      date_column: Optional[str] = None,
                      database: str = CH_DATABASE,
                      client=None, final: bool = True) -> pd.DataFrame:
    """Read the last `days` days from a table — the ClickHouse-backed
    replacement for each dashboard.py's CSV-loading code path.

    final=True adds FINAL, which forces ClickHouse to merge-on-read and
    guarantees no duplicate rows even if a day was ever double-inserted.
    With the writer's ORDER BY key now fully identifying each real source
    row, genuine duplicates shouldn't occur in normal operation — FINAL is
    just a safety net. On very large/high-cardinality tables that safety
    net can itself exceed the server's per-query memory limit (ClickHouse
    exception code 241); when that happens this automatically retries the
    same read without FINAL rather than failing the whole dashboard load.
    """
    own_client = client is None
    client = client or get_client(database)
    try:
        if date_column is None:
            # Discover a likely date column from the table schema.
            cols = client.query(
                f"SELECT name FROM system.columns "
                f"WHERE database = '{database}' AND table = '{_safe_ident(table)}'"
            ).result_rows
            names = [c[0] for c in cols]
            date_candidates = [c for c in names if re.search(r"date|day|ts$|timestamp", c, re.I)]
            date_column = date_candidates[0] if date_candidates else names[0]
        cutoff = date.today() - timedelta(days=days)
        final_kw = " FINAL" if final else ""
        query = (
            f"SELECT * FROM `{_safe_ident(table)}`{final_kw} "
            f"WHERE `{date_column}` >= toDate('{cutoff.isoformat()}') "
            f"ORDER BY `{date_column}`"
        )
        try:
            df = client.query_df(query)
        except Exception as e:
            if final and "Memory limit" in str(e):
                log.warning(
                    "read_last_n_days(%s): FINAL exceeded the query memory "
                    "limit (%s) — retrying without FINAL. Safe as long as "
                    "no day was ever re-ingested into ClickHouse twice.",
                    table, e)
                query_no_final = query.replace(" FINAL ", " ", 1)
                df = client.query_df(query_no_final)
            else:
                raise

        # ClickHouse's DateTime type carries the server's timezone
        # implicitly (e.g. Africa/Cairo), so clickhouse-connect returns
        # tz-AWARE Timestamps for every DateTime column. Every dashboard's
        # own code (written for CSV-sourced, tz-NAIVE Timestamps) compares
        # these against naive Timestamps — e.g. `df["myday"] >= s` — which
        # raises "Cannot compare tz-naive and tz-aware datetime-like
        # objects". Strip tz info here, once, so callers see the exact
        # same naive dtype regardless of source (CSV or ClickHouse).
        for col in df.columns:
            if pd.api.types.is_datetime64tz_dtype(df[col]):
                df[col] = df[col].dt.tz_localize(None)

        return df
    finally:
        if own_client:
            client.close()


def table_exists(table: str, database: str = CH_DATABASE, client=None) -> bool:
    own_client = client is None
    client = client or get_client(database)
    try:
        res = client.query(
            f"SELECT count() FROM system.tables "
            f"WHERE database = '{database}' AND name = '{_safe_ident(table)}'"
        )
        return res.result_rows[0][0] > 0
    finally:
        if own_client:
            client.close()
