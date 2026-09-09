#!/usr/bin/env python3
"""
Free RGs Smart Care Dashboard
==============================
Analytics dashboard for free rating-group traffic and subscriber usage.

Usage:
    Live DB (Kerberos ticket required):
        python dashboard.py

    Offline from exported CSVs:
        python dashboard.py --csv data

    Custom lookback:
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

warnings.filterwarnings("ignore")

CONFIG_PATH = os.environ.get(
    "FREE_RG_CONFIG",
    os.path.join(os.path.dirname(__file__), "config", "config.yaml"))

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config() -> dict:
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)

# ---------------------------------------------------------------------------
# Database connection (mirrors Network-Service-Degradation exactly)
# ---------------------------------------------------------------------------

class _PureSASLAdapter:
    """Adapts pure-sasl's SASLClient API to the one thrift_sasl expects."""

    def __init__(self, host, service):
        from puresasl.client import SASLClient
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


def _connect_jdbc(db: dict):
    try:
        import jpype
        import jaydebeapi
    except ImportError as e:
        raise SystemExit(
            f"Missing import for JDBC mode: {e}\n"
            "Required packages: jpype1, JayDeBeApi"
        )
    import glob as _glob

    jdbc = db["jdbc"]
    jars_dir = jdbc["jars_dir"]
    jars = sorted(_glob.glob(os.path.join(jars_dir, "*.jar")))
    if not jars:
        raise SystemExit(
            f"No .jar files found in jdbc jars_dir: {jars_dir}\n"
            "Point config.yaml -> database.jdbc.jars_dir at the folder "
            "containing the Hive JDBC jars."
        )

    if not jpype.isJVMStarted():
        jvm_args = [
            f"-Djava.security.krb5.conf={jdbc['krb5_conf']}",
            f"-Djava.security.auth.login.config={jdbc['jaas_conf']}",
            "-Djavax.security.auth.useSubjectCredsOnly=false",
        ]
        jvm_path = jdbc.get("jvm_path") or jpype.getDefaultJVMPath()
        print(f" starting JVM: {jvm_path}")
        jpype.startJVM(jvm_path, *jvm_args, classpath=jars)

    url = (
        f"jdbc:hive2://{db['host']}:{int(db['port'])}"
        f"/{db.get('schema', 'default')}"
        f";principal={jdbc['principal']}"
        f";saslQop={jdbc.get('sasl_qop', 'auth')}"
    )
    print(f" JDBC URL: {url}")
    try:
        conn = jaydebeapi.connect(jdbc["driver_class"], url, [])
    except Exception as e:
        stacktrace = getattr(e, "stacktrace", None)
        if callable(stacktrace):
            print("----- Java stack trace -----")
            print(stacktrace())
            print("----------------------------")
        raise
    return conn


def connect_db(config: dict):
    db = config["database"]
    if str(db.get("mode", "sasl")).lower() == "jdbc":
        print(f"Connecting to Hive at {db['host']}:{int(db['port'])} via JDBC ...")
        conn = _connect_jdbc(db)
        print("Connected successfully.")
        return conn

    try:
        from pyhive import hive
        from thrift.transport.TSocket import TSocket
        from thrift_sasl import TSaslClientTransport
    except ImportError as e:
        raise SystemExit(
            f"Missing import for live-DB mode: {e}\n"
            "Required packages: pyhive, thrift, thrift_sasl, pure-sasl\n"
            "Or use offline mode: python dashboard.py --csv your_folder"
        )

    host = db["host"]
    port = int(db["port"])
    service = db["kerberos_service_name"]
    schema = db.get("schema", "ps")
    krb_host = db.get("kerberos_host", host)
    print(f"Connecting to Hive at {host}:{port} "
          f"(Kerberos SPN: {service}/{krb_host}) ...")

    try:
        import sasl as _csasl
        def sasl_factory():
            c = _csasl.Client()
            c.setAttr("host", krb_host)
            c.setAttr("service", service)
            c.setAttr("maxbufsize", 1_048_576)
            c.init()
            return c
        print(" using C sasl library (cyrus-sasl)")
    except ImportError:
        try:
            import winkerberos as _wk
            if not hasattr(_wk, "authGSSClientUserName"):
                _wk.authGSSClientUserName = _wk.authGSSClientUsername
            if not hasattr(_wk, "authGSSClientUsername"):
                _wk.authGSSClientUsername = _wk.authGSSClientUserName
        except (ImportError, AttributeError):
            pass
        sasl_factory = lambda: _PureSASLAdapter(krb_host, service)
        print(" using pure-sasl adapter (fallback)")

    socket = TSocket(host, port)
    socket.setTimeout(1_200_000)
    transport = TSaslClientTransport(sasl_factory, "GSSAPI", socket)
    conn = hive.connect(thrift_transport=transport, database=schema)
    print("Connected successfully.")
    return conn


def discover_tables(conn, schema: str, pattern: str) -> list[str]:
    spark_pattern = pattern.replace("%", "*")
    sql = f"SHOW TABLES IN {schema} LIKE '{spark_pattern}'"
    print(f" Discovering tables: {sql}")
    raw = pd.read_sql(sql, conn)
    candidates = ("tableName", "tab_name", "table_name", "name")
    name_col = next((c for c in candidates if c in raw.columns), None)
    if name_col is None:
        name_col = "tableName" if "tableName" in raw.columns else raw.columns[-2 if len(raw.columns) >= 3 else 0]
    names = raw[name_col].astype(str).tolist()
    names = [n for n in names if "_bak" not in n.lower()]
    fq = sorted(f"{schema}.{n}" for n in names)
    print(f" -> {len(fq)} table(s) found")
    return fq


# ---------------------------------------------------------------------------
# SQL builders
# ---------------------------------------------------------------------------

def _rg_case_sql(rg_config: dict) -> str:
    """Build the CASE statement for rating group names from config."""
    lines = []
    for rg_id, info in rg_config.items():
        lines.append(f"WHEN rating_group IN ('{rg_id}') THEN 'RG {rg_id} - {info['name']}'")
    lines.append("ELSE 'other'")
    return "CASE\n        " + "\n        ".join(lines) + "\n    END"


def _capping_case_sql(rg_config: dict) -> str:
    """Build the CASE for daily_capping_MB."""
    lines = []
    for rg_id, info in rg_config.items():
        cap = info.get("capping_mb")
        if cap is not None:
            lines.append(f"WHEN '{rg_id}' THEN {cap}")
    lines.append("ELSE NULL")
    return "CASE rg_id\n            " + "\n            ".join(lines) + "\n        END"


def daily_query(table: str, rg_config: dict, apn_filter: list[str],
                interface_id: int, start_ts: int, end_ts: int | None = None,
                top_n: int = 2000, msisdn_col: str = "MSISDN") -> str:
    """Single-scan query producing everything the dashboard needs for one table.

    One pass over the source table yields the per-user traffic base; window
    aggregates then attach the RG-level totals (traffic + unique users +
    base-wide violators) to every row before the top-N filter is applied,
    so nothing is lost:

      rg_traffic_mb   = SUM over (day, RG, APN)   == old traffic_query
      rg_unique_users = COUNT rows over (day, RG, APN), one row per IMSI
                        == old users_query's COUNT(DISTINCT IMSI)
      rg_violators    = users over their daily cap across the WHOLE base
                        (not just the exported top-N)
      rnk <= top_n rows (default 2000) per (day, RG) — capping-status charts
      use the full set; the top-users table displays rnk <= 20.
    """
    apn_clause = ""
    if apn_filter:
        apns = ", ".join(f"'{a}'" for a in apn_filter)
        apn_clause = f"apn IN ({apns}) AND"

    rg_list = ", ".join(f"'{k}'" for k in rg_config)
    end_clause = f"AND TRANS_REQ_TIME_SEC < {end_ts}" if end_ts else ""
    capping_case = _capping_case_sql(rg_config)

    return f"""
WITH user_traffic AS (
    SELECT
        FROM_UNIXTIME(TRANS_REQ_TIME_SEC, 'yyyy/MM/dd') AS myday,
        rating_group AS rg_id,
        {_rg_case_sql(rg_config)} AS rating_group_name,
        IMSI,
        MAX({msisdn_col}) AS msisdn,
        apn,
        CAST(SUM(CCR_CHARGE_TRAFFIC) AS DECIMAL(20,2)) / 1024 / 1024 AS ccr_charge_traffic_mb
    FROM {table}
    WHERE {apn_clause}
        rating_group IN ({rg_list})
        AND interfaceid IN ({interface_id})
        AND IMSI IS NOT NULL
        AND TRANS_REQ_TIME_SEC >= {start_ts}
        {end_clause}
    GROUP BY
        FROM_UNIXTIME(TRANS_REQ_TIME_SEC, 'yyyy/MM/dd'),
        rating_group,
        IMSI,
        apn
),
ranked_users AS (
    SELECT
        myday,
        rg_id,
        rating_group_name,
        IMSI,
        msisdn,
        apn,
        ccr_charge_traffic_mb,
        ROW_NUMBER() OVER (
            PARTITION BY myday, rg_id
            ORDER BY ccr_charge_traffic_mb DESC
        ) AS rnk,
        SUM(ccr_charge_traffic_mb) OVER (
            PARTITION BY myday, rg_id, apn
        ) AS rg_traffic_mb,
        COUNT(*) OVER (
            PARTITION BY myday, rg_id, apn
        ) AS rg_unique_users,
        {capping_case} AS daily_capping_mb
    FROM user_traffic
),
flagged AS (
    SELECT
        ranked_users.*,
        SUM(CASE
                WHEN daily_capping_mb IS NOT NULL
                     AND ccr_charge_traffic_mb > daily_capping_mb
                THEN 1 ELSE 0
            END) OVER (
            PARTITION BY myday, rg_id, apn
        ) AS rg_violators
    FROM ranked_users
)
SELECT
    myday,
    rating_group_name,
    rg_id,
    IMSI,
    msisdn,
    apn,
    ccr_charge_traffic_mb,
    rnk,
    rg_traffic_mb,
    rg_unique_users,
    rg_violators,
    daily_capping_mb,
    CASE
        WHEN daily_capping_mb IS NULL THEN 'no capping'
        WHEN ccr_charge_traffic_mb > daily_capping_mb THEN 'exceeded capping'
        ELSE 'within capping'
    END AS capping_status
FROM flagged
WHERE rnk <= {top_n}
ORDER BY myday, rating_group_name, ccr_charge_traffic_mb DESC
"""

def _normalize_csv(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = df.columns.str.strip('"').str.lower().str.strip()
    return df


def load_from_csv(path: str) -> pd.DataFrame:
    import glob
    p = os.path.abspath(path)
    if os.path.isdir(p):
        files = sorted(glob.glob(os.path.join(p, "*.csv")))
        if not files:
            return pd.DataFrame()
        frames = []
        for f in files:
            d = _normalize_csv(pd.read_csv(f))
            frames.append(d)
        return pd.concat(frames, ignore_index=True)
    elif os.path.isfile(p):
        return _normalize_csv(pd.read_csv(p))
    return pd.DataFrame()


def _coerce_types(df: pd.DataFrame) -> pd.DataFrame:
    for col in df.columns:
        if col in ("myday", "hour"):
            df[col] = pd.to_datetime(df[col], errors="coerce")
        elif col in ("ccr_charge_traffic_mb", "daily_capping_mb", "rg_traffic_mb",
                     "tcp_sr", "tcp_fr2"):
            df[col] = pd.to_numeric(df[col], errors="coerce")
        elif col in ("unique_users", "rg_unique_users", "rg_violators", "violators"):
            df[col] = pd.to_numeric(df[col], errors="coerce").astype("Int64")
        elif col in ("session_count", "rnk"):
            df[col] = pd.to_numeric(df[col], errors="coerce").astype("Int64")
    return df


_DEDUPE_KEYS = ["myday", "rg_id", "apn"]


def split_daily(daily_df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Split the combined daily export into the three dashboard frames.

    Every exported row carries the RG-level totals (rg_traffic_mb,
    rg_unique_users), so the traffic/users views are just the de-duplicated
    per-(day, RG, APN) totals; the full frame is the top-users view.
    """
    daily_df = _coerce_types(_normalize_csv(daily_df))
    if daily_df.empty:
        empty = pd.DataFrame()
        return empty, empty, empty

    totals = daily_df.drop_duplicates(subset=_DEDUPE_KEYS)
    traffic = totals[["myday", "rating_group_name", "rg_id", "apn",
                      "rg_traffic_mb"]].rename(
        columns={"rg_traffic_mb": "ccr_charge_traffic_mb"})
    user_cols = ["myday", "rating_group_name", "rg_id", "apn", "rg_unique_users"]
    if "rg_violators" in totals.columns:
        user_cols.append("rg_violators")
    users = totals[user_cols].rename(
        columns={"rg_unique_users": "unique_users",
                 "rg_violators": "violators"})
    top_users = daily_df.drop(columns=["rg_traffic_mb", "rg_unique_users",
                                       "rg_violators"], errors="ignore")
    return (traffic.reset_index(drop=True),
            users.reset_index(drop=True),
            top_users.reset_index(drop=True))


def _merge_frames(new: pd.DataFrame, legacy: pd.DataFrame,
                  extra_keys: list[str] | None = None) -> pd.DataFrame:
    """Combine new-format and legacy frames, preferring new on duplicates."""
    if new.empty:
        return legacy
    if legacy.empty:
        return new
    keys = _DEDUPE_KEYS + (extra_keys or [])
    keys = [k for k in keys if k in new.columns and k in legacy.columns]
    combined = pd.concat([new, legacy], ignore_index=True)
    if keys:
        combined = combined.drop_duplicates(subset=keys, keep="first")
    return combined.reset_index(drop=True)


def load_all_data(data_root: str) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Load the combined daily export, falling back to / merging legacy CSVs.

    New format:  data/free_rg_daily/*.csv     (one CSV per table, single scan)
    Legacy:      data/free_rg_traffic|users|top_users/*.csv  (3-scan exports)
    """
    daily = load_from_csv(os.path.join(data_root, "free_rg_daily"))
    if not daily.empty:
        traffic_new, users_new, top_users_new = split_daily(daily)
    else:
        traffic_new = users_new = top_users_new = pd.DataFrame()

    traffic_legacy = _coerce_types(load_from_csv(os.path.join(data_root, "free_rg_traffic")))
    users_legacy = _coerce_types(load_from_csv(os.path.join(data_root, "free_rg_users")))
    top_users_legacy = _coerce_types(load_from_csv(os.path.join(data_root, "free_rg_top_users")))

    traffic = _merge_frames(traffic_new, traffic_legacy)
    users = _merge_frames(users_new, users_legacy)
    top_users = _merge_frames(top_users_new, top_users_legacy, extra_keys=["imsi"])
    return traffic, users, top_users


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def compute_day_over_day(df: pd.DataFrame, value_col: str, group_cols: list[str],
                         date_col: str = "myday") -> pd.DataFrame:
    """Add prev_day_value, change_abs, change_pct columns."""
    df = df.copy()
    df[date_col] = pd.to_datetime(df[date_col])
    df = df.sort_values([date_col] + group_cols)
    df["prev_day_value"] = df.groupby(group_cols)[value_col].shift(1)
    df["change_abs"] = df[value_col] - df["prev_day_value"]
    df["change_pct"] = (
                        (df["change_abs"] /
                        df["prev_day_value"].replace(0, float("nan")))
                        * 100
                    ).round(2)
    return df


def pivot_for_chart(df: pd.DataFrame, date_col: str, group_col: str, value_col: str) -> pd.DataFrame:
    df = df.copy()
    df[date_col] = pd.to_datetime(df[date_col])
    pivot = df.pivot_table(index=date_col, columns=group_col, values=value_col, aggfunc="sum")
    pivot = pivot.fillna(0)
    pivot = pivot.sort_index()
    return pivot


# ---------------------------------------------------------------------------
# UI theme
# ---------------------------------------------------------------------------
C = {
    "bg": "#f4f6fa",
    "card": "#ffffff",
    "navy": "#1f2a44",
    "navy2": "#2f4b7c",
    "accent": "#2f6fed",
    "text": "#1f2a44",
    "muted": "#8a94a6",
    "border": "#e6eaf2",
    "critical": "#d64545",
    "high": "#e8912d",
    "medium": "#f2c94c",
    "ok": "#2ea44f",
    "purple": "#7c3aed",
    "teal": "#0d9488",
}

CARD_STYLE = {
    "background": C["card"], "borderRadius": "12px",
    "padding": "20px 22px",
    "boxShadow": "0 1px 3px rgba(31,42,68,0.08)"
}
SECTION_TITLE = {"margin": "0 0 4px", "fontSize": "15px",
                 "fontWeight": "700", "color": C["text"]}
SECTION_SUB = {"margin": "0 0 14px", "fontSize": "12px", "color": C["muted"]}
LABEL_STYLE = {"fontWeight": "600", "fontSize": "11px", "color": C["muted"],
               "textTransform": "uppercase", "letterSpacing": "0.4px"}

# Days exceeding the cap within the selected range before a user is flagged
REPEAT_FLAG_DAYS = 3


def _chip(text: str, color: str) -> html.Span:
    return html.Span(text, style={
        "backgroundColor": color, "color": "white", "borderRadius": "10px",
        "padding": "3px 11px", "fontSize": "10.5px", "fontWeight": "700",
        "letterSpacing": "0.5px"
    })


def _stat_card(label: str, value: str, color: str, sub: str = "") -> html.Div:
    return html.Div(
        style={**CARD_STYLE, "flex": "1", "minWidth": "150px", "padding": "16px 20px"},
        children=[
            html.Div(label, style={**LABEL_STYLE, "marginBottom": "4px"}),
            html.Div(value, style={"fontSize": "28px", "fontWeight": "800",
                                   "color": color, "lineHeight": "1.1"}),
            html.Div(sub, style={"fontSize": "11px", "color": C["muted"],
                                 "marginTop": "2px", "minHeight": "13px"}),
        ])


def _empty_figure(msg: str) -> go.Figure:
    fig = go.Figure()
    fig.update_layout(
        template="plotly_white",
        annotations=[dict(text=msg, showarrow=False,
                          font=dict(size=14, color="#95a5a6"),
                          xref="paper", yref="paper", x=0.5, y=0.5)],
        xaxis=dict(visible=False), yaxis=dict(visible=False),
    )
    return fig


def _fmt_mb(mb: float) -> str:
    """Human-readable traffic volume (input is MB)."""
    if mb is None or pd.isna(mb):
        return "—"
    if abs(mb) >= 1024 ** 2:
        return f"{mb / 1024 ** 2:,.2f} TB"
    if abs(mb) >= 1024:
        return f"{mb / 1024:,.1f} GB"
    return f"{mb:,.0f} MB"


def _graph(graph_id: str, height: int = 320) -> dcc.Loading:
    """Graph wrapped in a loading spinner."""
    return dcc.Loading(
        type="circle", color=C["accent"],
        children=dcc.Graph(id=graph_id, style={"height": f"{height}px"},
                           config={"displayModeBar": False}),
    )


TAB_STYLE = {
    "padding": "10px 18px", "fontWeight": "600", "fontSize": "13px",
    "color": C["muted"], "border": "none", "backgroundColor": "transparent",
}
TAB_SELECTED_STYLE = {
    **TAB_STYLE, "color": C["accent"],
    "borderBottom": f"3px solid {C['accent']}",
}


# ---------------------------------------------------------------------------
# Build Dash app
# ---------------------------------------------------------------------------

def build_app(traffic_df: pd.DataFrame, users_df: pd.DataFrame,
              top_users_df: pd.DataFrame, rg_config: dict,
              apn_filter: list[str], url_base_pathname: str = "/") -> Dash:

    app = Dash(__name__, suppress_callback_exceptions=True,
               url_base_pathname=url_base_pathname)

    # Coerce types
    traffic_df = _coerce_types(traffic_df)
    users_df = _coerce_types(users_df)
    top_users_df = _coerce_types(top_users_df)

    # Ensure myday is datetime
    for df in (traffic_df, users_df, top_users_df):
        if "myday" in df.columns:
            df["myday"] = pd.to_datetime(df["myday"], errors="coerce")

    # Available options
    all_rgs = sorted(traffic_df["rating_group_name"].dropna().unique()) if not traffic_df.empty else []
    all_apns = sorted(traffic_df["apn"].dropna().unique()) if not traffic_df.empty else []
    date_min = traffic_df["myday"].min() if not traffic_df.empty else pd.Timestamp.now() - timedelta(days=7)
    date_max = traffic_df["myday"].max() if not traffic_df.empty else pd.Timestamp.now()

    n_days = traffic_df["myday"].nunique() if not traffic_df.empty else 0
    data_range_txt = (
        f"Data: {date_min:%Y-%m-%d} → {date_max:%Y-%m-%d} · {n_days} days"
        if not traffic_df.empty and pd.notna(date_min) else "No data loaded"
    )

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    app.layout = html.Div(
        style={"fontFamily": "Segoe UI, Arial, sans-serif",
               "backgroundColor": C["bg"], "minHeight": "100vh",
               "paddingBottom": "40px"},
        children=[

            # ── Header ─────────────────────────────────────────────
            html.Div(
                style={"background": f"linear-gradient(135deg,{C['navy']},{C['navy2']})",
                       "color": "white", "padding": "20px 32px",
                       "display": "flex", "alignItems": "center",
                       "justifyContent": "space-between",
                       "flexWrap": "wrap", "gap": "12px"},
                children=[
                    html.Div([
                        html.H1("Free RGs Smart Care Dashboard",
                                style={"margin": 0, "fontSize": "22px", "fontWeight": "700"}),
                        html.P("Traffic & subscriber analytics for free rating groups — peer-capped usage monitoring.",
                               style={"margin": "4px 0 0", "color": "#b9c6e4", "fontSize": "12.5px"}),
                    ]),
                    html.Div([
                        html.Div(data_range_txt, style={
                            "fontSize": "11.5px", "color": "#b9c6e4",
                            "marginBottom": "6px", "textAlign": "right"}),
                        html.Button(
                            "Download Report", id="download-btn", n_clicks=0,
                            style={"background": "rgba(255,255,255,0.14)", "color": "white",
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

                    # ── Filters row ─────────────────────────────────
                    html.Div(
                        style={**CARD_STYLE, "marginBottom": "16px",
                               "display": "flex", "gap": "16px", "flexWrap": "wrap",
                               "alignItems": "flex-end"},
                        children=[
                            html.Div(style={"flex": "2", "minWidth": "220px"}, children=[
                                html.Label("Rating Groups", style=LABEL_STYLE),
                                dcc.Dropdown(
                                    id="rg-filter",
                                    options=[{"label": rg, "value": rg} for rg in all_rgs],
                                    value=all_rgs,
                                    multi=True,
                                    style={"marginTop": "4px", "fontSize": "13px"},
                                ),
                            ]),
                            html.Div(style={"flex": "2", "minWidth": "200px"}, children=[
                                html.Label("APNs", style=LABEL_STYLE),
                                dcc.Dropdown(
                                    id="apn-filter",
                                    options=[{"label": a, "value": a} for a in all_apns],
                                    value=all_apns,
                                    multi=True,
                                    placeholder="All APNs",
                                    style={"marginTop": "4px", "fontSize": "13px"},
                                ),
                            ]),
                            html.Div(style={"flex": "1", "minWidth": "160px"}, children=[
                                html.Label("Date Range (charts)", style=LABEL_STYLE),
                                dcc.DatePickerRange(
                                    id="date-range",
                                    min_date_allowed=date_min.date() if pd.notna(date_min) else None,
                                    max_date_allowed=date_max.date() if pd.notna(date_max) else None,
                                    start_date=(date_max - timedelta(days=6)).date() if pd.notna(date_max) else None,
                                    end_date=date_max.date() if pd.notna(date_max) else None,
                                    display_format="YYYY-MM-DD",
                                ),
                            ]),
                            html.Div(style={"flex": "1", "minWidth": "150px"}, children=[
                                html.Label("KPI Day", style=LABEL_STYLE),
                                dcc.DatePickerSingle(
                                    id="kpi-date",
                                    date=date_max.date() if pd.notna(date_max) else None,
                                    min_date_allowed=date_min.date() if pd.notna(date_min) else None,
                                    max_date_allowed=date_max.date() if pd.notna(date_max) else None,
                                    display_format="YYYY-MM-DD",
                                ),
                            ]),
                        ],
                    ),

                    # ── KPI Cards ───────────────────────────────────
                    html.Div(id="kpi-cards",
                             style={"display": "flex", "gap": "14px",
                                    "marginBottom": "18px", "flexWrap": "wrap"}),

                    # ── Tabs ──────────────────────────────────────
                    dcc.Tabs(
                        id="tabs", value="tab-overview",
                        style={"marginBottom": "16px"},
                        children=[

                            # ── Overview tab ──────────────────────
                            dcc.Tab(label="Overview", value="tab-overview",
                                    style=TAB_STYLE, selected_style=TAB_SELECTED_STYLE,
                                    children=[
                                        html.Div(
                                            style={"display": "flex", "gap": "16px",
                                                   "flexWrap": "wrap", "alignItems": "flex-start",
                                                   "marginTop": "16px"},
                                            children=[
                                                html.Div(
                                                    style={"flex": "1", "minWidth": "420px"},
                                                    children=[html.Div(
                                                        style=CARD_STYLE,
                                                        children=[
                                                            html.H3("Traffic per RG (GB/day)", style=SECTION_TITLE),
                                                            html.P("Daily CCR charge traffic by rating group.",
                                                                   style=SECTION_SUB),
                                                            _graph("traffic-chart"),
                                                        ])],
                                                ),
                                                html.Div(
                                                    style={"flex": "1", "minWidth": "420px"},
                                                    children=[html.Div(
                                                        style=CARD_STYLE,
                                                        children=[
                                                            html.H3("Unique Users per RG (daily)", style=SECTION_TITLE),
                                                            html.P("Daily distinct IMSI count by rating group.",
                                                                   style=SECTION_SUB),
                                                            _graph("users-chart"),
                                                        ])],
                                                ),
                                            ],
                                        ),
                                        html.Div(
                                            style={**CARD_STYLE, "marginTop": "16px"},
                                            children=[
                                                html.H3("Day-over-Day Change", style=SECTION_TITLE),
                                                html.P("Percentage change vs previous day for traffic and users.",
                                                       style=SECTION_SUB),
                                                html.Div(
                                                    style={"display": "flex", "gap": "16px",
                                                           "flexWrap": "wrap", "alignItems": "flex-start"},
                                                    children=[
                                                        html.Div(style={"flex": "1", "minWidth": "420px"},
                                                                 children=[_graph("traffic-dod-chart", 300)]),
                                                        html.Div(style={"flex": "1", "minWidth": "420px"},
                                                                 children=[_graph("users-dod-chart", 300)]),
                                                    ],
                                                ),
                                            ],
                                        ),
                                        html.Div(
                                            style={**CARD_STYLE, "marginTop": "16px"},
                                            children=[
                                                html.H3("Traffic Share by RG", style=SECTION_TITLE),
                                                html.P("Share of total traffic in the selected range.",
                                                       style=SECTION_SUB),
                                                _graph("traffic-pie", 300),
                                            ],
                                        ),
                                    ]),

                            # ── Capping & Top Users tab ───────────
                            dcc.Tab(label="Capping & Top Users", value="tab-capping",
                                    style=TAB_STYLE, selected_style=TAB_SELECTED_STYLE,
                                    children=[
                                        html.Div(
                                            style={"display": "flex", "gap": "16px",
                                                   "flexWrap": "wrap", "alignItems": "flex-start",
                                                   "marginTop": "16px"},
                                            children=[
                                                html.Div(
                                                    style={"flex": "1", "minWidth": "320px"},
                                                    children=[html.Div(
                                                        style=CARD_STYLE,
                                                        children=[
                                                            html.H3("Capping Status (Top 2000 Users)", style=SECTION_TITLE),
                                                            _graph("capping-pie", 300),
                                                        ])],
                                                ),
                                                html.Div(
                                                    style={"flex": "1", "minWidth": "320px"},
                                                    children=[html.Div(
                                                        style=CARD_STYLE,
                                                        children=[
                                                            html.H3("Capping Violations by RG", style=SECTION_TITLE),
                                                            _graph("violations-bar", 300),
                                                        ])],
                                                ),
                                            ],
                                        ),
                                        html.Div(
                                            style={**CARD_STYLE, "marginTop": "16px"},
                                            children=[
                                                html.H3("Repeat Offenders — Exceeding on Multiple Days",
                                                        style=SECTION_TITLE),
                                                html.P(f"Users exceeding their daily cap on ≥{REPEAT_FLAG_DAYS} "
                                                       "distinct days within the selected range are flagged.",
                                                       style=SECTION_SUB),
                                                html.Div(id="repeat-table"),
                                            ],
                                        ),
                                        html.Div(
                                            style={**CARD_STYLE, "marginTop": "16px"},
                                            children=[
                                                html.H3("Top Users (with Capping Status)", style=SECTION_TITLE),
                                                html.P("Top 20 users per RG per day. Capping charts above cover the top 2000.",
                                                       style=SECTION_SUB),
                                                html.Div(id="top-users-table"),
                                            ],
                                        ),
                                    ]),

                            # ── Daily Summary tab ─────────────────
                            dcc.Tab(label="Daily Summary", value="tab-summary",
                                    style=TAB_STYLE, selected_style=TAB_SELECTED_STYLE,
                                    children=[
                                        html.Div(
                                            style={**CARD_STYLE, "marginTop": "16px"},
                                            children=[
                                                html.H3("Daily Summary", style=SECTION_TITLE),
                                                html.P("Per-day totals with change vs previous day.",
                                                       style=SECTION_SUB),
                                                html.Div(id="summary-table"),
                                            ],
                                        ),
                                    ]),

                            # ── Compare Days tab ──────────────────
                            dcc.Tab(label="Compare Days", value="tab-compare",
                                    style=TAB_STYLE, selected_style=TAB_SELECTED_STYLE,
                                    children=[
                                        html.Div(
                                            style={**CARD_STYLE, "marginTop": "16px"},
                                            children=[
                                                html.H3("Compare Days", style=SECTION_TITLE),
                                                html.P("Per-RG traffic for the picked day vs the previous day "
                                                       "and the same weekday last week.",
                                                       style=SECTION_SUB),
                                                html.Div(
                                                    style={"maxWidth": "240px", "marginBottom": "10px"},
                                                    children=[
                                                        dcc.DatePickerSingle(
                                                            id="compare-date",
                                                            date=(date_max - timedelta(days=1)).date() if pd.notna(date_max) else None,
                                                            display_format="YYYY-MM-DD",
                                                            min_date_allowed=date_min.date() if pd.notna(date_min) else None,
                                                            max_date_allowed=date_max.date() if pd.notna(date_max) else None,
                                                        ),
                                                    ],
                                                ),
                                                _graph("compare-chart"),
                                            ],
                                        ),
                                    ]),
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
        Output("kpi-cards", "children"),
        Output("traffic-chart", "figure"),
        Output("users-chart", "figure"),
        Output("traffic-dod-chart", "figure"),
        Output("users-dod-chart", "figure"),
        Output("traffic-pie", "figure"),
        Output("capping-pie", "figure"),
        Output("violations-bar", "figure"),
        Output("summary-table", "children"),
        Output("top-users-table", "children"),
        Output("repeat-table", "children"),
        Input("rg-filter", "value"),
        Input("apn-filter", "value"),
        Input("date-range", "start_date"),
        Input("date-range", "end_date"),
        Input("kpi-date", "date"),
    )
    def update_dashboard(selected_rgs, selected_apns, start_date, end_date, kpi_date):
        # Filter traffic
        t = traffic_df.copy()
        u = users_df.copy()
        tu = top_users_df.copy()

        if selected_rgs:
            t = t[t["rating_group_name"].isin(selected_rgs)]
            u = u[u["rating_group_name"].isin(selected_rgs)]
            tu = tu[tu["rating_group_name"].isin(selected_rgs)]
        if selected_apns:
            t = t[t["apn"].isin(selected_apns)]
            u = u[u["apn"].isin(selected_apns)]
            tu = tu[tu["apn"].isin(selected_apns)]
        if start_date and end_date:
            s = pd.Timestamp(start_date)
            e = pd.Timestamp(end_date) + timedelta(days=1)
            t = t[(t["myday"] >= s) & (t["myday"] < e)]
            u = u[(u["myday"] >= s) & (u["myday"] < e)]
            tu = tu[(tu["myday"] >= s) & (tu["myday"] < e)]

        # ── KPIs (single selected day; charts/tables use the range) ──
        if kpi_date:
            kd = pd.Timestamp(kpi_date)
            kt = t[t["myday"] == kd]
            ku = u[u["myday"] == kd]
            ktu = tu[tu["myday"] == kd]
        else:
            kt, ku, ktu = t, u, tu
        day_txt = pd.Timestamp(kpi_date).strftime("%Y-%m-%d") if kpi_date else "all days"

        total_traffic = kt["ccr_charge_traffic_mb"].sum() if not kt.empty else 0
        total_users = int(ku["unique_users"].sum()) if not ku.empty else 0
        n_rgs = kt["rating_group_name"].nunique() if not kt.empty else 0

        # Base-wide violators come from the export's rg_violators window total
        # (whole user base). Legacy CSVs lack it -> fall back to top-N rows.
        if not ku.empty and "violators" in ku.columns and ku["violators"].notna().any():
            base_viol = int(ku["violators"].fillna(0).sum())
            base_pct = round(base_viol / total_users * 100, 3) if total_users else 0
            viol_value, viol_sub = (f"{base_viol:,}",
                                    f"{base_pct}% of the user base · {day_txt}")
        else:
            row_viol = 0
            if not ktu.empty and "capping_status" in ktu.columns:
                row_viol = int((ktu["capping_status"] == "exceeded capping").sum())
            row_pct = round(row_viol / len(ktu) * 100, 1) if not ktu.empty else 0
            viol_value, viol_sub = (str(row_viol),
                                    f"{row_pct}% of exported top users (legacy data)")
        top_rg, top_rg_share = "—", 0
        if not kt.empty and total_traffic > 0:
            by_rg = kt.groupby("rating_group_name")["ccr_charge_traffic_mb"].sum()
            top_rg = by_rg.idxmax().split(" - ", 1)[-1]
            top_rg_share = round(by_rg.max() / total_traffic * 100, 1)

        cards = [
            _stat_card("Total Traffic", _fmt_mb(total_traffic), C["accent"],
                       f"on {day_txt}"),
            _stat_card("Unique Users", f"{total_users:,}", C["teal"],
                       f"on {day_txt} · {n_rgs} RGs"),
            _stat_card("Capping Violations", viol_value, C["critical"], viol_sub),
            _stat_card("Busiest RG", top_rg, C["purple"],
                       f"{top_rg_share}% of the day's traffic"),
        ]

        # ── Traffic chart ──────────────────────────────────────
        if t.empty:
            fig_traffic = _empty_figure("No traffic data for selected filters")
        else:
            pivot_t = pivot_for_chart(t, "myday", "rating_group_name", "ccr_charge_traffic_mb") / 1024
            fig_traffic = go.Figure()
            for col in pivot_t.columns:
                fig_traffic.add_trace(go.Scatter(
                    x=pivot_t.index, y=pivot_t[col].round(2),
                    mode="lines+markers", name=col,
                    stackgroup="one",
                ))
            fig_traffic.update_layout(
                template="plotly_white", hovermode="x unified",
                legend=dict(orientation="h", y=-0.25, x=0),
                xaxis_title="Day", yaxis_title="Traffic (GB)",
                margin=dict(t=10, b=40, l=50, r=30),
            )

        # ── Users chart ────────────────────────────────────────
        if u.empty:
            fig_users = _empty_figure("No user data for selected filters")
        else:
            pivot_u = pivot_for_chart(u, "myday", "rating_group_name", "unique_users")
            fig_users = go.Figure()
            for col in pivot_u.columns:
                fig_users.add_trace(go.Scatter(
                    x=pivot_u.index, y=pivot_u[col],
                    mode="lines+markers", name=col,
                    stackgroup="one",
                ))
            fig_users.update_layout(
                template="plotly_white", hovermode="x unified",
                legend=dict(orientation="h", y=-0.25, x=0),
                xaxis_title="Day", yaxis_title="Unique Users",
                margin=dict(t=10, b=40, l=50, r=30),
            )

        # ── DoD Traffic ────────────────────────────────────────
        if t.empty or len(t) < 2:
            fig_traffic_dod = _empty_figure("Need at least 2 days of data")
        else:
            t_dod = compute_day_over_day(t, "ccr_charge_traffic_mb", ["rating_group_name"])
            t_dod = t_dod.dropna(subset=["change_pct"])
            pivot_td = t_dod.pivot_table(index="myday", columns="rating_group_name",
                                          values="change_pct", aggfunc="mean")
            fig_traffic_dod = go.Figure()
            for col in pivot_td.columns:
                fig_traffic_dod.add_trace(go.Bar(
                    x=pivot_td.index, y=pivot_td[col].round(2), name=col,
                ))
            fig_traffic_dod.update_layout(
                template="plotly_white", hovermode="x unified",
                legend=dict(orientation="h", y=-0.25, x=0),
                xaxis_title="Day", yaxis_title="Change % vs Prev Day",
                barmode="group",
                margin=dict(t=10, b=40, l=50, r=30),
            )

        # ── DoD Users ──────────────────────────────────────────
        if u.empty or len(u) < 2:
            fig_users_dod = _empty_figure("Need at least 2 days of data")
        else:
            u_dod = compute_day_over_day(u, "unique_users", ["rating_group_name"])
            u_dod = u_dod.dropna(subset=["change_pct"])
            pivot_ud = u_dod.pivot_table(index="myday", columns="rating_group_name",
                                          values="change_pct", aggfunc="mean")
            fig_users_dod = go.Figure()
            for col in pivot_ud.columns:
                fig_users_dod.add_trace(go.Bar(
                    x=pivot_ud.index, y=pivot_ud[col].round(2), name=col,
                ))
            fig_users_dod.update_layout(
                template="plotly_white", hovermode="x unified",
                legend=dict(orientation="h", y=-0.25, x=0),
                xaxis_title="Day", yaxis_title="Change % vs Prev Day",
                barmode="group",
                margin=dict(t=10, b=40, l=50, r=30),
            )

        # ── Traffic Pie ────────────────────────────────────────
        if t.empty:
            fig_pie = _empty_figure("No data")
        else:
            pie_data = t.groupby("rating_group_name")["ccr_charge_traffic_mb"].sum().reset_index()
            fig_pie = go.Figure(go.Pie(
                labels=pie_data["rating_group_name"],
                values=(pie_data["ccr_charge_traffic_mb"] / 1024).round(2),
                hole=0.45,
                textinfo="label+percent",
                hovertemplate="%{label}<br>%{value:,.1f} GB (%{percent})<extra></extra>",
                insidetextorientation="horizontal",
            ))
            fig_pie.update_layout(
                template="plotly_white", showlegend=False,
                margin=dict(t=10, b=10, l=10, r=10),
            )

        # ── Capping Pie ────────────────────────────────────────
        if tu.empty or "capping_status" not in tu.columns:
            fig_cap = _empty_figure("No capping data")
        else:
            cap_counts = tu["capping_status"].value_counts().reset_index()
            cap_counts.columns = ["status", "count"]
            colors_map = {"exceeded capping": C["critical"],
                          "within capping": C["ok"],
                          "no capping": C["muted"]}
            fig_cap = go.Figure(go.Pie(
                labels=cap_counts["status"],
                values=cap_counts["count"],
                hole=0.45,
                marker_colors=[colors_map.get(s, C["accent"]) for s in cap_counts["status"]],
                textinfo="label+percent",
            ))
            fig_cap.update_layout(
                template="plotly_white", showlegend=False,
                margin=dict(t=10, b=10, l=10, r=10),
            )

        # ── Violations Bar ─────────────────────────────────────
        if tu.empty or "capping_status" not in tu.columns:
            fig_viol = _empty_figure("No capping data")
        else:
            viol = tu[tu["capping_status"] == "exceeded capping"]
            if viol.empty:
                fig_viol = _empty_figure("No violations in selected range")
            else:
                viol_counts = viol.groupby("rating_group_name").size().reset_index(name="violations")
                viol_counts = viol_counts.sort_values("violations", ascending=True)
                fig_viol = go.Figure(go.Bar(
                    x=viol_counts["violations"],
                    y=viol_counts["rating_group_name"],
                    orientation="h",
                    marker_color=C["critical"],
                ))
                fig_viol.update_layout(
                    template="plotly_white",
                    xaxis_title="Violation Count",
                    yaxis_title="",
                    margin=dict(t=10, b=10, l=150, r=30),
                )

        # ── Summary Table ────────────────────────────────────
        if t.empty or u.empty:
            summary = html.P("No data for selected filters.", style={"color": C["muted"], "fontSize": "13px"})
        else:
            t_sum = t.groupby("myday").agg({"ccr_charge_traffic_mb": "sum"}).reset_index()
            u_sum = u.groupby("myday").agg({"unique_users": "sum"}).reset_index()
            merged = t_sum.merge(u_sum, on="myday", how="outer")
            merged = merged.sort_values("myday", ascending=False)
            merged["myday_str"] = merged["myday"].dt.strftime("%Y-%m-%d")
            # compute DoD on the merged summary
            merged = merged.sort_values("myday")
            merged["traffic_prev"] = merged["ccr_charge_traffic_mb"].shift(1)
            merged["users_prev"] = merged["unique_users"].shift(1)
            merged["traffic_chg"] = ((merged["ccr_charge_traffic_mb"] - merged["traffic_prev"])
                                      / merged["traffic_prev"].replace(0, pd.NA) * 100).round(1)
            merged["users_chg"] = ((merged["unique_users"] - merged["users_prev"])
                                    / merged["users_prev"].replace(0, pd.NA) * 100).round(1)
            merged = merged.sort_values("myday", ascending=False)

            display = merged[["myday_str", "ccr_charge_traffic_mb", "traffic_chg",
                              "unique_users", "users_chg"]].copy()
            display["ccr_charge_traffic_mb"] = (display["ccr_charge_traffic_mb"] / 1024).round(2)
            display.columns = ["Day", "Traffic (GB)", "Traffic Δ%",
                               "Unique Users", "Users Δ%"]

            summary = dash_table.DataTable(
                data=display.to_dict("records"),
                columns=[{"name": c, "id": c} for c in display.columns],
                sort_action="native",
                page_size=10,
                style_table={"overflowX": "auto"},
                style_header={"backgroundColor": "#2c3e50", "color": "white",
                              "fontWeight": "bold", "fontSize": "13px"},
                style_cell={"padding": "8px 12px", "fontSize": "13px",
                            "border": "1px solid #f0f0f0"},
                style_data_conditional=[
                    {"if": {"column_id": "Traffic Δ%", "filter_query": "{Traffic Δ%} > 20"},
                     "backgroundColor": "#fdecea", "color": "#c0392b", "fontWeight": "600"},
                    {"if": {"column_id": "Traffic Δ%", "filter_query": "{Traffic Δ%} < -20"},
                     "backgroundColor": "#e8f5e9", "color": "#2e7d32", "fontWeight": "600"},
                    {"if": {"column_id": "Users Δ%", "filter_query": "{Users Δ%} > 20"},
                     "backgroundColor": "#fdecea", "color": "#c0392b", "fontWeight": "600"},
                    {"if": {"column_id": "Users Δ%", "filter_query": "{Users Δ%} < -20"},
                     "backgroundColor": "#e8f5e9", "color": "#2e7d32", "fontWeight": "600"},
                ],
            )

        # ── Top Users Table ────────────────────────────────────
        if tu.empty:
            top_table = html.P("No top-user data for selected filters.",
                               style={"color": C["muted"], "fontSize": "13px"})
        else:
            display_tu = tu.copy()
            # Table shows the top 20 per RG/day; charts use the full exported set
            if "rnk" in display_tu.columns:
                display_tu = display_tu[display_tu["rnk"] <= 20]
            display_tu["myday_str"] = display_tu["myday"].dt.strftime("%Y-%m-%d")
            display_tu = display_tu.sort_values(["myday", "rating_group_name", "ccr_charge_traffic_mb"],
                                                  ascending=[False, True, False])
            display_tu["ccr_charge_traffic_mb"] = display_tu["ccr_charge_traffic_mb"].round(1)
            cols = ["myday_str", "rating_group_name", "imsi", "msisdn", "apn",
                    "ccr_charge_traffic_mb", "daily_capping_mb", "capping_status"]
            display_tu = display_tu[[c for c in cols if c in display_tu.columns]]
            display_tu.columns = [c.replace("_", " ").title() for c in display_tu.columns]

            top_table = dash_table.DataTable(
                data=display_tu.head(200).to_dict("records"),
                columns=[{"name": c, "id": c} for c in display_tu.columns],
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
                            {
                                "if": {
                                    "column_id": "Capping Status",
                                    "filter_query": '{Capping Status} = "exceeded capping"'
                                },
                                "backgroundColor": "#fdecea",
                                "color": "#c0392b",
                                "fontWeight": "600",
                            },
                        ]
            )

        # ── Repeat Offenders Table ─────────────────────────────
        viol_rows = (tu[tu["capping_status"] == "exceeded capping"]
                     if not tu.empty and "capping_status" in tu.columns
                     else pd.DataFrame())
        if viol_rows.empty:
            repeat_table = html.P("No capping violations in the selected range.",
                                  style={"color": C["muted"], "fontSize": "13px"})
        else:
            group_keys = ["imsi"] + (["msisdn"] if "msisdn" in viol_rows.columns else [])
            ro = viol_rows.groupby(group_keys).agg(
                days_exceeded=("myday", "nunique"),
                rgs=("rating_group_name", lambda s: ", ".join(sorted(s.unique()))),
                max_daily_mb=("ccr_charge_traffic_mb", "max"),
                total_mb=("ccr_charge_traffic_mb", "sum"),
            ).reset_index()
            ro["flag"] = pd.Series("", index=ro.index, dtype=object)
            ro.loc[ro["days_exceeded"] >= REPEAT_FLAG_DAYS, "flag"] = "REPEAT OFFENDER"
            ro = ro.sort_values(["days_exceeded", "max_daily_mb"],
                                ascending=[False, False])
            ro["max_daily_mb"] = (ro["max_daily_mb"] / 1024).round(2)
            ro["total_mb"] = (ro["total_mb"] / 1024).round(2)
            ro = ro.rename(columns={
                "imsi": "IMSI", "msisdn": "MSISDN",
                "days_exceeded": "Days Exceeded", "rgs": "Rating Groups",
                "max_daily_mb": "Max Daily (GB)", "total_mb": "Total (GB)",
                "flag": "Flag",
            })

            repeat_table = dash_table.DataTable(
                data=ro.head(200).to_dict("records"),
                columns=[{"name": c, "id": c} for c in ro.columns],
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
                    {"if": {"filter_query": '{Flag} = "REPEAT OFFENDER"'},
                     "backgroundColor": "#fdecea", "color": "#c0392b",
                     "fontWeight": "600"},
                ],
            )

        return (cards, fig_traffic, fig_users, fig_traffic_dod, fig_users_dod,
                fig_pie, fig_cap, fig_viol, summary, top_table, repeat_table)

    @callback(
        Output("compare-chart", "figure"),
        Input("compare-date", "date"),
        Input("rg-filter", "value"),
        Input("apn-filter", "value"),
    )
    def update_compare(date_str, selected_rgs, selected_apns):
        if not date_str:
            return _empty_figure("Pick a day to compare")

        target = pd.Timestamp(date_str).date()
        prev = target - timedelta(days=1)
        week = target - timedelta(days=7)

        t = traffic_df.copy()
        if selected_rgs:
            t = t[t["rating_group_name"].isin(selected_rgs)]
        if selected_apns:
            t = t[t["apn"].isin(selected_apns)]

        if t.empty or "myday" not in t.columns:
            return _empty_figure("No data for comparison")

        t["day"] = t["myday"].dt.date

        fig = go.Figure()
        colors = {"week": "#95a5a6", "prev": "#3498db", "target": "#e74c3c"}

        for day, label, key in ((week, f"{week} (week ago)", "week"),
                                  (prev, f"{prev} (day before)", "prev"),
                                  (target, f"{target} (picked)", "target")):
            d = t[t["day"] == day]
            if d.empty:
                continue
            # Data is daily-grained, so compare per-RG totals for each day
            g = d.groupby("rating_group_name")["ccr_charge_traffic_mb"].sum().reset_index()
            fig.add_trace(go.Bar(
                x=g["rating_group_name"], y=(g["ccr_charge_traffic_mb"] / 1024).round(2),
                name=label,
                marker_color=colors[key],
                opacity=0.85 if key == "target" else 0.6,
            ))

        fig.update_layout(
            template="plotly_white",
            hovermode="x unified",
            xaxis_title="Rating Group",
            yaxis_title="Traffic (GB)",
            legend=dict(orientation="h", y=-0.25, x=0),
            margin=dict(t=20, b=40, l=50, r=30),
            barmode="group",
        )
        return fig

    @callback(
        Output("download-report", "data"),
        Input("download-btn", "n_clicks"),
        State("rg-filter", "value"),
        State("apn-filter", "value"),
        State("date-range", "start_date"),
        State("date-range", "end_date"),
        prevent_initial_call=True,
    )
    def export_report(n_clicks, selected_rgs, selected_apns, start_date, end_date):
        ts = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
        filename = f"free_rg_report_{ts}.xlsx"

        def _write(buf):
            from report import build_report_workbook
            build_report_workbook(
                buf, traffic_df, users_df, top_users_df,
                selected_rgs=selected_rgs, selected_apns=selected_apns,
                start_date=start_date, end_date=end_date)

        return dcc.send_bytes(_write, filename)

    return app


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
    rg_config = config.get("free_rating_groups", {})
    apn_raw = config.get("apn_filter", "")
    apn_filter = [a.strip() for a in apn_raw.split(",") if a.strip()] if apn_raw else []
    msisdn_col = config.get("msisdn_column", "MSISDN")

    data_root = os.path.abspath(args.csv)

    import glob as _glob
    def _has_data(p):
        if not os.path.exists(p):
            return False
        if os.path.isfile(p):
            return True
        return bool(_glob.glob(os.path.join(p, "*.csv")))

    has_csv = any(_has_data(os.path.join(data_root, d)) for d in
                  ("free_rg_daily", "free_rg_traffic",
                   "free_rg_users", "free_rg_top_users"))

    if has_csv:
        print(f"Loading from CSV folders under: {data_root}")
        traffic_df, users_df, top_users_df = load_all_data(data_root)
    else:
        print(f"No CSVs found under {data_root} — falling back to live DB")
        # Live DB loading: discover tables, one scan per table for lookback period
        conn = connect_db(config)
        schema = config["database"].get("schema", "ps")
        pattern = config.get("table_pattern", "DETAIL_CDR_SGIDIAMETER_%")
        interface_id = config.get("interface_id", 12)
        tables = discover_tables(conn, schema, pattern)
        if not tables:
            conn.close()
            raise SystemExit("No tables discovered.")

        cutoff = int((datetime.utcnow() - timedelta(days=args.lookback)).timestamp())
        keep = args.lookback + 2
        if len(tables) > keep:
            print(f" Trimming {len(tables)} tables to most-recent {keep}")
            tables = tables[-keep:]

        frames = []
        for table in tables:
            print(f" Querying {table} ...")
            try:
                dq = daily_query(table, rg_config, apn_filter, interface_id,
                                 cutoff, msisdn_col=msisdn_col)
                d = pd.read_sql(dq, conn)
                d.columns = [c.split(".")[-1] for c in d.columns]
                frames.append(d)
                print(f" -> {len(d):,} rows")
            except Exception as e:
                print(f" ! Skipped {table}: {e}")
        conn.close()

        daily_df = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
        traffic_df, users_df, top_users_df = split_daily(daily_df)

    print(f"Loaded traffic={len(traffic_df):,} users={len(users_df):,} top_users={len(top_users_df):,}")

    viz = config.get("visualization", {})
    host = viz.get("host", "127.0.0.1")
    port = viz.get("port", 8889)

    app = build_app(traffic_df, users_df, top_users_df, rg_config, apn_filter,
                    url_base_pathname=url_base_pathname)
    return app, host, port


def main():
    parser = argparse.ArgumentParser(description="Free RGs Smart Care Dashboard")
    parser.add_argument("--csv", type=str, default="data",
                        help="Root data folder containing free_rg_traffic/, free_rg_users/, free_rg_top_users/")
    parser.add_argument("--lookback", type=int, default=7,
                        help="Days of history to fetch from live DB (default: 7)")
    args = parser.parse_args()

    app, host, port = load_and_build(args)
    print(f"\nDashboard running -> open http://localhost:{port} in your browser")
    print("Press Ctrl+C to stop.\n")
    app.run(debug=False, host=host, port=port)


if __name__ == "__main__":
    main()
