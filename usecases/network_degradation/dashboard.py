"""
Network Degradation Monitor - dashboard
========================================
Reads ONLY ready-made tables from ClickHouse (built by etl.py) - it never
touches Hive, CSV files or raw data:

    IPv6 / IPv4 tabs : nd_subnet_hourly   (subnets, peer baselines already computed)
    Pools tab        : nd_pool_hourly     (per IP pool, from config/ip_pools.csv)
    Sites tab        : nd_site_hourly + nd_site_baseline
    Site drill-down  : nd_cell_daily      (queried on demand, per site)

Run standalone:   python3.9 dashboard.py          (normally started by ../../hub.py)
Data is refreshed by:   python3.9 etl.py daily
"""

from __future__ import annotations

import argparse
import os
import sys as _sys
import warnings
from datetime import timedelta

import pandas as pd
import plotly.graph_objects as go
import yaml
from dash import Dash, Input, Output, State, ctx, dash_table, dcc, html, no_update
from dash import ALL

warnings.filterwarnings("ignore")

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config", "config.yaml")

# Shared ClickHouse client lives in <repo>/tools/clickhouse_io.py
_TOP_TOOLS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "tools")
if _TOP_TOOLS not in _sys.path:
    _sys.path.insert(0, _TOP_TOOLS)
from clickhouse_io import get_client as _ch_client  # noqa: E402

MIN_LOOKBACK_DAYS = 10      # the day-compare panel needs "same weekday last week"
MIN_POOL_SESSIONS = 50_000  # keep in sync with etl.py (pools below this are noise)


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# Data access - plain SELECTs on the tables etl.py maintains
# ---------------------------------------------------------------------------
def _ch_df(sql: str) -> pd.DataFrame:
    client = _ch_client()
    try:
        df = client.query_df(sql)
    finally:
        client.close()
    for col in df.columns:  # ClickHouse DateTime comes back tz-aware; the UI is tz-naive
        if isinstance(df[col].dtype, pd.DatetimeTZDtype):
            df[col] = df[col].dt.tz_localize(None)
    return df


def _num(df: pd.DataFrame, cols) -> pd.DataFrame:
    for c in cols:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    return df


_KPI = ["session_count", "tcp_sr", "tcp_fr2", "baseline_sr", "baseline_fr2", "sr_drop", "fr2_rise"]


def load_subnets(days: int) -> pd.DataFrame:
    df = _ch_df(f"""
        SELECT hour AS hour_dt, ugw, ip_version, prefix,
               toInt64(session_count) AS session_count,
               tcp_sr, tcp_fr2, baseline_sr, baseline_fr2, sr_drop, fr2_rise
        FROM nd_subnet_hourly
        WHERE report_date >= today() - {int(days)}
        ORDER BY ugw, ip_version, prefix, hour""")
    if df.empty:   # e.g. etl.py hasn't loaded/rebuilt this lookback window yet
        return df
    return _num(df, _KPI)


def load_pools(days: int, ugw_labels) -> pd.DataFrame:
    """One row per (pool, hour). Locked redundancy twins are hidden (they
    carry the same traffic as their primary pool) and so are tiny pools."""
    df = _ch_df(f"""
        SELECT hour AS hour_dt, gw, pool_name AS prefix,
               toInt64(session_count) AS session_count,
               tcp_sr, tcp_fr2, baseline_sr, baseline_fr2, sr_drop, fr2_rise
        FROM nd_pool_hourly
        WHERE report_date >= today() - {int(days)}
          AND locked = 0 AND session_count >= {MIN_POOL_SESSIONS}
        ORDER BY gw, pool_name, hour""")
    if df.empty:
        return df
    label = {u.rsplit("_", 1)[-1]: u for u in ugw_labels}   # 'PDG25' -> 'RamsisPost_PDG25'
    df["ugw"] = df["gw"].map(label).fillna(df["gw"])
    df["ip_version"] = "Pool"
    return _num(df, _KPI)


def load_sites(days: int) -> pd.DataFrame:
    """Sites: FR3 is shown as 'SR' = 100 - FR3, against the site's OWN normal."""
    df = _ch_df(f"""
        SELECT hour AS hour_dt, ugw, site AS prefix,
               toInt64(session_count) AS session_count,
               tcp_2_fr, tcp_3_fr, baseline_sr, baseline_fr2
        FROM nd_site_hourly
        ANY LEFT JOIN nd_site_baseline USING (site)
        WHERE report_date >= today() - {int(days)}
        ORDER BY ugw, site, hour""")
    if df.empty:
        return df
    df = _num(df, ["session_count", "tcp_2_fr", "tcp_3_fr", "baseline_sr", "baseline_fr2"])
    df["tcp_sr"] = 100.0 - df["tcp_3_fr"]
    df["tcp_fr2"] = df["tcp_3_fr"]
    df["ip_version"] = "Site"
    df["sr_drop"] = (df["baseline_sr"] - df["tcp_sr"]).round(2)
    df["fr2_rise"] = (df["tcp_fr2"] - df["baseline_fr2"]).round(2)
    return df


# (gateway, subnet) -> pool_id, e.g. ("Telemisr_YDG30", "10.207.150") -> "YDG30:ydg30_etisalat"
_SUBNET_POOL: dict = {}


def load_subnet_pool() -> dict:
    """Which IP pool each subnet belongs to (built by etl.py: nd_subnet_pool)."""
    try:
        df = _ch_df("SELECT ugw, prefix, pool_id FROM nd_subnet_pool")
    except Exception:
        return {}
    return {(u, p): pid for u, p, pid in zip(df["ugw"], df["prefix"], df["pool_id"])}


def _attach_pool(anom: pd.DataFrame, tab: str) -> pd.DataFrame:
    """Add a `pool` column to an anomaly table (subnet tabs only)."""
    if anom.empty or tab not in ("IPv6", "IPv4") or not _SUBNET_POOL:
        return anom
    out = anom.copy()
    out["pool"] = [_SUBNET_POOL.get((u, p), "-") for u, p in zip(out["ugw"], out["prefix"])]
    return out


def _compare_frame(df: pd.DataFrame, entity: str = "prefix") -> pd.DataFrame:
    """Slim frame for the day-compare panel (hour + entity + KPIs)."""
    cols = ["hour_dt", "ugw", "prefix", "tcp_sr", "tcp_fr2", "session_count"]
    out = df[cols].rename(columns={"hour_dt": "hour"})
    return out


def _esc(s: str) -> str:
    return str(s).replace("\\", "\\\\").replace("'", "\\'")


def cells_available() -> bool:
    try:
        return int(_ch_df("SELECT count() AS n FROM nd_cell_daily")["n"].iloc[0]) > 0
    except Exception:
        return False


def _cell_rows(site: str) -> pd.DataFrame:
    """Per-cell FR3 for one site - a tiny indexed query, run on click."""
    return _ch_df(f"""
        SELECT cell_name, cgisai, sum(session_count) AS sessions,
               if(sum(fr3_n) > 0, sum(fr3_sum) / sum(fr3_n), NULL) AS tcp_3_fr
        FROM nd_cell_daily
        WHERE site = '{_esc(site)}' AND report_date >= today() - {MIN_LOOKBACK_DAYS}
        GROUP BY cell_name, cgisai
        ORDER BY tcp_3_fr DESC""")


# ---------------------------------------------------------------------------
# Day-compare (target day vs day before vs same weekday last week)
# ---------------------------------------------------------------------------
_METRICS = {
    "tcp_sr":   {"label": "TCP SR %",  "direction": -1},
    "tcp_fr2":  {"label": "TCP FR2 %", "direction": +1},
    "tcp_2_fr": {"label": "TCP FR2 %", "direction": +1},
    "tcp_3_fr": {"label": "TCP FR3 %", "direction": +1},
}


_ENTITY_COLS = ("ipv6_prefix_48", "ipv4_prefix_24", "subnet_prefix",
                "prefix", "site")


def entity_column(df: pd.DataFrame) -> str:
    for c in _ENTITY_COLS:
        if c in df.columns:
            return c
    raise SystemExit(f"No entity column ({_ENTITY_COLS}) in CSV columns: "
                     f"{list(df.columns)}")


def _compare_days(df: pd.DataFrame, target_day, top: int):
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


# ---------------------------------------------------------------------------
# Anomaly detection + UI  (unchanged logic)
# ---------------------------------------------------------------------------

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
_FONT = "Inter, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
C = {
    "bg":       "#eef0fc",   # soft lavender page background
    "card":     "#ffffff",
    "navy":     "#4f52c9",   # sidebar / deep indigo
    "navy2":    "#6c63e6",
    "accent":   "#5b5fe0",   # primary indigo
    "lilac":    "#b9b8f5",
    "text":     "#2b2d4a",
    "muted":    "#8b8fae",
    "border":   "#e6e8f8",
    "critical": "#e5533d",
    "high":     "#f28c5b",   # warm orange (secondary colour)
    "medium":   "#f6c177",
    "ok":       "#3fbf9b",
}
CARD_STYLE = {"background": C["card"], "borderRadius": "22px",
              "padding": "22px 24px",
              "boxShadow": "0 10px 30px rgba(91,95,224,0.09)"}
SECTION_TITLE = {"margin": "0 0 4px", "fontSize": "15px",
                 "fontWeight": "700", "color": C["text"]}
SECTION_SUB = {"margin": "0 0 14px", "fontSize": "12px", "color": C["muted"]}
LABEL_STYLE = {"fontWeight": "600", "fontSize": "11px", "color": C["muted"],
               "textTransform": "uppercase", "letterSpacing": "0.4px"}


def _chip(text: str, color: str) -> html.Span:
    return html.Span(text, style={
        "backgroundColor": color, "color": "white", "borderRadius": "999px",
        "padding": "3px 12px", "fontSize": "10.5px", "fontWeight": "700",
        "letterSpacing": "0.5px"})


def _stat_card(label: str, value: str, color: str, sub: str = "") -> html.Div:
    return html.Div(
        style={**CARD_STYLE, "flex": "1", "minWidth": "150px",
               "padding": "18px 22px"},
        children=[
            html.Div(label, style={**LABEL_STYLE, "marginBottom": "6px"}),
            html.Div(value, style={"fontSize": "32px", "fontWeight": "700",
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


_INDEX_HTML = """<!DOCTYPE html>
<html>
<head>
{%metas%}<title>{%title%}</title>{%favicon%}{%css%}
<style>
  html, body { margin: 0; background: __BG__; font-family: __FONT__; color: __TEXT__; }
  * { box-sizing: border-box; }
  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-thumb { background: #cfd1f2; border-radius: 8px; }
  .tab-container, .tab-parent { border: none !important; }
  .tab { border: none !important; }
  .rc-slider-track { background-color: __ACCENT__ !important; }
  .rc-slider-handle { border-color: __ACCENT__ !important; background: #fff !important; }
  .rc-slider-rail { background-color: #e3e5fa !important; }
  .Select-control { border-radius: 12px !important; border-color: __BORDER__ !important; }
  .dash-dropdown, .dash-dropdown-trigger { border-radius: 12px !important; border-color: __BORDER__ !important; }
  .nd-nav a:hover { background: rgba(255,255,255,0.18) !important; }
  button:hover { filter: brightness(1.06); }
</style>
</head>
<body>
{%app_entry%}
<footer>{%config%}{%scripts%}{%renderer%}</footer>
</body>
</html>"""
_INDEX_HTML = (_INDEX_HTML.replace("__BG__", C["bg"]).replace("__FONT__", _FONT)
               .replace("__TEXT__", C["text"]).replace("__ACCENT__", C["accent"])
               .replace("__BORDER__", C["border"]))


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
    app.title = "Network Degradation Monitor"
    app.index_string = _INDEX_HTML
    has_ip_data = not ip_df.empty
    raw_datasets = raw_datasets or {}
    has_cell_data = cells_available()

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
            _anom_cache[key] = _attach_pool(find_anomalies(
                df, threshold, mode=mode, min_hours=min_hours,
                min_history_days=min_history_days), tab)
        return _anom_cache[key]

    _pool_total_cache: dict = {}

    def _pool_totals(tab):
        """pool_id -> number of subnets of this tab that live in the pool."""
        if tab not in _pool_total_cache:
            df = datasets[tab][["ugw", "prefix"]].drop_duplicates()
            pools = pd.Series([_SUBNET_POOL.get((u, p), "-")
                               for u, p in zip(df["ugw"], df["prefix"])])
            _pool_total_cache[tab] = pools.value_counts().to_dict()
        return _pool_total_cache[tab]

    def _pool_summary(anom, tab):
        """'Degraded subnets grouped by pool' - the manager's view."""
        if anom.empty or "pool" not in anom.columns:
            return None
        a = anom[anom["pool"] != "-"]
        if a.empty:
            return None
        totals = _pool_totals(tab)
        g = (a.groupby("pool")
              .agg(degraded=("prefix", "nunique"), worst=("max_sr_drop", "max"))
              .reset_index())
        g["total"] = g["pool"].map(totals).fillna(0).astype(int)
        g["share"] = (100.0 * g["degraded"] / g["total"].clip(lower=1)).round(0)
        g["worst"] = g["worst"].round(1)
        g = g.sort_values(["degraded", "worst"], ascending=False)
        return html.Div(style={"marginBottom": "14px"}, children=[
            html.Div("Degraded subnets grouped by IP pool",
                     style={"fontSize": "12.5px", "fontWeight": "700",
                            "color": C["text"], "marginBottom": "4px"}),
            html.Div("Several degraded subnets in one pool = likely a pool-level problem.",
                     style={"fontSize": "11px", "color": C["muted"],
                            "marginBottom": "6px"}),
            dash_table.DataTable(
                data=g.rename(columns={
                    "pool": "Pool", "degraded": "Degraded subnets",
                    "total": "Subnets in pool", "share": "% of pool",
                    "worst": "Worst drop (pts)"}).to_dict("records"),
                columns=[{"name": c, "id": c} for c in
                         ("Pool", "Degraded subnets", "Subnets in pool",
                          "% of pool", "Worst drop (pts)")],
                page_size=8, sort_action="native",
                style_table={"overflowX": "auto"},
                style_header={"backgroundColor": "#5b5fe0", "color": "white",
                              "fontWeight": "bold", "fontSize": "11.5px"},
                style_cell={"padding": "5px 8px", "fontSize": "11.5px",
                            "border": "1px solid #eef0fb", "textAlign": "left"},
                style_data_conditional=[
                    {"if": {"filter_query": "{Degraded subnets} >= 2"},
                     "backgroundColor": "#fef5e7", "fontWeight": "600"},
                    {"if": {"filter_query": "{% of pool} >= 50"},
                     "backgroundColor": "#fdecea", "color": "#c0392b"}]),
        ])

    # One-line caption per tab explaining what "drop" means there.
    _TAB_CAPTIONS = {
        "IPv6":  "IPv6 /48 subnets — drop = TCP SR this many points below healthy peers (75th pct). Degraded subnets are also grouped by their IP pool",
        "IPv4":  "IPv4 /24 subnets — drop = TCP SR this many points below healthy peers (75th pct). Degraded subnets are also grouped by their IP pool",
        "Pools": "IP pools (ip_pools.xlsx) - drop = TCP SR this many points below same-type pools of the other gateways at that hour. LOCKed redundancy twins and pools under 50k sessions/hour are hidden",
        "Sites": "Sites (RAN) — drop = TCP FR3 this many points ABOVE the site's own normal level (its best-quarter hours)",
    }

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    app.layout = html.Div(
        style={"fontFamily": _FONT,
               "backgroundColor": C["bg"], "minHeight": "100vh",
               "paddingBottom": "40px"},
        children=[

            # ── Header ─────────────────────────────────────────────────
            html.Div(
                style={"padding": "28px 32px 8px", "display": "flex",
                       "alignItems": "center", "justifyContent": "space-between",
                       "flexWrap": "wrap", "gap": "12px"},
                children=[
                    html.Div([
                        html.H1("Network Degradation Monitor",
                                style={"margin": 0, "fontSize": "26px",
                                       "fontWeight": "700", "color": C["text"]}),
                        html.P("TCP KPI anomalies across subnets, IP pools, gateways "
                               "and sites — peer-benchmarked, updated daily.",
                               style={"margin": "6px 0 0", "color": C["muted"],
                                      "fontSize": "13px"}),
                    ]),
                    html.Div(
                        style={"display": "flex", "gap": "10px", "flexWrap": "wrap"},
                        children=[
                            html.Button(
                                "Export Degraded Pools", id="download-pools-btn", n_clicks=0,
                                style={"background": "#ffffff", "color": C["accent"],
                                       "border": f"1.5px solid {C['accent']}",
                                       "borderRadius": "999px", "padding": "11px 22px",
                                       "fontWeight": "600", "fontSize": "13px",
                                       "cursor": "pointer", "whiteSpace": "nowrap"},
                            ),
                            dcc.Download(id="download-pools-report"),
                            html.Button(
                                "Download Report", id="download-btn", n_clicks=0,
                                style={"background": f"linear-gradient(135deg,{C['accent']},{C['navy2']})",
                                       "color": "white", "border": "none",
                                       "borderRadius": "999px", "padding": "11px 24px",
                                       "fontWeight": "600", "fontSize": "13px",
                                       "cursor": "pointer", "whiteSpace": "nowrap",
                                       "boxShadow": "0 8px 20px rgba(91,95,224,0.35)"},
                            ),
                            dcc.Download(id="download-report"),
                        ],
                    ),
                ],
            ),

            html.Div(
                style={"padding": "12px 32px 0"},
                children=[

                    # ── Family tabs ─────────────────────────────────────
                    dcc.Tabs(
                        id="family-tabs",
                        value=first_tab,
                        style={"marginBottom": "10px", "border": "none"},
                        colors={"border": "transparent", "primary": C["accent"],
                                "background": "transparent"},
                        children=[
                            dcc.Tab(
                                label=label, value=label,
                                style={"padding": "9px 22px", "fontWeight": "600",
                                       "fontSize": "13px", "border": "none",
                                       "borderRadius": "999px", "marginRight": "8px",
                                       "background": "#ffffff", "color": C["muted"],
                                       "boxShadow": "0 2px 10px rgba(91,95,224,0.07)"},
                                selected_style={"padding": "9px 22px",
                                                "fontWeight": "700",
                                                "fontSize": "13px", "border": "none",
                                                "borderRadius": "999px",
                                                "marginRight": "8px",
                                                "background": C["accent"],
                                                "color": "#ffffff",
                                                "boxShadow": "0 8px 18px rgba(91,95,224,0.35)"},
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

    @app.callback(
        Output("gw-filter",       "options"),
        Output("gw-filter",       "value"),
        Output("contrib-gw",      "options"),
        Output("contrib-gw",      "value"),
        Output("tab-caption",     "children"),
        Output("download-pools-btn", "style"),
        Input("family-tabs",      "value"),
    )
    def switch_tab(tab):
        """Tab switched -> rebuild gateway dropdowns for the new dataset.
        (subnet-selector.value is owned by select_entity below.)"""
        df = datasets[tab] if tab in datasets else datasets[first_tab]
        gws = sorted(df["ugw"].dropna().unique())
        pools_btn_style = {
            "background": "#ffffff", "color": C["accent"],
            "border": f"1.5px solid {C['accent']}",
            "borderRadius": "999px", "padding": "11px 22px",
            "fontWeight": "600", "fontSize": "13px",
            "cursor": "pointer", "whiteSpace": "nowrap",
            "display": "inline-block" if tab in ("IPv4", "IPv6") else "none",
        }
        return ([{"label": g, "value": g} for g in ["All"] + gws],
                "All",
                [{"label": g, "value": g} for g in gws],
                None,
                _TAB_CAPTIONS.get(tab, ""),
                pools_btn_style)

    @app.callback(
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

    @app.callback(
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

        if "pool" in anom.columns:
            n_pools = int(anom.loc[anom["pool"] != "-", "pool"].nunique())
            cards.append(_stat_card("Pools affected", str(n_pools), C["high"],
                                    sub="pools holding a degraded subnet"))

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
        pool_block = _pool_summary(anom, tab)
        if pool_block is not None:
            items.insert(0, pool_block)
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
                       "borderRadius": "14px", "cursor": "pointer",
                       "border": f"2px solid {C['accent'] if is_sel else 'transparent'}",
                       "borderLeft": f"4px solid {color}",
                       "background": "#ecebff" if is_sel else "#f7f8ff"},
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
                        f"{r['ugw']} · "
                        + (f"pool {r['pool']} · " if "pool" in r.index and r["pool"] != "-" else "")
                        + f"drop {r['max_sr_drop']:.1f} pts · since {first}",
                        style={"fontSize": "11px", "color": C["muted"],
                               "marginTop": "4px"}),
                ],
            ))

        return cards, html.Div(items), _build_subnet_options(anom), label

    @app.callback(
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

    @app.callback(
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
            style_header={"backgroundColor": "#5b5fe0", "color": "white",
                          "fontWeight": "bold", "fontSize": "13px"},
            style_cell={"padding": "8px 12px", "fontSize": "13px",
                        "border": "1px solid #eef0fb"},
            style_data_conditional=[
                {"if": {"column_id": "sr_lift_pts", "filter_query": "{sr_lift_pts} > 5"},
                 "backgroundColor": "#fdecea", "color": "#c0392b", "fontWeight": "600"},
                {"if": {"column_id": "sr_lift_pts", "filter_query": "{sr_lift_pts} > 1"},
                 "backgroundColor": "#fef5e7", "color": "#e67e22"},
            ],
        )
        return summary, table

    @app.callback(
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
            cols = ["severity", "ip_version", "ugw", "prefix"]
            names = ["Severity", "IP Family", "Gateway", "Subnet"]
            if "pool" in report.columns:
                cols.append("pool"); names.append("Pool")
            cols += ["current_sr", "normal_sr", "max_sr_drop", "max_fr2_rise",
                     "first_appeared", "first_seen", "worst_hour"]
            names += ["Current SR (%)", "Healthy Peer SR (%)", "SR Drop (pts)",
                      "FR2 Rise (pts)", "First Appeared", "First Seen", "Worst Hour"]
            report = report[cols]
            report.columns = names
        for col in ("First Appeared", "First Seen", "Worst Hour"):
            report[col] = pd.to_datetime(report[col]).dt.strftime("%Y-%m-%d %H:%M")

        ts = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
        mode_tag = {"current": "currently_impacted",
                    "historical": "historical_drops",
                    "recovered": "recovered"}.get(mode or "current", "subnets")
        tab_tag = (tab or first_tab).lower()
        filename = f"tcp_kpi_{tab_tag}_{mode_tag}_{ts}.csv"
        return dcc.send_data_frame(report.to_csv, filename, index=False)

    @app.callback(
        Output("download-pools-report", "data"),
        Input("download-pools-btn",     "n_clicks"),
        State("family-tabs",      "value"),
        State("gw-filter",        "value"),
        State("threshold-slider",         "value"),
        State("mode-dropdown",            "value"),
        State("min-hours-slider",         "value"),
        State("min-history-days-slider",  "value"),
        prevent_initial_call=True,
    )
    def export_pools_report(n_clicks, tab, gw_filter, threshold, mode,
                            min_hours, min_history_days):
        """'Degraded subnets grouped by IP pool' panel, as CSV — IPv4/IPv6 only."""
        if tab not in ("IPv4", "IPv6"):
            return no_update

        anom = _cached_anomalies(tab, threshold, mode, min_hours, min_history_days)
        if gw_filter and gw_filter != "All":
            anom = anom[anom["ugw"] == gw_filter]
        if anom.empty or "pool" not in anom.columns:
            return no_update

        a = anom[anom["pool"] != "-"]
        if a.empty:
            return no_update

        totals = _pool_totals(tab)
        g = (a.groupby("pool")
              .agg(degraded=("prefix", "nunique"), worst=("max_sr_drop", "max"))
              .reset_index())
        g["total"] = g["pool"].map(totals).fillna(0).astype(int)
        g["share_pct"] = (100.0 * g["degraded"] / g["total"].clip(lower=1)).round(1)
        g["worst"] = g["worst"].round(1)
        g = g.sort_values(["degraded", "worst"], ascending=False)
        g = g.rename(columns={
            "pool": "Pool", "degraded": "Degraded subnets",
            "total": "Subnets in pool", "share_pct": "% of pool",
            "worst": "Worst drop (pts)"})
        g = g[["Pool", "Degraded subnets", "Subnets in pool",
               "% of pool", "Worst drop (pts)"]]

        ts = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
        filename = f"tcp_kpi_{tab.lower()}_degraded_pools_{ts}.csv"
        return dcc.send_data_frame(g.to_csv, filename, index=False)

    @app.callback(
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
            fillcolor="rgba(108,99,230,0.12)",
            line=dict(color="rgba(0,0,0,0)"),
            name="Healthy peer range",
            hoverinfo="skip",
        ))

        # Healthy-peer reference line
        fig.add_trace(go.Scatter(
            x=s["hour_dt"], y=base_y,
            mode="lines", name=base_name,
            line=dict(color="#a5a8f5", width=2.5, dash="dot"),
        ))

        # Main metric
        fig.add_trace(go.Scatter(
            x=s["hour_dt"], y=main_y.round(1),
            mode="lines+markers", name=main_name,
            line=dict(color="#5b5fe0", width=2.5),
            marker=dict(size=4),
        ))

        # Secondary metric (subnets only — the Sites tab shows FR3 alone)
        if sec_y is not None:
            fig.add_trace(go.Scatter(
                x=s["hour_dt"], y=sec_y.round(1),
                mode="lines", name=sec_name,
                line=dict(color="#f28c5b", width=2, dash="dash"),
                yaxis="y" if same_axis else "y2",
            ))

        fig.update_layout(
            template="plotly_white", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family=_FONT, color=C["text"]),
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
            ip_content = _cell_drilldown(prefix, has_cell_data)
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
                        "backgroundColor": "#5b5fe0", "color": "white",
                        "fontWeight": "bold", "fontSize": "13px",
                    },
                    style_cell={"padding": "8px 12px", "fontSize": "13px", "border": "1px solid #eef0fb"},
                    style_data_conditional=[
                        {"if": {"filter_query": "{tcp_sr} < 30"},
                         "backgroundColor": "#fdecea", "color": "#c0392b"},
                        {"if": {"filter_query": "{tcp_sr} >= 30 && {tcp_sr} < 60"},
                         "backgroundColor": "#fef5e7", "color": "#e67e22"},
                    ],
                )

        return fig, title, ip_content, panel_title

    @app.callback(
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
            colorscale=[[0, "#f3f2ff"], [0.5, "#ffc9a8"], [1, "#e5533d"]],
            colorbar={"title": "FR3 %"},
            hovertemplate="site=%{y}<br>hour=%{x}<br>FR3=%{z:.2f}%<extra></extra>",
        ))
        fig.update_layout(
            template="plotly_white", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family=_FONT, color=C["text"]),
            xaxis={"title": "Hour", "tickangle": -45},
            yaxis={"title": "", "autorange": "reversed"},
            margin={"t": 10, "b": 80, "l": 100, "r": 40},
        )
        return fig, shown

    @app.callback(
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
            style_header={"backgroundColor": "#5b5fe0", "color": "white",
                          "fontWeight": "bold", "fontSize": "12px"},
            style_cell={"padding": "6px 10px", "fontSize": "12px",
                        "border": "1px solid #eef0fb"},
            style_data_conditional=(
                [{"if": {"column_id": c, "filter_query": f"{{{c}}} > 10"},
                  "backgroundColor": "#fdecea", "color": "#c0392b",
                  "fontWeight": "600"} for c in deg_cols] +
                [{"if": {"column_id": c, "filter_query": f"{{{c}}} > 3"},
                  "backgroundColor": "#fef5e7", "color": "#e67e22"} for c in deg_cols]
            ),
        )

    @app.callback(
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
        ent_col = "site" if tab == "Sites" else "prefix"
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
                (week,   f"{week} (week ago)",   "#c3c5ee", 2.0),
                (prev,   f"{prev} (day before)", "#f28c5b", 2.0),
                (target, f"{target} (picked)",   "#5b5fe0", 3.5)):
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
            template="plotly_white", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family=_FONT, color=C["text"]),
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

def _cell_drilldown(site: str, has_cell_data: bool):
    """Right-panel content for the Sites tab: per-cell FR2/FR3 table for the
    selected site, worst cells first."""
    if not has_cell_data:
        return html.P(
            "Cell drill-down not available — export cell-level data first "
            "(python3.9 etl.py fetch --jobs site_cells, then etl.py transform).",
            style={"color": "#95a5a6", "fontSize": "13px"},
        )
    g = _cell_rows(site)
    if g.empty:
        return html.P("No cell data for this site.",
                      style={"color": "#95a5a6", "fontSize": "13px"})
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
        style_header={"backgroundColor": "#5b5fe0", "color": "white",
                      "fontWeight": "bold", "fontSize": "13px"},
        style_cell={"padding": "8px 12px", "fontSize": "13px",
                    "border": "1px solid #eef0fb"},
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
        template="plotly_white", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family=_FONT, color=C["text"]),
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



# ---------------------------------------------------------------------------
# Assemble the app
# ---------------------------------------------------------------------------
def load_and_build(args, url_base_pathname: str = "/"):
    """Everything main() does except argparse and app.run(). hub.py calls this
    to mount the app at a sub-path. Only `lookback` and `threshold` are read
    from args; everything else comes from ClickHouse."""
    config = load_config()
    lookback = max(int(getattr(args, "lookback", 0) or 0), MIN_LOOKBACK_DAYS)
    threshold = float(getattr(args, "threshold", 15.0))

    datasets, raw_datasets = {}, {}

    _SUBNET_POOL.clear()
    _SUBNET_POOL.update(load_subnet_pool())
    print(f"Loaded {len(_SUBNET_POOL):,} subnet -> pool mappings")

    subnets = load_subnets(lookback)
    if subnets.empty:
        raise SystemExit("No rows in nd_subnet_hourly. Build the tables first:\n"
                         "  python3.9 etl.py pools\n"
                         "  python3.9 etl.py transform --days 30 --rebuild")
    print(f"Loaded {len(subnets):,} subnet-hours from nd_subnet_hourly (last {lookback} days)")
    for family in ("IPv6", "IPv4"):
        part = subnets[subnets["ip_version"] == family].reset_index(drop=True)
        if not part.empty:
            datasets[family] = part
            raw_datasets[family] = _compare_frame(part)

    pools = load_pools(lookback, subnets["ugw"].unique())
    if not pools.empty:
        datasets["Pools"] = pools
        raw_datasets["Pools"] = _compare_frame(pools)
        print(f"  -> {len(pools):,} pool-hours, {pools['prefix'].nunique()} pools")

    sites = load_sites(lookback)
    if not sites.empty:
        datasets["Sites"] = sites
        raw_datasets["Sites"] = (sites[["hour_dt", "ugw", "prefix", "tcp_2_fr", "tcp_3_fr",
                                        "session_count"]]
                                 .rename(columns={"hour_dt": "hour", "prefix": "site"}))
        print(f"  -> {len(sites):,} site-hours, {sites['prefix'].nunique()} sites")

    for label, d in datasets.items():
        n_anom = len(find_anomalies(d, threshold))
        print(f"[{label}] {d['prefix'].nunique()} entities, "
              f"{n_anom} impacted (SR drop > {threshold}%)")

    viz = config.get("visualization", {})
    app = build_app(datasets, pd.DataFrame(), threshold, raw_datasets=raw_datasets,
                    url_base_pathname=url_base_pathname)
    return app, viz.get("host", "127.0.0.1"), viz.get("port", 8888)


def main():
    parser = argparse.ArgumentParser(description="Network Degradation Monitor")
    parser.add_argument("--lookback", type=int, default=MIN_LOOKBACK_DAYS,
                        help=f"days of history to load (min {MIN_LOOKBACK_DAYS})")
    parser.add_argument("--threshold", type=float, default=15.0,
                        help="SR drop threshold in %% points (default: 15)")
    args = parser.parse_args()

    app, host, port = load_and_build(args)
    print(f"\nDashboard running -> http://localhost:{port}\nPress Ctrl+C to stop.\n")
    app.run(debug=False, host=host, port=port)


if __name__ == "__main__":
    main()
