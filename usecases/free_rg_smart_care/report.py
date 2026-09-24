#!/usr/bin/env python3
"""Shared management-report builder.

Produces the multi-sheet Excel workbook used by both deployment approaches:
  - the dashboard's "Download Report" button (dashboard.py)
  - the headless server export (tools/export_report.py)

Sheets: Overview, Daily Summary, RG Day-over-Day, Violators, Repeat Offenders.
"""

from __future__ import annotations

import pandas as pd

from dashboard import REPEAT_FLAG_DAYS, _fmt_mb, compute_day_over_day


def build_report_workbook(buf, traffic_df: pd.DataFrame, users_df: pd.DataFrame,
                          top_users_df: pd.DataFrame,
                          selected_rgs: list[str] | None = None,
                          selected_apns: list[str] | None = None,
                          start_date: str | None = None,
                          end_date: str | None = None) -> None:
    """Write the management workbook to a file-like object `buf`.

    The three frames are the UNFILTERED dashboard datasets; the filter
    arguments mirror the dashboard filter bar (None/empty = no filtering).
    """
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
        e = pd.Timestamp(end_date) + pd.Timedelta(days=1)
        t = t[(t["myday"] >= s) & (t["myday"] < e)]
        u = u[(u["myday"] >= s) & (u["myday"] < e)]
        tu = tu[(tu["myday"] >= s) & (tu["myday"] < e)]

    has_base_viol = "violators" in u.columns and u["violators"].notna().any()
    viol_rows = (tu[tu["capping_status"] == "exceeded capping"].copy()
                 if not tu.empty and "capping_status" in tu.columns
                 else pd.DataFrame())

    # ── Sheet: Daily Summary ───────────────────────────────
    t_sum = t.groupby("myday").agg({"ccr_charge_traffic_mb": "sum"})
    u_agg = {"unique_users": "sum"}
    if has_base_viol:
        u_agg["violators"] = "sum"
    u_sum = u.groupby("myday").agg(u_agg)
    daily = t_sum.join(u_sum, how="outer").sort_index()
    daily["Traffic Δ%"] = (daily["ccr_charge_traffic_mb"].pct_change() * 100).round(1)
    daily["Users Δ%"] = (daily["unique_users"].pct_change() * 100).round(1)
    daily["Traffic (GB)"] = (daily["ccr_charge_traffic_mb"] / 1024).round(2)
    if has_base_viol:
        daily["Violators % of Base"] = (
            daily["violators"] / daily["unique_users"].replace(0, pd.NA) * 100
        ).round(3)
    if not viol_rows.empty:
        vrows = viol_rows.groupby("myday").size().rename("Violation Rows (top users)")
        daily = daily.join(vrows, how="left")
        daily["Violation Rows (top users)"] = daily["Violation Rows (top users)"].fillna(0).astype(int)
    daily = daily.reset_index()
    daily["Day"] = daily["myday"].dt.strftime("%Y-%m-%d")
    daily = daily.rename(columns={"unique_users": "Unique Users",
                                  "violators": "Violators (whole base)"})
    daily_cols = ["Day", "Traffic (GB)", "Traffic Δ%", "Unique Users", "Users Δ%"]
    if has_base_viol:
        daily_cols += ["Violators (whole base)", "Violators % of Base"]
    if "Violation Rows (top users)" in daily.columns:
        daily_cols += ["Violation Rows (top users)"]
    daily = daily[daily_cols]

    # ── Sheet: RG Day-over-Day ─────────────────────────────
    if t.empty:
        rg_dod = pd.DataFrame()
    else:
        rg_day = t.groupby(["myday", "rating_group_name"]).agg(
            {"ccr_charge_traffic_mb": "sum"}).reset_index()
        rg_day = compute_day_over_day(rg_day, "ccr_charge_traffic_mb",
                                      ["rating_group_name"])
        u_day = u.groupby(["myday", "rating_group_name"]).agg(
            {"unique_users": "sum"}).reset_index()
        u_day = compute_day_over_day(u_day, "unique_users",
                                     ["rating_group_name"])
        rg_dod = rg_day.merge(
            u_day[["myday", "rating_group_name", "unique_users",
                   "change_pct"]],
            on=["myday", "rating_group_name"], how="outer",
            suffixes=("_traffic", "_users"))
        rg_dod["Traffic (GB)"] = (rg_dod["ccr_charge_traffic_mb"] / 1024).round(2)
        rg_dod["Day"] = rg_dod["myday"].dt.strftime("%Y-%m-%d")
        rg_dod = rg_dod.rename(columns={
            "rating_group_name": "Rating Group",
            "change_pct_traffic": "Traffic Δ%",
            "unique_users": "Unique Users",
            "change_pct_users": "Users Δ%"})
        rg_dod = rg_dod[["Day", "Rating Group", "Traffic (GB)", "Traffic Δ%",
                         "Unique Users", "Users Δ%"]]
        rg_dod = rg_dod.sort_values(["Day", "Rating Group"],
                                    ascending=[False, True])

    # ── Sheet: Violators (every violation row in range) ────
    if viol_rows.empty:
        violators = pd.DataFrame()
    else:
        violators = viol_rows.copy()
        violators["Usage (GB)"] = (violators["ccr_charge_traffic_mb"] / 1024).round(3)
        violators["Over Cap (GB)"] = (
            (violators["ccr_charge_traffic_mb"] - violators["daily_capping_mb"]) / 1024
        ).round(3)
        violators["× Cap"] = (
            violators["ccr_charge_traffic_mb"] / violators["daily_capping_mb"]
        ).round(1)
        violators["Day"] = violators["myday"].dt.strftime("%Y-%m-%d")
        violators = violators.rename(columns={
            "rating_group_name": "Rating Group", "imsi": "IMSI",
            "msisdn": "MSISDN", "apn": "APN",
            "daily_capping_mb": "Daily Cap (MB)"})
        vcols = ["Day", "Rating Group", "IMSI", "MSISDN", "APN",
                 "Usage (GB)", "Daily Cap (MB)", "Over Cap (GB)", "× Cap"]
        violators = violators[[c for c in vcols if c in violators.columns]]
        violators = violators.sort_values(["Usage (GB)"], ascending=False)
        for id_col in ("IMSI", "MSISDN"):
            if id_col in violators.columns:
                violators[id_col] = violators[id_col].astype(str)

    # ── Sheet: Repeat Offenders (action list) ──────────────
    if viol_rows.empty:
        repeat = pd.DataFrame()
    else:
        group_keys = ["imsi"] + (["msisdn"] if "msisdn" in viol_rows.columns else [])
        repeat = viol_rows.groupby(group_keys).agg(
            days_exceeded=("myday", "nunique"),
            first_day=("myday", "min"),
            last_day=("myday", "max"),
            rgs=("rating_group_name", lambda s: ", ".join(sorted(s.unique()))),
            max_daily_mb=("ccr_charge_traffic_mb", "max"),
            total_mb=("ccr_charge_traffic_mb", "sum"),
        ).reset_index()
        repeat["Priority"] = "MEDIUM"
        repeat.loc[repeat["days_exceeded"] >= REPEAT_FLAG_DAYS, "Priority"] = "HIGH"
        repeat.loc[repeat["days_exceeded"] <= 1, "Priority"] = "LOW"
        repeat["First Day"] = repeat["first_day"].dt.strftime("%Y-%m-%d")
        repeat["Last Day"] = repeat["last_day"].dt.strftime("%Y-%m-%d")
        repeat["Max Daily (GB)"] = (repeat["max_daily_mb"] / 1024).round(2)
        repeat["Total (GB)"] = (repeat["total_mb"] / 1024).round(2)
        repeat = repeat.rename(columns={
            "imsi": "IMSI", "msisdn": "MSISDN",
            "days_exceeded": "Days Exceeded", "rgs": "Rating Groups"})
        repeat = repeat[["Priority", "IMSI"] +
                        (["MSISDN"] if "msisdn" in viol_rows.columns else []) +
                        ["Days Exceeded", "First Day", "Last Day",
                         "Rating Groups", "Max Daily (GB)", "Total (GB)"]]
        repeat = repeat.sort_values(["Days Exceeded", "Max Daily (GB)"],
                                    ascending=[False, False])
        for id_col in ("IMSI", "MSISDN"):
            if id_col in repeat.columns:
                repeat[id_col] = repeat[id_col].astype(str)

    # ── Sheet: Overview ────────────────────────────────────
    n_days = t["myday"].nunique() if not t.empty else 0
    total_mb = t["ccr_charge_traffic_mb"].sum() if not t.empty else 0
    busiest_rg = "—"
    if not t.empty and total_mb > 0:
        busiest_rg = t.groupby("rating_group_name")["ccr_charge_traffic_mb"].sum().idxmax()
    n_repeat_high = int((repeat["Priority"] == "HIGH").sum()) if not repeat.empty else 0
    overview_rows = [
        ("Report", "Free RGs Smart Care — Management Report"),
        ("Generated", pd.Timestamp.now().strftime("%Y-%m-%d %H:%M")),
        ("Date Range", f"{start_date} → {end_date}"),
        ("Rating Groups", f"{len(selected_rgs)} selected" if selected_rgs else "All"),
        ("APNs", f"{len(selected_apns)} selected" if selected_apns else "All"),
        ("Days Covered", n_days),
        ("Total Traffic", _fmt_mb(total_mb)),
        ("Avg Traffic / Day", _fmt_mb(total_mb / max(n_days, 1))),
        ("Busiest RG (range)", busiest_rg),
    ]
    if has_base_viol:
        base_v = int(u["violators"].sum())
        base_u = int(u["unique_users"].sum())
        overview_rows.append(("Violators (whole base, Σ daily)", f"{base_v:,}"))
        overview_rows.append(("Violators % of Base",
                              f"{round(base_v / base_u * 100, 3) if base_u else 0}%"))
    overview_rows += [
        ("Violation Rows (exported top users)", len(viol_rows)),
        ("Distinct Violating Users (top users)",
         viol_rows["imsi"].nunique() if not viol_rows.empty else 0),
        (f"Repeat Offenders (≥{REPEAT_FLAG_DAYS} days) — HIGH priority", n_repeat_high),
        ("Action Required",
         "See 'Repeat Offenders' sheet — HIGH priority rows first." if n_repeat_high
         else "No repeat offenders in range."),
    ]
    overview = pd.DataFrame(overview_rows, columns=["Metric", "Value"])

    # ── Write the workbook ─────────────────────────────────
    with pd.ExcelWriter(buf, engine="xlsxwriter") as writer:
        wb = writer.book
        header_fmt = wb.add_format({
            "bold": True, "font_color": "white", "bg_color": "#2c3e50",
            "border": 1, "text_wrap": False})
        red_fmt = wb.add_format({"font_color": "#c0392b", "bold": True,
                                 "bg_color": "#fdecea"})
        text_fmt = wb.add_format({"num_format": "@"})

        sheets = [("Overview", overview), ("Daily Summary", daily),
                  ("RG Day-over-Day", rg_dod), ("Violators", violators),
                  ("Repeat Offenders", repeat)]
        for name, df_sheet in sheets:
            if df_sheet.empty:
                df_sheet = pd.DataFrame({"Info": ["No data for selected filters."]})
            df_sheet.to_excel(writer, sheet_name=name, index=False,
                              startrow=1, header=False)
            ws = writer.sheets[name]
            for col_idx, col_name in enumerate(df_sheet.columns):
                ws.write(0, col_idx, col_name, header_fmt)
                width = max(len(str(col_name)) + 2,
                            int(df_sheet[col_name].astype(str).str.len().quantile(0.95)) + 2
                            if len(df_sheet) else 12)
                fmt = text_fmt if col_name in ("IMSI", "MSISDN") else None
                ws.set_column(col_idx, col_idx, min(width, 42), fmt)
            ws.freeze_panes(1, 0)
            ws.autofilter(0, 0, max(len(df_sheet), 1),
                          max(len(df_sheet.columns) - 1, 0))
            for flag_col in ("Flag", "Priority"):
                if flag_col in df_sheet.columns:
                    ci = df_sheet.columns.get_loc(flag_col)
                    ws.conditional_format(1, ci, len(df_sheet), ci, {
                        "type": "text", "criteria": "containing",
                        "value": "HIGH" if flag_col == "Priority" else "REPEAT",
                        "format": red_fmt})
