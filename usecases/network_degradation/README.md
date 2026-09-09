# TCP KPI Anomaly Detection Dashboard

Identifies IPv6 subnets (Etisalat `2c0f:fc89::/32` range) whose TCP Success Rate
is far below their healthy peers — the symptom of a missing BGP return path.
Built for the May 2026 mobile-internet degradation incident.

## What you need

- A Windows or Linux machine with **Python 3.9+**
- The exported CSVs from the Hive query (see below)
- (Optional) Kerberos ticket if you want to query the database directly instead
  of using CSVs

## Setup (one time)

```bat
:: Open a terminal in this folder, then:
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

On Linux / macOS the second line is `source .venv/bin/activate`.

## How to use

### 1. Export the data

Run this query in DBeaver (or whatever SQL client you use against the Hive
warehouse). Run it **once per 15-min table** you care about and save each
result as a separate CSV inside the `data/` folder.

```sql
SELECT
    FROM_UNIXTIME(
        CAST(timecolumn AS BIGINT) - (CAST(timecolumn AS BIGINT) % 3600),
        'yyyy/MM/dd HH:00'
    )                                                                           AS hour,
    CASE ggsn_pgw_id
        WHEN 27 THEN 'RamsisPost_PDG25' WHEN 200036 THEN 'RamsisPost_PDG25'
        WHEN 20 THEN 'Aburawash_R1DG28' WHEN 200042 THEN 'Aburawash_R1DG28'
        WHEN 19 THEN 'Banisuif_FGG13'   WHEN 200019 THEN 'Banisuif_FGG13'
        WHEN 41 THEN 'SV_UDG01'         WHEN 200053 THEN 'SV_UDG01'
        WHEN 26 THEN 'AlexPost_ODG21'   WHEN 200028 THEN 'AlexPost_ODG21'
        WHEN 1  THEN 'AlexAuto_XGG09'   WHEN 200015 THEN 'AlexAuto_XGG09'
        ELSE CAST(ggsn_pgw_id AS STRING)
    END                                                                         AS ugw,
    CASE WHEN SIZE(SPLIT(ms_ip_pa,':')) >= 3
         THEN CONCAT(SPLIT(ms_ip_pa,':')[0],':',SPLIT(ms_ip_pa,':')[1],':',SPLIT(ms_ip_pa,':')[2])
         ELSE ms_ip_pa END
                                                                                 AS ipv6_prefix_48,
    COUNT(*)                                                                    AS session_count,
    SUM(ide_total_tcpconnsucccount) * 100.0
        / NULLIF(SUM(ide_total_tcpconncount), 0)                               AS tcp_sr,
    SUM(ide_total_tcp_conn_2_failed_times) * 100.0
        / NULLIF(SUM(ide_total_tcp_conn_times), 0)                             AS tcp_fr2
FROM sdr_nethouse.sdr_dyn_ide_soc_tcp_user_15m_XXXXX
WHERE timecolumn >= unix_timestamp('2026-05-05 00:00:00')
  AND ms_ip_type_pa = 'IPV6'
  AND ms_ip_pa LIKE '2c0f:fc89:%'
  AND apn IN ('ETISALAT', 'INTERNET.ETISALAT')
  AND ggsn_pgw_id IN (27,200036, 20,200042, 19,200019, 41,200053, 26,200028, 1,200015)
GROUP BY
    FROM_UNIXTIME(
        CAST(timecolumn AS BIGINT) - (CAST(timecolumn AS BIGINT) % 3600),
        'yyyy/MM/dd HH:00'
    ),
    ggsn_pgw_id,
    CASE WHEN SIZE(SPLIT(ms_ip_pa,':')) >= 3
         THEN CONCAT(SPLIT(ms_ip_pa,':')[0],':',SPLIT(ms_ip_pa,':')[1],':',SPLIT(ms_ip_pa,':')[2])
         ELSE ms_ip_pa END
HAVING COUNT(*) >= 200
```

Replace `XXXXX` with each table number you want to query. To cover the
degradation period (May 5 → today), run tables **20578 through 20594**
(or wider if you want extra buffer).

Save each result into `data/` — file names don't matter, just keep them `.csv`.
Example layout:

```
Network Service Degradation/
├── dashboard.py
├── data/
│   ├── 20578.csv
│   ├── 20579.csv
│   ├── ...
│   └── 20594.csv
```

### 2. Run the dashboard

```bat
.venv\Scripts\activate
python dashboard.py
```

That's it. The dashboard auto-loads everything in `data/`, runs the peer-based
detection, and starts a local web server. Open the URL it prints (usually
`http://localhost:8888`) in any browser.

### 3. Adjust sensitivity

The slider at the top sets the SR-drop threshold (how far below the healthy
peers a subnet has to be before it's flagged). Default 15%. Move it up for
fewer flags, down for more.

## Optional: per-IP drill-down

To populate the **"Affected Subscriber IPs"** panel, export a second set of
CSVs with one row per individual IP. Same query as above, but:

1. Add `ms_ip_pa AS subscriber_ip` to `SELECT`
2. Add `ms_ip_pa` to `GROUP BY`
3. Change `HAVING COUNT(*) >= 200` to `HAVING COUNT(*) >= 5`
4. Add a filter for the broken subnets only, e.g.
   `AND ms_ip_pa LIKE '2c0f:fc89:181:%'` (otherwise you'll get millions of rows)

Save those CSVs into a separate folder like `data_ips/` and run:

```bat
python dashboard.py --ip-csv data_ips
```

## Command-line options

| Flag | Default | Description |
|------|---------|-------------|
| `--csv PATH` | `data` | CSV file or folder of CSVs (per-subnet aggregated) |
| `--ip-csv PATH` | (none) | CSV file or folder of CSVs (per-IP drill-down) |
| `--site-csv PATH` | `data/data_site` | CSV file or folder of CSVs (site-level FR2/FR3) |
| `--cells-csv PATH` | `data/data_site_cells` | CSV file or folder of CSVs (per-cell drill-down) |
| `--threshold N` | `15` | SR-drop threshold in percentage points |
| `--lookback N` | `7` | Days to fetch (live DB mode only) |

## Tabs: IPv6 / IPv4 / Sites

The dashboard shows a tab bar at the top. IPv4 and IPv6 subnets get their own
tabs (split automatically from the `--csv` data — peers are never mixed across
families). If site-level CSVs exist (columns `hour, site, session_count,
tcp_2_fr, tcp_3_fr` — e.g. exported by `tools/daily_update.py`), a **Sites**
tab appears. There, a "drop" means the site's TCP FR2 is that many points
**above** its healthy peer sites (the chart plots `100 − FR2` so it reads the
same as the subnet views; the right axis shows FR3). The Download Report
button exports per-tab CSVs.

Extra panels:

- **Cells drill-down** (Sites tab): if cell-level CSVs exist (see
  `--cells-csv` / the `site_cells` job in `tools/daily_update.py`), selecting
  a site lists its cells with sessions/FR2/FR3, worst first.
- **Worst Sites FR2 heatmap** (Sites tab): top 25 sites by average FR2 over
  the last 72 hours, hour by hour.
- **Compare days** (all tabs): pick a day — a line chart overlays that day's
  hourly KPI with the day before and the same weekday last week (select a
  subnet/site first to scope the lines to it), and the table below gives
  per-entity daily values with degradation columns (positive = worse).
  Same math as `tools/compare_days.py`.

Note: the `data_site_cells` CSVs are the largest ones (~0.5–1M rows/day).
They load once at startup; keep the folder to about a week of files (old
CSVs can be pruned freely — the daily_update state file prevents
re-exporting them).

## How the detection works

For each (gateway, timepoint) pair the dashboard computes the **75th-percentile
TCP Success Rate** across that gateway's subnets — i.e. what *healthy* subnets
are achieving right now. Any subnet whose SR is more than `--threshold`
percentage points below that reference is flagged.

This works even with a single day of post-degradation data — no pre-incident
baseline needed — because broken subnets and working subnets coexist in the
same dataset.

## Automated daily update

`tools/daily_update.py` queries the warehouse directly and appends yesterday's
rotated table as a new CSV per pipeline — no manual DBeaver exports. It covers
three jobs: `ipv6` (→ `data/data_ipv6/`), `ipv4` (→ `data/data_ipv4/`) and
`site` (site-level FR2/FR3 → `data/data_site/`).

Tables are discovered with `SHOW TABLES LIKE` and date-checked by probing
`MIN/MAX(timecolumn)`, so table-number gaps don't matter, the partial
current-day table is never exported, and days missed while the machine was
off are backfilled automatically on the next run.

### Setup on the machine that runs it (must have VPN + Kerberos access)

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

:: one-time validation (VPN connected, Kerberos ticket valid):
python tools/daily_update.py --check
:: see what it would export, writing nothing:
python tools/daily_update.py --dry-run
:: first real run:
python tools/daily_update.py
```

### Schedule it (Windows Task Scheduler)

```bat
schtasks /Create /TN "TCP-KPI-Daily-Update" /TR "\"C:\path\to\project\tools\run_daily_update.bat\"" /SC DAILY /ST 07:30
```

The Kerberos ticket must be renewed **before** the run each day — if it has
expired the script exits with a clear "renew your ticket" message in
`tools/daily_update.log`. Already-exported tables are tracked in
`tools/.daily_update_state.json` and by the CSVs themselves, so re-runs are
safe.

Useful flags: `--jobs ipv6,ipv4` (subset), `--dry-run`, `--check`,
`--out-root PATH` (if the `data/` folders live somewhere else),
`--backfill N` (one-time: also export older days, up to the newest N tables
per job — already-exported days are skipped automatically. Use e.g.
`--backfill 10` so week-before comparisons have their day-7 baseline).

## Troubleshooting

- **"No .csv files found in folder: ./data"** — put at least one exported CSV
  in the `data/` folder.
- **Chart shows 1970-01-01** — the `day`/`hour` column wasn't parsed. Make sure
  the CSV's first column is named `hour` (string like `"2026/05/13 14:00"`) or
  `day` (string or integer daypartition).
- **Port 8888 already in use** — edit `config/config.yaml` and change
  `visualization.port` to something else.
