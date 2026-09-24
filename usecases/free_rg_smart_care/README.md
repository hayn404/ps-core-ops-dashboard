# Free RGs Smart Care Dashboard

Analytics dashboard for **free rating-group traffic and subscriber usage** on the Smart Care diameter interface (APN = ETISALAT, interfaceid = 12).

Built on the same database connection stack as [Network-Service-Degradation](https://github.com/hayn404/Network-Service-Degradation) but with a completely separate data model, queries, and visualizations.

---

## What you need

- Python 3.9+
- Valid Kerberos ticket + VPN (for live-DB mode)
- Or exported CSVs from the Hive query (for offline mode)

## Setup (one time)

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

On Linux / macOS the second line is `source .venv/bin/activate`.

## Configuration

Edit `config/config.yaml` (laptop) or `config/config.server.yaml` (Linux server, selected
via `FREE_RG_CONFIG`). The server variant uses `mode: "sasl"` and needs no JDBC settings.

| Key | Description |
|-----|-------------|
| `database.*` | Same connection settings as the TCP-KPI dashboard (host, port, Kerberos, JDBC jars, etc.) |
| `table_pattern` | Pattern to discover rotated daily tables, e.g. `DETAIL_CDR_SGIDIAMETER_%` |
| `apn_filter` | Comma-separated APN list, e.g. `ETISALAT` or `ETISALAT,INTERNET.ETISALAT`. Leave empty for all APNs. |
| `interface_id` | Diameter interface ID (default 12) |
| `msisdn_column` | Column holding the subscriber phone number in the CDR table (default `MSISDN`) |
| `free_rating_groups` | Maps RG ID → `{name, capping_mb}`. Used for labeling and capping-flag logic. |
| `visualization.port` | Dashboard port (default 8889) |

## How to use

Two deployment approaches are supported — both share the same export logic and the same
report builder, so the outputs are identical:

| | **A. Laptop** | **B. Server (headless)** |
|---|---|---|
| Data export | `tools\run_daily_update.bat` via Task Scheduler | `tools/run_daily_update.sh` via cron |
| Dashboard | `python dashboard.py` locally (port 8889) | later, once network security opens a port |
| Report | "Download Report" button in the dashboard | auto-written to `report.output_dir` every run |

### Approach A — laptop (data export + dashboard)

```bat
:: One-time validation
python tools\daily_update.py --check

:: See what it would export
python tools\daily_update.py --dry-run

:: First real run (backfill last 10 days)
python tools\daily_update.py --backfill 10

:: Normal daily run (append only new completed days)
python tools\daily_update.py
```

**Schedule it (Windows Task Scheduler):**

```bat
schtasks /Create /TN "FreeRG-SmartCare-Daily" /TR "\"C:\path\to\project\tools\run_daily_update.bat\"" /SC DAILY /ST 07:30
```

Then run the dashboard and open the URL it prints (usually `http://localhost:8889`):

```bat
.venv\Scripts\activate
python dashboard.py
```

**Offline mode (no DB connection):** `python dashboard.py --csv data`

### Approach B — server (headless: data export + report to a folder)

Use this while the dashboard port is not yet opened by network security. A cron job
exports the new day's data **and** writes the management report (multi-sheet Excel) to a
folder — no web port needed. This mirrors the Network-Service-Degradation server
deployment (same Hive, same SASL connection path).

**One-time server setup (Linux, no internet):**

```bash
python3.9 -m venv .venv && source .venv/bin/activate
# offline install from the wheel folder (copy offline_packages/ to the server)
pip install --no-index --find-links offline_packages -r requirements-server.txt
```

The project ships a ready `offline_packages/` folder (cp39 / manylinux wheels +
the `thrift` sdist). To rebuild it from a machine with internet:

```bat
:: binary wheels (cp39 / manylinux)
python -m pip download pandas plotly dash pyyaml xlsxwriter pure-sasl ^
    -d offline_packages --python-version 3.9 --platform manylinux2014_x86_64 --only-binary=:all:
python -m pip download pyhive thrift_sasl --no-deps ^
    -d offline_packages --python-version 3.9 --platform manylinux2014_x86_64 --only-binary=:all:
:: thrift has no wheel at all (pure-Python sdist — builds without a compiler)
python -m pip download thrift==0.23.0 --no-deps --no-binary=:all: -d offline_packages
:: sasl + kerberos Linux wheels — copy from the Network-Service-Degradation
:: server bundle (offline_packages) or download on a Linux machine
```

The server connects over **SASL** (pyhive/thrift + cyrus-sasl — no Java/JDBC needed);
`config/config.server.yaml` is a ready-made template (`mode: "sasl"`, dashboard bound to
`0.0.0.0`). It needs `/etc/krb5.conf` pointing at the HADOOP.COM KDC and a ticket for a
principal that can read the `ps` schema.

```bash
export FREE_RG_CONFIG=/path/to/project/config/config.server.yaml

# validate, backfill, then generate the report
python tools/daily_update.py --check
python tools/daily_update.py --backfill 10
python tools/export_report.py            # writes reports/free_rg_report_<ts>.xlsx
```

**Schedule it (cron):** — the runner renews the Kerberos ticket from a keytab when
`KRB5_KEYTAB`/`KRB5_PRINCIPAL` are set, then exports data and writes the report:

```cron
30 7 * * * FREE_RG_CONFIG=/path/to/config.server.yaml KRB5_KEYTAB=/home/user/svc.keytab KRB5_PRINCIPAL=svc@HADOOP.COM /path/to/project/tools/run_daily_update.sh >> /path/to/project/tools/cron.log 2>&1
```

`run_daily_update.sh` runs `daily_update.py` (new data) then `export_report.py`
(report → `report.output_dir`, default `reports/`). Useful flags for
`export_report.py`: `--days N` (default 7), `--out-dir PATH`, `--rg`, `--apn`.

**Later — hosting the dashboard on the server:** once the port is opened, the server
config already binds `0.0.0.0`; just run it in the background like the reference project:

```bash
FREE_RG_CONFIG=config/config.server.yaml nohup python dashboard.py > dashboard.log 2>&1 &
echo $! > dashboard.pid     # stop later with: kill $(cat dashboard.pid)
```

It reads the same `data/` folder the cron job maintains.

### What the daily export produces

The script discovers tables via `SHOW TABLES LIKE`, probes `MIN/MAX(TRANS_REQ_TIME_SEC)` to learn each table's calendar day, and exports **one CSV per completed day** using a **single unified query per table** (one scan instead of the old three):

| Job | Output folder | Content |
|-----|---------------|---------|
| `daily` | `data/free_rg_daily/` | Top 2000 users per RG per day (IMSI + MSISDN) with capping status, plus RG-level totals attached to every row: daily traffic, unique users, and **base-wide violator count** (all users over their cap, not just the top 2000) |

The dashboard derives the traffic, users, and top-users views from this one file. The legacy folders (`free_rg_traffic/`, `free_rg_users/`, `free_rg_top_users/`) are still read and merged if present, so previously exported days keep working; a `--backfill 10` run regenerates them in the new format.

Already-exported tables are tracked in `tools/.daily_update_state.json` and by the CSVs themselves — re-runs are safe. Legacy state watermarks are migrated automatically on the first run.

## Dashboard panels

Organized into four tabs (filters at the top apply everywhere):

- **Overview** — KPI cards (total traffic in GB/TB, daily users Σ, capping violations, avg/day),
  traffic & unique-users trends per RG, day-over-day % change charts, traffic-share donut
- **Capping & Top Users** — capping-status pie and violations-by-RG bar chart (computed over the
  top 2000 users per RG per day), a **Repeat Offenders** table (users exceeding their cap on
  ≥3 distinct days in the selected range are flagged, with IMSI + MSISDN), and the top-20
  users table (sortable/filterable, CSV-exportable, violation rows highlighted)
- **Daily Summary** — per-day totals (GB) with Δ% vs previous day, color-coded
- **Compare Days** — per-RG traffic bars for a picked day vs the previous day and the same
  weekday last week

Filters: rating groups (multi), APNs (multi, all selected by default), date range for charts,
plus a **KPI Day** picker that drives the KPI cards. The header shows the loaded data range, and
**Download Report** exports a multi-sheet **Excel workbook** for the current filters:

- **Overview** — report metadata and headline numbers (traffic, base-wide violators, repeat-offender count, action note)
- **Daily Summary** — per-day traffic (GB), users, base-wide violators + % of base, with day-over-day Δ%
- **RG Day-over-Day** — per-RG daily traffic/users with Δ% (spot which free service is growing)
- **Violators** — every capping violation in the range: IMSI, MSISDN, usage, cap, over-cap amount, ×cap multiple
- **Repeat Offenders** — one row per violating user, prioritized HIGH / MEDIUM / LOW by days exceeded — the action list for ops teams

## Command-line options

### dashboard.py

| Flag | Default | Description |
|------|---------|-------------|
| `--csv PATH` | `data` | Root folder containing `free_rg_daily/` (and/or the legacy `free_rg_traffic/`, `free_rg_users/`, `free_rg_top_users/`) |
| `--lookback N` | `7` | Days to fetch (live DB mode only) |

### tools/daily_update.py

| Flag | Default | Description |
|------|---------|-------------|
| `--jobs` | `daily` | Single unified export job (one scan per table) |
| `--out-root PATH` | repo root | Where `data/` folders live |
| `--dry-run` | — | Probe and report; write nothing |
| `--backfill N` | `0` | Also consider newest N tables (for initial load) |
| `--workers N` | `1` | Parallel exports (each gets its own DB connection) |
| `--fetch-size N` | `500` | JDBC fetch frame size |
| `--check` | — | Validate connectivity + schema, then exit |

### tools/export_report.py

| Flag | Default | Description |
|------|---------|-------------|
| `--csv PATH` | `<repo>/data` | Root data folder to read |
| `--out-dir PATH` | config `report.output_dir` | Where the `.xlsx` report is written |
| `--days N` | `7` | Cover the newest N days of data (`0` = all) |
| `--rg LIST` | all | Comma-separated rating-group filter |
| `--apn LIST` | config `apn_filter` | Comma-separated APN filter |

All tools honor the `FREE_RG_CONFIG` environment variable to point at an
alternative `config.yaml` (useful for separate laptop/server configs).

## Troubleshooting

- **"No CSVs found"** — Run `daily_update.py` first, or check the `data/free_rg_*` folders.
- **Kerberos errors** — Renew your ticket before running. The script exits with a clear message if the ticket is missing/expired.
- **Empty charts** — Check that `apn_filter` in `config.yaml` matches the APN values in your data.
