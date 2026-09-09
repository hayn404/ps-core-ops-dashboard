# PS Core Operations Dashboard

One dashboard, several use cases, one port (8820):

```
http://<server>:8820/                       -> landing page
http://<server>:8820/network-degradation/   -> Network Service Degradation
http://<server>:8820/free-rg-smart-care/    -> Free RGs Smart Care
```

## How it's structured

Each use case is a fully independent project under `usecases/`, unmodified
in behavior — its own config, its own data folder, its own
`tools/daily_update.py` cron job. `hub.py` at the top level only combines
the already-built Dash apps at the web-server layer: it imports each
`dashboard.py`, calls its `load_and_build(args, url_base_pathname=...)`
function to get back a ready Dash app, and serves a small landing page with
links to each.

```
ps-core-ops-dashboard/
  hub.py                              <- run this; serves everything on :8820
  requirements.txt                    <- union of both use cases' deps
  tools/
    run_hub.sh                        <- quick manual/foreground launcher
    ps-core-ops-dashboard.service      <- systemd unit (production — auto-restart)
  usecases/
    network_degradation/              <- unchanged Network Service Degradation project
      dashboard.py, config/, tools/daily_update.py, tools/run_daily_update.sh, ...
    free_rg_smart_care/                <- unchanged Free RGs Smart Care project
      dashboard.py, config/config.server.yaml, tools/daily_update.py, ...
```

## One-time setup on the server

1. Install dependencies (server has no internet — use the offline wheels):
   ```
   pip install --no-index \
       --find-links usecases/free_rg_smart_care/offline_packages \
       -r requirements.txt
   ```
2. Get a Kerberos ticket, then backfill each use case's data once (each
   `daily_update.py` is unmodified — same command as always):
   ```
   kinit -kt "/etc/security/keytabs/ossuser.keytab" ossuser@HADOOP.COM

   cd usecases/network_degradation && python3.9 tools/daily_update.py --backfill 20 && cd ../..
   cd usecases/free_rg_smart_care && FREE_RG_CONFIG=config/config.server.yaml python3.9 tools/daily_update.py --backfill 20 && cd ../..
   ```
3. Set up ONE cron job for all data fetching — `tools/run_daily_update.sh`
   renews the ticket once and calls both use cases' own `daily_update.py`
   in turn (no duplicated logic, just orchestration):
   ```
   chmod +x tools/run_daily_update.sh
   crontab -e
   15 6 * * * /path/to/ps-core-ops-dashboard/tools/run_daily_update.sh
   ```
   Logs go to `tools/daily_update.log`.
4. Set up the hub itself as a systemd service so it survives crashes and
   reboots (see `tools/ps-core-ops-dashboard.service` for the exact steps).

## Adding a new use case later

1. Build it the same way any of the two existing ones are: a `build_app(...)
   -> Dash` function, plus a `load_and_build(args, url_base_pathname="/") ->
   (app, host, port)` function that does the data loading.
2. Drop the project under `usecases/<name>/`.
3. In `hub.py`, add one `_build_<name>()` function (copy an existing one as
   a template) and one line to the `USE_CASES` list.
4. Add one tile's worth of text — the landing page builds itself from
   `USE_CASES`, no HTML changes needed.

## Local/offline testing without live Hive access

Each use case falls back to CSV data if its `data/` folder (or the paths
passed to `--csv`) already has exported CSVs — `hub.py`'s builder functions
point at each project's own `data/` folder the same way each dashboard's
own `main()` does, so backfilling with `tools/daily_update.py` first (per
use case) is what makes `hub.py` fast and independent of live Hive queries
on every startup.
