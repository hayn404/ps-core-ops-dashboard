# PS Core Operations Dashboard

One port (8820), several dashboards. Linux server (10.80.90.130), Python 3.9, ClickHouse as the data layer.

```
http://10.80.90.130:8820/                   ONE page: sidebar with a tab per dashboard, the selected dashboard beside it
http://10.80.90.130:8820/network-degradation/   Network Service Degradation (IPv6 | IPv4 | Pools | Sites)
http://10.80.90.130:8820/free-rg-smart-care/    Free RGs Smart Care
```

## Network Degradation: how the data flows

```
Hive (sdr_nethouse) --etl.py fetch--> RAW tables in ClickHouse
                                          network_degradation_ipv6 / _ipv4 / _site / _site_cells
                                                |  etl.py transform  (pure SQL inside ClickHouse)
                                                v
                                     TABLES THE DASHBOARD READS
   nd_subnet_hourly   IPv6 rolled up to /48 + IPv4 /24, peer baseline and sr_drop precomputed
   nd_pool_hourly     TCP SR / FR2 per IP pool per hour, baseline vs same-type pools of other gateways
   nd_pool_daily      ONE TCP FR2 / SR number per pool per day (what the manager asked for)
   nd_subnet_degraded subnets that fell from THEIR OWN normal and stayed down for days (IPv6/IPv4 tabs list this)
   nd_site_hourly     site-level FR3 per hour        nd_site_baseline  each site's own normal level
   nd_cell_daily      per-cell FR3, queried per site when you click a site
                                     DIMENSIONS / STATE
   nd_subnet_pool     which pool each subnet (IPv4 /24, IPv6 /48) belongs to -> 'degraded subnets by pool'
   dim_pool           pools from config/ip_pools.csv
   nd_subnet_pool_map subnet -> pool(s); each new subnet is resolved once
   nd_ingest_log      which Hive tables were already loaded (replaces the old state file + CSVs)
```

The dashboard never touches Hive or files - it only runs `SELECT`s on the tables above.
That is why the IPv6 tab is back to /48 (about 140 subnets) even though RAW keeps /64:
the roll-up happens once per day in `etl.py`, not on every page load.

### Project layout (everything else from the old version can be deleted)

```
ps-core-ops-dashboard/
  hub.py                                   serves everything on :8820 (sidebar shell + both dashboards)
  requirements.txt
  tools/
    clickhouse_io.py                       shared ClickHouse helper
    run_daily_update.sh                    the ONE cron entry (kinit + both use cases)
    run_hub.sh                             foreground launcher for testing
    ps-core-ops-dashboard.service          systemd unit (production)
  usecases/
    network_degradation/
      etl.py                               the only data script (fetch + transform + pools)
      dashboard.py                         UI, reads ClickHouse tables only
      config/config.yaml, config/ip_pools.csv
    free_rg_smart_care/                    unchanged (only its .bat file is gone)
```

## Deploy (first time)

1. Copy this folder over the project on the server. It contains no data, so nothing is overwritten
   except code. Delete the old files listed at the bottom.
2. Build the dashboard tables from the RAW data that is already in ClickHouse (no Hive, no Kerberos).
   Takes roughly 15-40 min for 30 days, so run it detached:
   ```
   cd usecases/network_degradation
   nohup python3.9 etl.py transform --days 30 --rebuild > /tmp/etl_first.log 2>&1 &
   tail -f /tmp/etl_first.log          # one "[transform] <day>: ..." line per day
   python3.9 etl.py status             # row counts per table when it is done
   ```
3. Restart the dashboard: `sudo systemctl restart ps-core-ops-dashboard`
4. Cron stays as it is (`tools/run_daily_update.sh`); it now calls `etl.py daily`.

## Daily / operations (run from usecases/network_degradation, python3.9)

| Command | What it does |
|---|---|
| `python3.9 etl.py daily` | what cron runs: load new complete days from Hive, then build every derived table for them |
| `python3.9 etl.py status` | table sizes and day ranges |
| `python3.9 etl.py fetch --check` | test the Hive connection / tables / site map (needs kinit) |
| `python3.9 etl.py fetch --backfill 10` | pull older days missing from ClickHouse |
| `python3.9 etl.py transform --days 30 --rebuild` | rebuild derived tables from RAW (no Hive) |
| `python3.9 etl.py transform --date 2026-08-30 --parts pool` | rebuild one part of one day |
| `python3.9 etl.py pools` | after editing `config/ip_pools.csv`: reload pools and rebuild pool tables |

`daily` is self-healing: any day present in RAW but missing from the derived tables is built on the next run,
and re-running a day replaces its rows (no duplicates). If Hive is down, `daily` still rebuilds from what is in ClickHouse.

Manager's per-pool daily number:
```sql
SELECT report_date, pool_id, session_count, owner_sessions, round(tcp_fr2,2) AS tcp_fr2, round(tcp_sr,2) AS tcp_sr
FROM ps_core_ops.nd_pool_daily WHERE locked = 0 ORDER BY report_date, pool_id;
```
Add pools together with `owner_sessions`, never `session_count` (a subnet inside two overlapping pools is
counted in both `session_count`s but only once in `owner_sessions`).

## Pool view of degraded subnets (manager's request)

On the IPv6 and IPv4 tabs every degraded subnet now shows its IP pool, and the left panel starts with a
table **"Degraded subnets grouped by IP pool"**: pool, degraded subnets, subnets in pool, % of pool, worst drop.
Two or more degraded subnets in one pool (orange) or half the pool degraded (red) points to a pool-level problem.
There is also a "Pools affected" card, and the CSV export has a Pool column. The **Pools** tab shows the
pools' own TCP SR / FR2 trend.

If you already deployed the previous version, apply this one with:
`python3.9 etl.py transform --days 30 --rebuild --parts pool` (builds `nd_subnet_pool`), then restart the dashboard.

## Which subnets count as "degraded" (IPv6 / IPv4 tabs)

Decided in `etl.py` (`find_sustained_drops`, tunables `SUST_*` at the top), stored in `nd_subnet_degraded`,
rebuilt on every `transform`/`daily`. The dashboard only filters that table. A subnet is listed only if it
fell from **its own** normal (median of its previous 7 days) and stayed down:
* not listed: always ~0 SR (own normal < 50%), naturally fluctuating (range of its normal days > 25 pts, or the
  drop is not bigger than 1.5x that range), too new (< 4 reference days), short blip (< 3 consecutive down days)
* traffic rule: the subnet's average daily sessions while down must be >= 70% of its normal (`SUST_MIN_TRAFFIC_PCT`).
  Fewer users = the SR fell because of lost traffic, so it is NOT listed. Only session counts exist in the data (no upload bytes)
* a "down" day = daily SR >= 10 pts (slider: 10-40) below its normal AND SR <= 60% (failure rate >= 40%)
* View dropdown: *Currently impacted* = still down on the latest day, *Recovered* = was down, back to normal
* re-run only the detector after changing thresholds: `python3.9 etl.py transform --parts degraded`
* why is subnet X not listed? `python3.9 etl.py explain` (counts per excluding rule + the near-misses)
* test: `python3.9 test_sustained.py` (synthetic data, no database needed)

## Rules baked into the pool tables

* Overlapping pools (primary vs its LOCKed `red_p` twin, `new_*_to_rp_*`) each get the full traffic of their range;
  `owner_sessions` counts every subnet once, under its most specific pool. Locked twins are hidden in the Pools tab.
* Sessions on a gateway using another gateway's addresses are attributed to the owning pool (`cross_gw_sessions`).
* UPF gateways are out of scope (the 7 non-UPF gateways only).
* Pools tab hides pools under 50,000 sessions/hour (`MIN_POOL_SESSIONS` in `etl.py` and `dashboard.py`).
* Baselines: subnets vs the 75th percentile of the same gateway + family + hour; pools vs same-type pools of
  other gateways at the same hour; sites vs their own best-quarter hours of the last 10 days.
* Pool/subnet volumes only include subnets the Hive query keeps (>= 200 sessions per hour per /64).

## Delete on the server (superseded)

```
usecases/network_degradation/tools/          (daily_update.py, compare_days.py, generate_data_sql.py,
                                              discover_gw_ids*.py, compute_pool_fr2.py, pool_matcher.py, *.bat ...)
usecases/network_degradation/data/           (old CSV exports)
usecases/network_degradation/README.md, apply_ipv6_rollup_patch.py, pools_out/
usecases/free_rg_smart_care/tools/run_daily_update.bat
```
