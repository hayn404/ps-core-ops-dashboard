"""
Generate the SQL needed to populate the dashboard.

Usage:
    python tools/generate_data_sql.py                                  # default: all tables May 1 -> today, batches of 5
    python tools/generate_data_sql.py --start 20574 --end 20619        # explicit table range
    python tools/generate_data_sql.py --family ipv4                    # IPv4 instead of IPv6
    python tools/generate_data_sql.py --batch-size 3                   # smaller batches if timeouts persist
    python tools/generate_data_sql.py --batch-size 0                   # produce ONE giant UNION ALL

It prints the SQL to stdout. Pipe it to a file if you want:
    python tools/generate_data_sql.py > queries.sql
"""

import argparse
import os

TABLE_PREFIX = "sdr_nethouse.sdr_dyn_ide_soc_tcp_user_15m_"
START_DATE   = "2026-05-01 00:00:00"

GW_CASE = """CASE ggsn_pgw_id
        WHEN 27 THEN 'RamsisPost_PDG25' WHEN 200036 THEN 'RamsisPost_PDG25'
        WHEN 20 THEN 'Aburawash_R1DG28' WHEN 200042 THEN 'Aburawash_R1DG28'
        WHEN 19 THEN 'Banisuif_FGG13'   WHEN 200019 THEN 'Banisuif_FGG13'
        WHEN 41 THEN 'SV_UDG01'         WHEN 200053 THEN 'SV_UDG01'
        WHEN 26 THEN 'AlexPost_ODG21'   WHEN 200028 THEN 'AlexPost_ODG21'
        WHEN 1  THEN 'AlexAuto_XGG09'   WHEN 200015 THEN 'AlexAuto_XGG09'
        ELSE CAST(ggsn_pgw_id AS STRING)
    END"""

GW_IN  = "(27,200036, 20,200042, 19,200019, 41,200053, 26,200028, 1,200015)"

IPV6_PREFIX_SQL = (
    "CONCAT(SPLIT(ms_ip_pa,':')[0],':',SPLIT(ms_ip_pa,':')[1],':',SPLIT(ms_ip_pa,':')[2])"
)
IPV4_PREFIX_SQL = "SUBSTRING_INDEX(ms_ip_pa, '.', 3)"

IPV6_FILTER = (
    "AND ms_ip_type_pa = 'IPV6'\n"
    "  AND ms_ip_pa LIKE '2c0f:fc89:%'"
)
IPV4_FILTER = (
    "AND ms_ip_type_pa = 'IPV4'\n"
    "  AND ms_ip_pa <> '0.0.0.0'\n"
    "  AND (\n"
    "          ms_ip_pa LIKE '10.%'\n"
    "       OR ms_ip_pa RLIKE '^172\\\\.(1[6-9]|2[0-9]|3[01])\\\\.'\n"
    "       OR ms_ip_pa RLIKE '^100\\\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\\\.'\n"
    "  )"
)


def per_table_sql(table_num: int, family: str) -> str:
    if family == "ipv6":
        prefix_col = "ipv6_prefix_48"
        prefix_sql = IPV6_PREFIX_SQL
        ip_filter  = IPV6_FILTER
    else:
        prefix_col = "ipv4_prefix_24"
        prefix_sql = IPV4_PREFIX_SQL
        ip_filter  = IPV4_FILTER

    return f"""SELECT
    FROM_UNIXTIME(
        CAST(timecolumn AS BIGINT) - (CAST(timecolumn AS BIGINT) % 3600),
        'yyyy/MM/dd HH:00'
    )                                                                           AS hour,
    {GW_CASE}                                                                  AS ugw,
    {prefix_sql}                                                              AS {prefix_col},
    COUNT(*)                                                                    AS session_count,
    SUM(ide_total_tcpconnsucccount) * 100.0
        / NULLIF(SUM(ide_total_tcpconncount), 0)                               AS tcp_sr,
    SUM(ide_total_tcp_conn_2_failed_times) * 100.0
        / NULLIF(SUM(ide_total_tcp_conn_times), 0)                             AS tcp_fr2
FROM {TABLE_PREFIX}{table_num}
WHERE timecolumn >= unix_timestamp('{START_DATE}')
  {ip_filter}
  AND apn IN ('ETISALAT', 'INTERNET.ETISALAT')
  AND ggsn_pgw_id IN {GW_IN}
GROUP BY
    FROM_UNIXTIME(
        CAST(timecolumn AS BIGINT) - (CAST(timecolumn AS BIGINT) % 3600),
        'yyyy/MM/dd HH:00'
    ),
    ggsn_pgw_id,
    {prefix_sql}
HAVING COUNT(*) >= 200"""


def main():
    ap = argparse.ArgumentParser(description="Generate dashboard-feed SQL")
    ap.add_argument("--start",      type=int, default=20574, help="first table number")
    ap.add_argument("--end",        type=int, default=20619, help="last table number (inclusive)")
    ap.add_argument("--family",     choices=("ipv6", "ipv4"), default="ipv6")
    ap.add_argument("--batch-size", type=int, default=5,
                    help="tables per UNION ALL block (0 = one giant query)")
    ap.add_argument("--out-dir", type=str, default=None,
                    help="if set, write one .sql file per batch into this folder "
                         "(no console output)")
    args = ap.parse_args()

    tables = list(range(args.start, args.end + 1))

    if args.batch_size <= 0:
        # one giant query
        blocks = [per_table_sql(t, args.family) for t in tables]
        sql = "\nUNION ALL\n\n".join(blocks) + ";\n"
        if args.out_dir:
            os.makedirs(args.out_dir, exist_ok=True)
            path = os.path.join(args.out_dir, f"all_{args.family}.sql")
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"-- {len(tables)} tables (from _{args.start} to _{args.end}) for "
                        f"{args.family.upper()}\n\n{sql}")
            print(f"wrote {path}")
        else:
            print(f"-- {len(tables)} tables (from _{args.start} to _{args.end}) for "
                  f"{args.family.upper()}\n")
            print(sql)
        return

    # batched
    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)

    for i in range(0, len(tables), args.batch_size):
        chunk = tables[i:i + args.batch_size]
        batch_num = (i // args.batch_size) + 1
        header = (f"-- Batch {batch_num}: tables _{chunk[0]} -> _{chunk[-1]} "
                  f"({args.family.upper()})\n")
        blocks = [per_table_sql(t, args.family) for t in chunk]
        sql = header + "\n" + "\nUNION ALL\n\n".join(blocks) + ";\n"

        if args.out_dir:
            path = os.path.join(args.out_dir,
                                f"batch_{batch_num:02d}_{args.family}.sql")
            with open(path, "w", encoding="utf-8") as f:
                f.write(sql)
            print(f"wrote {path}")
        else:
            print(f"\n-- ===== Batch {batch_num}: "
                  f"tables _{chunk[0]} -> _{chunk[-1]} =====\n")
            print(sql)


if __name__ == "__main__":
    main()
