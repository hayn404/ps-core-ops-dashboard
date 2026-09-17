"""
discover_gw_ids_v2.py
-----------------------
discover_gw_ids.py's row-count-matching was too unreliable with 33
unlabeled candidate IDs in the mix (many clearly unrelated enterprise/POS
gateways — SUPERPAY, AMAN, FRANCHISE, MASARYPOS APNs have nothing to do
with the 4 missing consumer mobile gateways). This is more reliable: for
each candidate ggsn_pgw_id, sample real session IPs (ms_ip_pa) and check
which pool's IP range (from config/ip_pools.csv) they actually fall
inside. A gateway's pool assignment is definitional — real session IPs
under the true R1DG18 will fall inside R1DG18's declared pool ranges, not
by coincidence.

Run from the repo root (needs both usecases/network_degradation/dashboard
imports AND config/ip_pools.csv):
    kinit -kt "/etc/security/keytabs/ossuser.keytab" ossuser@HADOOP.COM
    python3.9 usecases/network_degradation/tools/discover_gw_ids_v2.py
"""

import csv
import ipaddress
import os
import sys

import pandas as pd

_HERE = os.path.dirname(os.path.abspath(__file__))   # .../network_degradation/tools
REPO_ROOT = os.path.dirname(_HERE)                    # .../network_degradation
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from dashboard import connect_db, discover_tables, load_config, GATEWAY_MAP  # noqa: E402

POOLS_CSV = os.path.join(REPO_ROOT, "config", "ip_pools.csv")

# Already-labeled IDs — skip these, we only need to identify the rest.
KNOWN_IDS = set(GATEWAY_MAP.keys())

# Candidates worth checking: ETISALAT-dominant traffic profile (matches
# the pattern of every already-known consumer gateway), picked from the
# discover_gw_ids.py output rather than checking all 33 unlabeled IDs.
# If none of these turn out to be a match, widen this list.
CANDIDATE_IDS = [200044, 200031, 200067, 200039, 200057, 200022, 31, 30, 43]

MISSING_GW_CODES = ["R1DG18", "YDG29", "YDG30", "TGG14"]


def load_pool_ranges():
    """gw_code -> list of (start_int, end_int, family) for exact
    containment checks — deliberately NOT using pool_matcher's prefix
    index here, since we want to check raw IPs against the exact declared
    range, with no granularity approximation."""
    ranges = {}
    with open(POOLS_CSV, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            gw = row["gw"]
            vpn = (row["vpn_instance"] or "").lower()
            try:
                if "ipv4" in vpn:
                    s = int(ipaddress.IPv4Address(row["start_ip"]))
                    e = int(ipaddress.IPv4Address(row["end_ip"]))
                    fam = "ipv4"
                elif "ipv6" in vpn:
                    s = int(ipaddress.IPv6Address(row["start_ip"]))
                    e = int(ipaddress.IPv6Address(row["end_ip"]))
                    fam = "ipv6"
                else:
                    continue
            except ValueError:
                continue
            ranges.setdefault(gw, []).append((s, e, fam))
    return ranges


def find_owning_gw(ip_str: str, pool_ranges: dict) -> "str | None":
    try:
        if ":" in ip_str:
            val = int(ipaddress.IPv6Address(ip_str))
            fam = "ipv6"
        else:
            val = int(ipaddress.IPv4Address(ip_str))
            fam = "ipv4"
    except ValueError:
        return None
    for gw, ranges in pool_ranges.items():
        for s, e, rfam in ranges:
            if rfam == fam and s <= val <= e:
                return gw
    return None


def main():
    pool_ranges = load_pool_ranges()
    print(f"Loaded pool ranges for {len(pool_ranges)} gateways from "
          f"{POOLS_CSV}\n")

    config = load_config()
    conn = connect_db(config)
    tables = discover_tables(conn, "sdr_nethouse",
                              "sdr_dyn_ide_soc_tcp_user_15m_%")
    latest = sorted(tables)[-1]
    print(f"Using most recent table: {latest}\n")

    ids_sql = ", ".join(str(i) for i in CANDIDATE_IDS)
    sql = f"""
        SELECT ggsn_pgw_id, ms_ip_pa
        FROM {latest}
        WHERE ggsn_pgw_id IN ({ids_sql})
        LIMIT 20000
    """
    print("Sampling session IPs for candidate gateway IDs "
          f"{CANDIDATE_IDS} ...")
    df = pd.read_sql(sql, conn)
    print(f"Sampled {len(df):,} rows\n")

    for gw_id, group in df.groupby("ggsn_pgw_id"):
        matches = {}
        checked = 0
        for ip in group["ms_ip_pa"].dropna().head(500):
            owner = find_owning_gw(str(ip), pool_ranges)
            checked += 1
            if owner:
                matches[owner] = matches.get(owner, 0) + 1
        if not matches:
            print(f"ggsn_pgw_id={gw_id}: {checked} IPs checked, "
                  f"no pool match found")
            continue
        best_gw, best_count = max(matches.items(), key=lambda kv: kv[1])
        confidence = best_count / checked if checked else 0
        flag = " <-- LIKELY MATCH" if confidence > 0.8 else ""
        print(f"ggsn_pgw_id={gw_id}: {checked} IPs checked -> "
              f"best match {best_gw} ({best_count}/{checked} = "
              f"{confidence:.0%}){flag}")
        if len(matches) > 1:
            others = {k: v for k, v in matches.items() if k != best_gw}
            print(f"    (other partial matches: {others})")

    print("\nFor whichever of R1DG18/YDG29/YDG30/TGG14 show up as a "
          ">80% match above, add that (id, name) pair to GATEWAY_MAP in "
          "dashboard.py. If a target gateway doesn't appear here at all, "
          "tell me and I'll widen CANDIDATE_IDS and re-run.")


if __name__ == "__main__":
    main()
