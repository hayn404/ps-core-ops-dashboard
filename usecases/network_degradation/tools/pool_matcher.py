"""
pool_matcher.py
----------------
Loads config/ip_pools.csv (exported from the manager's ip_pools.xlsx) and
resolves each pool's Start-IP/End-IP range(s) to the subnet-prefix
granularity network_degradation's ClickHouse tables group by:
  - IPv4: first 3 dotted-decimal octets  (e.g. "10.29.0")   — one /24
  - IPv6: first 3 OR 4 colon-separated hextets, DEPENDING ON THE POOL —
    see note below.

IPv6 pools are NOT all the same size. Auditing the sheet found two
patterns:
  - Some pools are scoped to exactly one /64 (the 4th hextet is fixed,
    e.g. Start=2c0f:fc88:4:b2:: End=...b2:ffff:ffff:ffff:ffff).
  - Others are scoped to an entire /48 (the 4th hextet is fully free,
    0000-ffff — the pool covers ALL of it), e.g. a range whose 4th
    hextet spans its full 65,536-value range.
Naively enumerating "every /64 in the range" treats the second kind as
65,536 separate prefixes (this crashed the process with OOM the first
time — ~93 million strings across the sheet). Instead, this uses
ipaddress.summarize_address_range() to find each section's true CIDR
block(s), then derives how many hextets are actually FIXED (prefixlen //
16, when prefixlen is a clean multiple of 16) — a /48-scoped pool gets a
3-hextet key, a /64-scoped pool gets a 4-hextet key. Matching against
ClickHouse then truncates the stored 4-hextet prefix down to whatever
depth each pool actually needs.

Also resolves each pool's short GW code (e.g. "ODG21") to the full `ugw`
label network_degradation stores (e.g. "AlexPost_ODG21") by suffix match,
since that's the only relationship between the two naming schemes.
"""

import csv
import ipaddress
import os
from collections import defaultdict

POOLS_CSV = os.path.join(os.path.dirname(__file__), "..", "config", "ip_pools.csv")


def _ipv4_prefixes(start_ip: str, end_ip: str) -> "set[str]":
    s = int(ipaddress.IPv4Address(start_ip))
    e = int(ipaddress.IPv4Address(end_ip))
    prefixes = set()
    for top in range(s >> 8, (e >> 8) + 1):
        octets = [(top >> 16) & 0xFF, (top >> 8) & 0xFF, top & 0xFF]
        prefixes.add(".".join(str(o) for o in octets))
    return prefixes


def _hextets_no_pad(addr_int: int, n: int) -> str:
    """First n 16-bit groups of a 128-bit int, lowercase hex, NOT
    zero-padded — matches Spark's raw string SPLIT() on an uncompressed
    textual address, which is what network_degradation's Hive query
    actually does (NOT Python's zero-padded ipaddress.exploded format)."""
    groups = []
    for i in range(n):
        shift = (7 - i) * 16
        groups.append(format((addr_int >> shift) & 0xFFFF, "x"))
    return ":".join(groups)


def _ipv6_keys(start_ip: str, end_ip: str) -> "set[tuple[int, str]]":
    """Return {(depth, prefix_at_that_depth), ...} for a section — usually
    exactly one entry, occasionally a few if the range isn't a single
    clean CIDR block (summarize_address_range then returns >1 network)."""
    s = ipaddress.IPv6Address(start_ip)
    e = ipaddress.IPv6Address(end_ip)
    keys = set()
    for net in ipaddress.summarize_address_range(s, e):
        if net.prefixlen % 16 == 0 and net.prefixlen > 0:
            depth = net.prefixlen // 16
            depth = min(depth, 4)  # never finer than the /64 ClickHouse stores
            keys.add((depth, _hextets_no_pad(int(net.network_address), depth)))
        else:
            # Not hextet-aligned (unusual for provisioned pools) — fall
            # back to the coarsest safe assumption, /48, rather than
            # silently enumerating a potentially huge range.
            keys.add((3, _hextets_no_pad(int(net.network_address), 3)))
    return keys


def load_pools(csv_path: str = POOLS_CSV) -> "list[dict]":
    """Return one dict per (pool_name, section) row. IPv4 rows get a
    'prefixes' set (exact /24 strings); IPv6 rows get a 'keys' set of
    (depth, prefix) tuples, per the granularity note above."""
    sections = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            vpn = (row["vpn_instance"] or "").lower()
            if "ipv6" in vpn:
                family = "ipv6"
            elif "ipv4" in vpn:
                family = "ipv4"
            else:
                continue  # not an addressable pool (rare non-IP VPN rows)
            try:
                if family == "ipv4":
                    entry = {"prefixes": _ipv4_prefixes(row["start_ip"], row["end_ip"])}
                else:
                    entry = {"keys": _ipv6_keys(row["start_ip"], row["end_ip"])}
            except ValueError as e:
                print(f"  [pool_matcher] skipping {row['pool_name']} "
                      f"section {row['section']}: {e}")
                continue
            entry.update({
                "pool_name": row["pool_name"],
                "path": row["path"],
                "gw": row["gw"],
                "apn": row["apn"],
                "family": family,
            })
            sections.append(entry)
    return sections


def build_ipv4_index(sections: "list[dict]") -> "dict[tuple[str, str], set[str]]":
    """(gw_short_code, '/24 prefix') -> set of pool_names claiming it."""
    idx = defaultdict(set)
    for s in sections:
        if s["family"] != "ipv4":
            continue
        for p in s["prefixes"]:
            idx[(s["gw"], p)].add(s["pool_name"])
    return idx


def build_ipv6_index(sections: "list[dict]") -> "dict[tuple[str, int, str], set[str]]":
    """(gw_short_code, depth, prefix_at_depth) -> set of pool_names.

    depth is 3 or 4 hextets — callers must check both depths against each
    ClickHouse row (truncate its 4-hextet prefix to 3 and look up depth=3,
    then also look up depth=4 with the full value) since pools can be
    scoped at either granularity.
    """
    idx = defaultdict(set)
    for s in sections:
        if s["family"] != "ipv6":
            continue
        for depth, prefix in s["keys"]:
            idx[(s["gw"], depth, prefix)].add(s["pool_name"])
    return idx


def gw_short_code(ugw_label: str) -> str:
    """'AlexPost_ODG21' -> 'ODG21' — network_degradation's ugw labels are
    always '<Site><Role>_<ShortCode>'; the short code is what the pool
    sheet's GW column uses."""
    return ugw_label.rsplit("_", 1)[-1] if "_" in ugw_label else ugw_label


if __name__ == "__main__":
    # Quick self-check when run directly: load the sheet, report basic
    # coverage stats without needing a ClickHouse connection.
    sections = load_pools()
    pools = {s["pool_name"] for s in sections}
    print(f"Loaded {len(sections)} pool sections, {len(pools)} distinct pools")

    v4_idx = build_ipv4_index(sections)
    v4_shared = {k: v for k, v in v4_idx.items() if len(v) > 1}
    print(f"IPv4: {len(v4_idx)} distinct (gw, /24) keys, "
          f"{len(v4_shared)} claimed by more than one pool")

    v6_idx = build_ipv6_index(sections)
    v6_shared = {k: v for k, v in v6_idx.items() if len(v) > 1}
    by_depth = defaultdict(int)
    for (gw, depth, prefix) in v6_idx:
        by_depth[depth] += 1
    print(f"IPv6: {len(v6_idx)} distinct (gw, depth, prefix) keys "
          f"({dict(by_depth)} by depth), "
          f"{len(v6_shared)} claimed by more than one pool")
