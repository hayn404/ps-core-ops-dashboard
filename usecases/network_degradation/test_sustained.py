"""Test of the sustained-drop detector in etl.py (synthetic data, no ClickHouse/Hive needed).
Run from anywhere inside the project:  python3.9 test_sustained.py"""
import importlib.util, os, sys
from unittest.mock import MagicMock
import numpy as np, pandas as pd

for mod in ("yaml", "clickhouse_io"):           # not needed for the pure logic
    try: __import__(mod)
    except Exception: sys.modules[mod] = MagicMock()

def _find_etl():
    here = os.path.dirname(os.path.abspath(__file__))
    for base in (here, os.path.dirname(here), os.path.join(here, "proj")):
        for root, _d, files in os.walk(base):
            if root.endswith(os.path.join("usecases", "network_degradation")) and "etl.py" in files:
                return os.path.join(root, "etl.py")
    sys.exit("etl.py not found - put this script inside the project")
ETL = _find_etl()
sys.path.insert(0, os.path.join(os.path.dirname(ETL), "..", "..", "tools"))
spec = importlib.util.spec_from_file_location("etl_mod", ETL)
etl = importlib.util.module_from_spec(spec); spec.loader.exec_module(etl)

rng = np.random.default_rng(1)
DAYS, start = 14, pd.Timestamp("2026-10-01")
def daily(f, first=0): return {d: f(d) for d in range(first, DAYS)}
cases = {
 "A_real_drop_current":   daily(lambda d: 97 + rng.normal(0,1) if d < 10 else 20 + rng.normal(0,3)),
 "B_always_zero":         daily(lambda d: abs(rng.normal(0.5,0.3))),
 "C_fluctuating":         daily(lambda d: rng.uniform(25, 95)),
 "D_one_day_blip":        daily(lambda d: 97 if d != 11 else 10),
 "E_dropped_then_recovered": daily(lambda d: 20 if 5 <= d <= 8 else 96 + rng.normal(0,1)),
 "F_new_subnet_low":      daily(lambda d: 15, first=11),
 "G_fluct_then_lower":    daily(lambda d: rng.uniform(40, 95) if d < 10 else 5),
 "H_mild_noise_big_drop": daily(lambda d: 90 + rng.normal(0,3) if d < 11 else 55 + rng.normal(0,2)),
 "I_small_drop_8pts":     daily(lambda d: 97 if d < 9 else 89),
 "J_drop_2days_only":     daily(lambda d: 95 if d < 12 else 20),
 "K_80_to_30_5days":      daily(lambda d: 80 + rng.normal(0,2) if d < 9 else 30 + rng.normal(0,2)),
 "L_drop_but_users_left": daily(lambda d: 96 + rng.normal(0,1) if d < 10 else 25 + rng.normal(0,2)),
 "M_drop_users_same":     daily(lambda d: 96 + rng.normal(0,1) if d < 10 else 25 + rng.normal(0,2)),
 "N_drop_users_80pct":    daily(lambda d: 96 + rng.normal(0,1) if d < 10 else 25 + rng.normal(0,2)),
}
# sessions multiplier per day (default 1.0): L loses 80% of its users when SR drops
traffic = {"L_drop_but_users_left": lambda d: 1.0 if d < 10 else 0.2,
           "N_drop_users_80pct":    lambda d: 1.0 if d < 10 else 0.8}
# hourly frame (what nd_subnet_hourly holds) -> daily rows exactly like build_degraded's SQL
hours = []
for name, series in cases.items():
    for d, sr in series.items():
        for hh in range(24):
            hours.append((name, start + pd.Timedelta(days=d, hours=hh), int(rng.integers(500, 3000) * traffic.get(name, lambda d: 1.0)(d)),
                          float(np.clip(sr + rng.normal(0, 1.5), 0, 100))))
H = pd.DataFrame(hours, columns=["prefix", "hour", "sc", "sr"])
H["day"] = H["hour"].dt.normalize(); H["w"] = H["sr"] * H["sc"]
D = H.groupby(["prefix", "day"]).agg(w=("w","sum"), sc=("sc","sum"), hrs=("hour","nunique")).reset_index()
D["sr"] = D["w"] / D["sc"]; D["ugw"] = "GW1"

# 1) pure detector
runs = etl.find_sustained_drops(D)
cur = set(runs[runs.is_current == 1].prefix); rec = set(runs[runs.is_current == 0].prefix)
print(runs.sort_values("max_sr_drop", ascending=False).to_string(index=False))
assert cur == {"A_real_drop_current", "H_mild_noise_big_drop", "K_80_to_30_5days",
               "M_drop_users_same", "N_drop_users_80pct"}, cur
assert "L_drop_but_users_left" not in set(runs.prefix)      # fewer users -> not a degradation
assert runs.set_index("prefix").loc["N_drop_users_80pct", "traffic_pct"] > 70
assert rec == {"E_dropped_then_recovered"}, rec

# 2) build_degraded end to end against a fake ClickHouse client
class FakeC:
    def __init__(self): self.inserted = None; self.cmds = []
    def command(self, sql): self.cmds.append(sql)
    def insert_df(self, table, df): self.inserted = (table, df)
    def query(self, sql):
        r = MagicMock()
        if "GROUP BY ugw, ip_version, prefix, report_date" in sql:
            r.result_rows = [("GW1", "IPv6", x.prefix, str(x.day.date()), x.w, x.sc, x.hrs) for x in D.itertuples()]
        else:
            r.result_rows = [("GW1", x.prefix, x.hour.tz_localize("Africa/Cairo").to_pydatetime(), x.sr, 100 - x.sr) for x in H.itertuples()]  # tz-aware like the real client
        return r
fc = FakeC()
n = etl.build_degraded(fc)
tbl, out = fc.inserted
assert tbl == "nd_subnet_degraded" and n == len(out) == 6, (tbl, n)
assert set(out.prefix) == cur | rec and (out.ip_version == "IPv6").all()
assert out.worst_hour.notna().all() and out.first_appeared.notna().all()
print("\nbuild_degraded inserted", n, "rows; columns:", list(out.columns))
# 3) explain() runs and classifies the "users left" subnet
fc2 = FakeC(); fc2.query = FakeC.query.__get__(fc2)
import io, contextlib
buf = io.StringIO()
with contextlib.redirect_stdout(buf): etl.explain_current(fc2)
txt = buf.getvalue()
assert "fewer users" in txt and "L_drop_but_users_left" in txt and "FLAGGED" in txt, txt
print(txt)
print("ASSERTIONS PASSED")
