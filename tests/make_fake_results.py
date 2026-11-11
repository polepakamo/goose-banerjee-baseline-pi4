#!/usr/bin/env python3
"""Generate SYNTHETIC CSVs in the exact format of gs_pub / gs_sub so that
scripts/analyze.py can be tested without hardware. The numbers are random and
mean nothing - never use them in a paper.

    python3 tests/make_fake_results.py /tmp/fake && python3 scripts/analyze.py /tmp/fake
"""
import csv, os, random, sys

out = sys.argv[1] if len(sys.argv) > 1 else "fake_results"
os.makedirs(out, exist_ok=True)
random.seed(1)

MODEL = {  # scheme: (frame, gen mean, proc mean)
    "none": (202, 24.0, 5.0),
    "banerjee": (261, 28.0, 13.0),
}
WARM, N = 100, 2000

for scheme, (frame, g, p) in MODEL.items():
    for run in range(1, 6):
        drift = random.gauss(0, 0.3)
        with open(f"{out}/perf_{scheme}_r{run}.pub.csv", "w", newline="") as fp, \
             open(f"{out}/perf_{scheme}_r{run}.sub.csv", "w", newline="") as fs:
            wp = csv.writer(fp); ws = csv.writer(fs)
            wp.writerow("idx,warmup,newstate,frame_len,t_inc_us,t_gen_us,t_tx_us".split(","))
            ws.writerow("idx,warmup,stNum,sqNum,frame_len,verdict,t_proc_us".split(","))
            st, sq = 1, 0
            for i in range(WARM + N):
                new = (i % 8 == 0)
                if new:
                    st += 1; sq = 0
                wp.writerow([i, int(i < WARM), int(new), frame, 0.4,
                             round(max(1, random.gauss(g + drift, 1.5)), 3), round(frame * 8 / 1e8 * 1e6, 3)])
                ws.writerow([i, int(i < WARM), st, sq, frame, 0,
                             round(max(1, random.gauss(p + drift, 1.2)), 3)])
                sq += 1

# security
for scen in ["replay", "forge", "flood"]:
    for cfg in ["banerjee", "banerjee-strict"]:
        pubn = 2000
        with open(f"{out}/sec_{scen}_{cfg}.pub.csv", "w", newline="") as fp, \
             open(f"{out}/sec_{scen}_{cfg}.sub.csv", "w", newline="") as fs:
            wp = csv.writer(fp); ws = csv.writer(fs)
            wp.writerow("idx,warmup,newstate,frame_len,t_inc_us,t_gen_us,t_tx_us".split(","))
            ws.writerow("idx,warmup,stNum,sqNum,frame_len,verdict,t_proc_us".split(","))
            for i in range(pubn):
                wp.writerow([i, 0, 0, 261, 0.4, 28.0, 20.9])
                ws.writerow([i, 0, 2 + i // 8, i % 8, 261, 0, 12.0])
            n = 200
            for j in range(n):
                if scen == "forge":
                    v = 1
                elif cfg == "banerjee":
                    v = 0
                else:
                    v = 2
                ws.writerow([pubn + j, 0, 2, j % 8, 261, v, 9.0 if v else 13.0])
print("wrote", out)
