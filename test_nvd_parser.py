"""
Quick smoke-test for the nvdtrans processor.
Run from the FYP root directory:
  python test_nvd_parser.py

Does NOT require a database or Flask — pure parsing test.
"""

import sys
import os
import importlib.util

# Import the processor module directly without going through app/__init__.py
def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

PROC_PATH = os.path.join(
    os.path.dirname(__file__), "backend", "app", "ml", "nvdtrans_processor.py"
)
proc = _load_module("nvdtrans_processor", PROC_PATH)

FILES = [
    r"C:\Users\Dell\Downloads\nvdcve-2025trans.xml\nvdcve-2025trans.xml",
    r"C:\Users\Dell\Downloads\nvdcve-2024trans.xml\nvdcve-2024trans.xml",
    r"C:\Users\Dell\Downloads\nvdcve-2023trans.xml\nvdcve-2023trans.xml",
]

total = 0
priority_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

for fpath in FILES:
    if not os.path.isfile(fpath):
        print(f"[SKIP] {fpath}")
        continue

    fname = os.path.basename(fpath)
    print(f"\nParsing {fname} ...", flush=True)
    records = proc.parse_nvdtrans_file(fpath)
    print(f"  Extracted {len(records):,} usable records")

    for r in records[:3]:
        print(f"  {r['cve_id']:20s}  score={r['cvss_score']:.1f}"
              f"  priority={r['priority']:8s}"
              f"  av={r['attack_vector']}  ac={r['attack_complexity']}"
              f"  cwe={r['cwe_number']}")

    for r in records:
        priority_counts[r["priority"]] = priority_counts.get(r["priority"], 0) + 1
    total += len(records)

print(f"\n{'='*50}")
print(f"Total usable records across all files: {total:,}")
print("\nClass distribution:")
for p in ["Critical", "High", "Medium", "Low"]:
    n = priority_counts.get(p, 0)
    pct = n / total * 100 if total else 0
    bar = "#" * int(pct / 2)
    print(f"  {p:10s}: {n:5,}  ({pct:5.1f}%)  {bar}")
