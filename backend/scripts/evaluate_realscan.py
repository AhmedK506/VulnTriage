"""
Real-target Confidence Engine evaluation.

This harness reports the Confidence Engine's behaviour on a REAL scan stored in
a VulnTriage database — the actual confidence scores it assigned, the
classification bands, and the PoC validator's objective active-confirmation
results.

Ground-truth anchors used here are objective, not hand-labelled:
  • PoC active confirmation — the validator probed the live app (e.g. a SQLi
    payload returning an SQL error) and objectively confirmed the finding.
  • Scanner-assigned Informational severity — pure technology-detection output
    (fingerprints, banners) that is not an actionable vulnerability.

Note (transparency): poc_validation is one of the engine's six scoring factors,
so this measures the end-to-end triage outcome on a real target, i.e. how well
the engine *prioritises* genuine findings above informational noise — not an
independent predictor.

Run:
  cd backend && python -m scripts.evaluate_realscan <path-to-scan.db>
"""

import sqlite3
import sys


def _mean(xs):
    return sum(xs) / len(xs) if xs else 0.0


def main(db_path):
    c = sqlite3.connect(db_path)
    rows = c.execute("""
        select nf.id, nf.title, nf.severity, nf.cwe_id, cs.score, cs.classification
        from normalized_findings nf
        join confidence_scores cs on cs.finding_id = nf.id
        order by cs.score desc
    """).fetchall()
    poc = {r[0] for r in c.execute(
        "select distinct finding_id from poc_validations where result='confirmed'")}

    total = len(rows)
    confirmed = [r for r in rows if r[5] == "Confirmed"]
    review = [r for r in rows if r[5] == "Needs Manual Verification"]
    not_conf = [r for r in rows if r[5] == "Not Confirmed"]
    info = [r for r in rows if r[5] == "Informational"]
    poc_scores = [r[4] for r in rows if r[0] in poc]
    noise_scores = [r[4] for r in rows if r[5] == "Informational"]

    print("=" * 62)
    print("  VulnTriage - Confidence Engine on a REAL scan")
    print("=" * 62)
    print(f"  Target        : OWASP Juice Shop (deliberately vulnerable app)")
    print(f"  Scanners      : OWASP ZAP + Nuclei")
    print(f"  Findings      : {total}")
    print("-" * 62)
    print("  Classification band breakdown")
    print(f"    Confirmed (>=70)              : {len(confirmed):>2}")
    print(f"    Needs Manual Verification     : {len(review):>2}")
    print(f"    Not Confirmed (<40)           : {len(not_conf):>2}")
    print(f"    Informational                 : {len(info):>2}")
    print("-" * 62)
    print("  Objective active confirmation (PoC validator)")
    print(f"    PoC-confirmed findings        : {len(poc)}")
    print(f"    ...all placed in Confirmed band: "
          f"{'YES' if all(r[5] == 'Confirmed' for r in rows if r[0] in poc) else 'no'}")
    print(f"    mean confidence (PoC-confirmed): {_mean(poc_scores):.1f}")
    print(f"    mean confidence (Informational): {_mean(noise_scores):.1f}")
    lo_conf = min((r[4] for r in confirmed), default=0)
    hi_rest = max((r[4] for r in rows if r[5] != "Confirmed"), default=0)
    print(f"    lowest Confirmed {lo_conf:.1f} vs highest non-Confirmed {hi_rest:.1f}"
          f"  -> {'clean separation' if lo_conf > hi_rest else 'overlap'}")
    print("-" * 62)
    print("  Ranked findings (real confidence scores)")
    print(f"  {'score':>6}  {'band':<14} {'sev':<13} {'PoC':<4} title")
    for _id, title, sev, cwe, score, cls in rows:
        tag = "yes" if _id in poc else "-"
        band = {"Confirmed": "Confirmed", "Needs Manual Verification": "Review",
                "Not Confirmed": "NotConfirmed", "Informational": "Informational"}.get(cls, cls)
        print(f"  {score:>6.1f}  {band:<14} {sev:<13} {tag:<4} {title[:40]}")
    print("=" * 62)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "instance/vulntriage.db")
