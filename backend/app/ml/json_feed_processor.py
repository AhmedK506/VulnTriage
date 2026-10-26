"""
NVD JSON 2.0 Feed Processor

Streams full NVD CVE feeds (NVD API 2.0 schema) and emits training records with
the SAME shape/encoding as `nvdtrans_processor.load_nvdtrans_directory`, so the
ModelTrainer can consume either source interchangeably.

Why this exists
---------------
The Spanish "nvdtrans" XML feed only yields ~800 usable rows and relies on
fragile regex inference of CVSS metrics from free text. The official JSON feed
carries the **structured CVSS vector** for every CVE, giving tens of thousands of
clean, correctly-encoded training rows — a much stronger basis for the model.

Memory & disk
-------------
Feeds are large (~300 MB decompressed each) and the dev box is disk-constrained,
so we **never decompress to disk**. Files are read straight from `.xz` and parsed
with `ijson` (constant memory — one CVE object at a time), keeping only the ~10
fields we need.

Supported container shapes (auto-detected):
  - fkie-cad mirror:  {"cve_items": [ {<cve>}, ... ]}
  - NVD API dump:     {"vulnerabilities": [ {"cve": {<cve>}}, ... ]}
  - legacy 1.1 feed:  {"CVE_Items": [ ... ]}   (best-effort)
"""

import os
import lzma
import ijson

from app.ml.nvdtrans_processor import (
    ATTACK_VECTOR_MAP,
    ATTACK_COMPLEXITY_MAP,
    PRIV_REQUIRED_MAP,
    USER_INTERACTION_MAP,
    SCOPE_MAP,
    IMPACT_MAP,
)

import pandas as pd

# Top-level array keys we know how to read, in priority order.
_ARRAY_KEYS = ["cve_items", "vulnerabilities", "CVE_Items"]


def _open(path: str):
    """Open a feed for binary reading, transparently handling .xz."""
    if path.endswith(".xz"):
        return lzma.open(path, "rb")
    return open(path, "rb")


def _detect_array_key(path: str) -> str | None:
    """Sniff the first chunk to find which top-level array key is present."""
    with _open(path) as fh:
        head = fh.read(4096)
    text = head.decode("utf-8", errors="ignore")
    # Pick the key that appears earliest in the header.
    found = [(text.find(f'"{k}"'), k) for k in _ARRAY_KEYS]
    found = [(pos, k) for pos, k in found if pos != -1]
    if not found:
        return None
    return min(found)[0:2][1]


def _priority_from_score(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _encode(value, mapping: dict) -> int:
    return mapping.get((value or "").upper(), 0)


def _extract_cwe_number(weaknesses) -> int:
    """First concrete CWE-NNN from the weaknesses block (ignore noinfo/Other)."""
    for w in weaknesses or []:
        for desc in w.get("description", []):
            val = (desc.get("value") or "").strip()
            if val.startswith("CWE-") and val[4:].isdigit():
                return int(val[4:])
    return 0


def _cvss_v3(metrics: dict) -> dict | None:
    """Return the first CVSS v3.1 (preferred) or v3.0 cvssData block."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData") or {}
            if data.get("baseScore") is not None:
                return data
    return None


def _row_from_cve(cve: dict) -> dict | None:
    """Build one encoded training row from a CVE object, or None to skip."""
    metrics = cve.get("metrics") or {}
    data = _cvss_v3(metrics)
    if data is None:
        return None  # no CVSS v3.x vector → skip (keeps feature encoding consistent)

    try:
        score = float(data["baseScore"])
    except (TypeError, ValueError, KeyError):
        return None

    return {
        "cve_id": cve.get("id", ""),
        "cvss_score": score,
        "attack_vector":          _encode(data.get("attackVector"),          ATTACK_VECTOR_MAP),
        "attack_complexity":      _encode(data.get("attackComplexity"),      ATTACK_COMPLEXITY_MAP),
        "privileges_required":    _encode(data.get("privilegesRequired"),    PRIV_REQUIRED_MAP),
        "user_interaction":       _encode(data.get("userInteraction"),       USER_INTERACTION_MAP),
        "scope":                  _encode(data.get("scope"),                 SCOPE_MAP),
        "confidentiality_impact": _encode(data.get("confidentialityImpact"), IMPACT_MAP),
        "integrity_impact":       _encode(data.get("integrityImpact"),       IMPACT_MAP),
        "availability_impact":    _encode(data.get("availabilityImpact"),    IMPACT_MAP),
        "cwe_number":             _extract_cwe_number(cve.get("weaknesses")),
        "priority":               _priority_from_score(score),
    }


def parse_json_feed_file(path: str) -> list[dict]:
    """Stream one NVD JSON feed (.json or .json.xz) into encoded training rows."""
    array_key = _detect_array_key(path)
    if array_key is None:
        raise ValueError(f"Could not find a known CVE array key in {path}")

    records: list[dict] = []
    with _open(path) as fh:
        for item in ijson.items(fh, f"{array_key}.item"):
            # NVD-API shape wraps the CVE under a "cve" key; mirror feeds don't.
            cve = item.get("cve", item) if isinstance(item, dict) else None
            if not cve:
                continue
            row = _row_from_cve(cve)
            if row:
                records.append(row)
    return records


def list_json_feeds(nvd_dir: str) -> list[str]:
    """Return JSON feed files (compressed or not) in a directory."""
    out = []
    for fname in os.listdir(nvd_dir):
        low = fname.lower()
        if low.endswith(".json.xz") or low.endswith(".json"):
            out.append(os.path.join(nvd_dir, fname))
    return sorted(out)


def load_json_feeds_directory(nvd_dir: str) -> pd.DataFrame:
    """
    Load all JSON feeds in a directory into a deduplicated DataFrame,
    identical in shape to nvdtrans_processor.load_nvdtrans_directory.
    """
    feeds = list_json_feeds(nvd_dir)
    if not feeds:
        raise ValueError(f"No JSON feeds (.json/.json.xz) found in {nvd_dir}")

    all_records: list[dict] = []
    for path in feeds:
        print(f"  [JSONFeed] Parsing {os.path.basename(path)} ...", end=" ", flush=True)
        try:
            recs = parse_json_feed_file(path)
            all_records.extend(recs)
            print(f"{len(recs):,} records")
        except Exception as exc:  # noqa: BLE001 — keep going on a bad file
            print(f"ERROR: {exc}")

    if not all_records:
        raise ValueError("No CVSS-v3 training records could be extracted from JSON feeds")

    df = pd.DataFrame(all_records)
    df = df.drop_duplicates(subset=["cve_id"], keep="first").reset_index(drop=True)

    print(f"  [JSONFeed] Total usable CVSS-v3 records after dedup: {len(df):,}")
    _print_class_distribution(df)
    return df


def _print_class_distribution(df: pd.DataFrame) -> None:
    counts = df["priority"].value_counts()
    total = len(df)
    for label in ["Critical", "High", "Medium", "Low"]:
        n = int(counts.get(label, 0))
        print(f"  [JSONFeed]   {label:10s}: {n:6,} ({n/total*100:.1f}%)")
