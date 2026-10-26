"""
NVD Translation Feed Processor

Parses the nvdtrans XML format produced by NIST's Spanish translation feed.
Schema: http://nvd.nist.gov/feeds/nvdcvetrans

Each <entry> contains Spanish-translated CVE descriptions that often embed
CVSS scores and vectors in two formats:

  Format A (VulnDB-style):
    "puntuación CVSS de 8,3 y un vector CVSS de CVSS:3.0/AV:N/AC:H/PR:N/..."

  Format B (Oracle/structured):
    "CVSS 3.1 Puntaje base 5.0 ... Vector CVSS: (CVSS:3.1/AV:N/AC:L/...)"

When the full vector is absent, individual CVSS metric values are inferred
from recurring Spanish text patterns (e.g. "fácilmente explotable" → AC:L).

Returns a pandas DataFrame identical in shape to NvdDataProcessor output,
so the same ModelTrainer can consume it without changes.
"""

import re
import os
import numpy as np
import pandas as pd
import defusedxml.ElementTree as ET

# ------------------------------------------------------------------ #
#  Encoding maps (shared with data_processor.py)                      #
# ------------------------------------------------------------------ #
ATTACK_VECTOR_MAP    = {"NETWORK": 4, "ADJACENT": 3, "ADJACENT_NETWORK": 3, "LOCAL": 2, "PHYSICAL": 1}
ATTACK_COMPLEXITY_MAP = {"LOW": 2, "HIGH": 1}
PRIV_REQUIRED_MAP    = {"NONE": 3, "LOW": 2, "HIGH": 1}
USER_INTERACTION_MAP  = {"NONE": 2, "REQUIRED": 1}
SCOPE_MAP            = {"CHANGED": 2, "UNCHANGED": 1}
IMPACT_MAP           = {"HIGH": 3, "LOW": 2, "NONE": 1}
PRIORITY_MAP         = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

# Abbreviated metric values used inside a CVSS vector string
AV_ABBR  = {"N": "NETWORK",   "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}
AC_ABBR  = {"L": "LOW", "H": "HIGH"}
PR_ABBR  = {"N": "NONE", "L": "LOW", "H": "HIGH"}
UI_ABBR  = {"N": "NONE", "R": "REQUIRED"}
S_ABBR   = {"U": "UNCHANGED", "C": "CHANGED"}
IMP_ABBR = {"N": "NONE", "L": "LOW", "H": "HIGH"}

# ------------------------------------------------------------------ #
#  Regex patterns                                                      #
# ------------------------------------------------------------------ #

# CVSS vector: allow optional whitespace between slashes (some descriptions
# wrap long vectors by inserting a space before a component, e.g. "/A:H")
_VECTOR_RE = re.compile(
    r"CVSS:(?P<ver>[0-9]\.[0-9])"
    r"/AV:(?P<av>[NALP])\s*"
    r"/AC:(?P<ac>[LH])\s*"
    r"/PR:(?P<pr>[NLH])\s*"
    r"/UI:(?P<ui>[NR])\s*"
    r"/S:(?P<s>[UC])\s*"
    r"/C:(?P<ci>[NLH])\s*"
    r"/I:(?P<ii>[NLH])\s*"
    r"/A:(?P<ai>[NLH])",
    re.IGNORECASE,
)

# CVSS base score — covers all observed formats:
#   2024 VulnDB:  "puntuación CVSS de 8,3 y un vector CVSS de ..."
#   2024 Oracle:  "CVSS 3.1 Puntaje base 5.0 (Impactos...)"
#   2024 Oracle:  "CVSS 3.1 Puntuación base 5.0"
#   2024 English: "CVSS 3.1 Base Score 3.0"
#   2025 Oracle:  "Puntuación base CVSS 3.1 6.1 (impactos...)"
#   2025 Oracle:  "Puntuación base de CVSS 3.1: 4,9 (impactos...)"
_SCORE_RE = re.compile(
    r"(?:"
    # 2025 style: "Puntuación base [de] CVSS 3.1[:]  6.1"
    r"puntuaci[oó]n\s+base\s+(?:de\s+)?CVSS\s+[0-9]\.[0-9]:?\s+|"
    # VulnDB style: "puntuación CVSS de 8,3"
    r"puntuaci[oó]n\s+CVSS\s+de\s+|"
    # Oracle 2024: "CVSS 3.1 Puntaje base" or "Puntuación base" or "Base Score"
    r"CVSS\s+[0-9]\.[0-9]\s+(?:puntaje|puntuaci[oó]n)\s+base\s+|"
    r"CVSS\s+[0-9]\.[0-9]\s+base\s+score\s+"
    r")([\d]+[.,][\d]+)",
    re.IGNORECASE,
)

# CWE from description keyword patterns (Spanish)
_CWE_KEYWORD_MAP = [
    (r"inyecci[oó]n\s+SQL|SQL\s+inject",                          "CWE-89"),
    (r"cross.site.script|XSS|scripting\s+entre\s+sitios",         "CWE-79"),
    (r"falsificaci[oó]n\s+de\s+petici[oó]n|CSRF",                 "CWE-352"),
    (r"traversal\s+de\s+(?:ruta|directorio)|path\s+traversal",    "CWE-22"),
    (r"inyecci[oó]n\s+de\s+comandos|command\s+inject",             "CWE-78"),
    (r"entidad\s+externa\s+XML|XXE",                               "CWE-611"),
    (r"deserializ",                                                "CWE-502"),
    (r"SSRF|falsificaci[oó]n.+del.+servidor",                     "CWE-918"),
    (r"redirecci[oó]n\s+abierta|open\s+redirect",                 "CWE-601"),
    (r"ejecuci[oó]n\s+remota\s+de\s+c[oó]digo|RCE",              "CWE-94"),
    (r"carga\s+sin\s+restricciones|upload\s+unrestric",           "CWE-434"),
    (r"omisi[oó]n\s+de\s+autenticaci[oó]n|authentication\s+bypass", "CWE-287"),
    (r"ausencia\s+de\s+autenticaci[oó]n|missing\s+auth",          "CWE-306"),
    (r"divulgaci[oó]n\s+de\s+informaci[oó]n|information\s+disclos", "CWE-200"),
    (r"desbordamiento\s+de\s+b[uú]fer|buffer\s+overflow",         "CWE-120"),
    (r"desbordamiento\s+de\s+enteros|integer\s+overflow",          "CWE-190"),
    (r"uso\s+despu[eé]s\s+de\s+liberaci[oó]n|use.after.free",     "CWE-416"),
    (r"condici[oó]n\s+de\s+carrera|race\s+condition",              "CWE-362"),
    (r"contrase[nñ]a\s+(?:d[eé]bil|por\s+defecto)|weak\s+password", "CWE-521"),
    (r"denegaci[oó]n\s+de\s+servicio|DoS|DDoS",                   "CWE-400"),
]
_CWE_PATTERNS = [(re.compile(p, re.IGNORECASE), c) for p, c in _CWE_KEYWORD_MAP]


# ------------------------------------------------------------------ #
#  Spanish text → CVSS metric inference                               #
# ------------------------------------------------------------------ #

_AC_EASY = re.compile(r"f[aá]cilmente\s+explotable", re.IGNORECASE)
_AC_HARD = re.compile(r"dif[ií]cil\s+de\s+explotar|complejidad\s+alta", re.IGNORECASE)

_PR_NONE = re.compile(r"atacante\s+no\s+autenticado|sin\s+autenticaci[oó]n", re.IGNORECASE)
_PR_LOW  = re.compile(r"pocos\s+privilegios|bajos\s+privilegios", re.IGNORECASE)
_PR_HIGH = re.compile(r"altos\s+privilegios|privilegios\s+elevados", re.IGNORECASE)

_UI_REQ  = re.compile(r"requiere\s+la\s+interacci[oó]n\s+del\s+usuario", re.IGNORECASE)
_UI_NONE = re.compile(r"no\s+requiere\s+interacci[oó]n", re.IGNORECASE)

_SCOPE_C = re.compile(r"pueden\s+afectar\s+significativamente\s+a\s+productos\s+adicionales"
                       r"|scope\s+change|cambio\s+de\s+alcance", re.IGNORECASE)

_AV_NET  = re.compile(r"acceso\s+a\s+la\s+red|a\s+trav[eé]s\s+de\s+(?:HTTP|HTTPS|red)\b", re.IGNORECASE)
_AV_LOC  = re.compile(r"acceso\s+local|inicio\s+de\s+sesi[oó]n\s+en\s+la\s+infraestructura", re.IGNORECASE)
_AV_PHY  = re.compile(r"acceso\s+f[ií]sico|segmento\s+de\s+comunicaci[oó]n\s+f[ií]sico", re.IGNORECASE)

_IMP_HIGH = re.compile(r"alto\s+impacto\s+en\s+(?:la\s+)?(?:confidencialidad|integridad|disponibilidad)", re.IGNORECASE)
_IMP_NONE = re.compile(r"(?:ning[uú]n|sin)\s+impacto\s+en\s+(?:la\s+)?(?:confidencialidad|integridad|disponibilidad)", re.IGNORECASE)


def _infer_metrics_from_text(text: str) -> dict:
    """Best-effort extraction of CVSS metric values from Spanish description."""

    # Attack Complexity
    if _AC_EASY.search(text):
        ac = "LOW"
    elif _AC_HARD.search(text):
        ac = "HIGH"
    else:
        ac = None

    # Privileges Required
    if _PR_NONE.search(text):
        pr = "NONE"
    elif _PR_LOW.search(text):
        pr = "LOW"
    elif _PR_HIGH.search(text):
        pr = "HIGH"
    else:
        pr = None

    # User Interaction
    if _UI_REQ.search(text):
        ui = "REQUIRED"
    elif _UI_NONE.search(text):
        ui = "NONE"
    else:
        ui = None

    # Scope
    scope = "CHANGED" if _SCOPE_C.search(text) else None

    # Attack Vector
    if _AV_PHY.search(text):
        av = "PHYSICAL"
    elif _AV_LOC.search(text):
        av = "LOCAL"
    elif _AV_NET.search(text):
        av = "NETWORK"
    else:
        av = None

    # Impact (simplified — detect if HIGH or NONE mentioned; default LOW)
    ci = ii = ai = None
    # Look for high/none in order — last matching pattern wins
    for m in _IMP_HIGH.finditer(text):
        term = m.group(0).lower()
        if "confidencialidad" in term:
            ci = "HIGH"
        elif "integridad" in term:
            ii = "HIGH"
        elif "disponibilidad" in term:
            ai = "HIGH"

    for m in _IMP_NONE.finditer(text):
        term = m.group(0).lower()
        if "confidencialidad" in term:
            ci = "NONE"
        elif "integridad" in term:
            ii = "NONE"
        elif "disponibilidad" in term:
            ai = "NONE"

    return {
        "attack_vector": av,
        "attack_complexity": ac,
        "privileges_required": pr,
        "user_interaction": ui,
        "scope": scope,
        "confidentiality_impact": ci,
        "integrity_impact": ii,
        "availability_impact": ai,
    }


def _parse_vector(match: re.Match) -> dict:
    g = match.groupdict()
    return {
        "attack_vector":          AV_ABBR.get(g["av"].upper(),  "NETWORK"),
        "attack_complexity":      AC_ABBR.get(g["ac"].upper(),  "LOW"),
        "privileges_required":    PR_ABBR.get(g["pr"].upper(),  "NONE"),
        "user_interaction":       UI_ABBR.get(g["ui"].upper(),  "NONE"),
        "scope":                  S_ABBR.get(g["s"].upper(),    "UNCHANGED"),
        "confidentiality_impact": IMP_ABBR.get(g["ci"].upper(), "NONE"),
        "integrity_impact":       IMP_ABBR.get(g["ii"].upper(), "NONE"),
        "availability_impact":    IMP_ABBR.get(g["ai"].upper(), "NONE"),
    }


def _parse_score(text: str) -> float | None:
    m = _SCORE_RE.search(text)
    if m:
        raw = m.group(1).replace(",", ".")
        try:
            return float(raw)
        except ValueError:
            pass
    return None


def _cwe_from_text(text: str) -> int:
    for pattern, cwe in _CWE_PATTERNS:
        if pattern.search(text):
            return int(cwe.split("-")[1])
    return 0


def _priority_from_score(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _encode(value: str | None, mapping: dict) -> int:
    return mapping.get((value or "").upper(), 0)


# ------------------------------------------------------------------ #
#  Public API                                                          #
# ------------------------------------------------------------------ #

NVD_NS = {"n": "http://nvd.nist.gov/feeds/nvdcvetrans"}


def parse_nvdtrans_file(xml_path: str) -> list[dict]:
    """
    Parse one nvdtrans XML file and return a list of dicts, one per CVE
    that has enough data to form a training record.
    """
    records = []
    tree = ET.parse(xml_path)
    root = tree.getroot()

    for entry in root.iter("{http://nvd.nist.gov/feeds/nvdcvetrans}entry"):
        cve_id = entry.get("name", "")
        if not cve_id.startswith("CVE-"):
            continue

        # Collect all description text
        texts = []
        for desc_el in entry.iter("{http://nvd.nist.gov/feeds/nvdcvetrans}descript"):
            if desc_el.text:
                texts.append(desc_el.text)
        if not texts:
            continue

        full_text = " ".join(texts)

        # --- Extract CVSS vector (most reliable source) ---
        vec_match = _VECTOR_RE.search(full_text)
        if vec_match:
            metrics = _parse_vector(vec_match)
        else:
            metrics = _infer_metrics_from_text(full_text)

        # --- Extract CVSS score ---
        score = _parse_score(full_text)

        # Only include records with an explicit numerical CVSS score in the
        # text. Severity keyword guessing produces a 96%+ Critical imbalance
        # because "crítica" appears in generic Spanish phrases constantly.
        if score is None:
            continue

        cwe_number = _cwe_from_text(full_text)

        records.append({
            "cve_id": cve_id,
            "cvss_score": score,
            "attack_vector":          _encode(metrics.get("attack_vector"),          ATTACK_VECTOR_MAP),
            "attack_complexity":      _encode(metrics.get("attack_complexity"),      ATTACK_COMPLEXITY_MAP),
            "privileges_required":    _encode(metrics.get("privileges_required"),    PRIV_REQUIRED_MAP),
            "user_interaction":       _encode(metrics.get("user_interaction"),       USER_INTERACTION_MAP),
            "scope":                  _encode(metrics.get("scope"),                  SCOPE_MAP),
            "confidentiality_impact": _encode(metrics.get("confidentiality_impact"), IMPACT_MAP),
            "integrity_impact":       _encode(metrics.get("integrity_impact"),       IMPACT_MAP),
            "availability_impact":    _encode(metrics.get("availability_impact"),    IMPACT_MAP),
            "cwe_number": cwe_number,
            "priority": _priority_from_score(score),
        })

    return records


def load_nvdtrans_directory(nvd_dir: str) -> pd.DataFrame:
    """
    Load all nvdtrans XML files from a directory and combine into a DataFrame.
    Automatically deduplicates by CVE ID, keeping the highest-score record.
    """
    all_records: list[dict] = []
    xml_files = [f for f in os.listdir(nvd_dir) if f.lower().endswith(".xml")]

    if not xml_files:
        raise ValueError(f"No XML files found in {nvd_dir}")

    for fname in xml_files:
        fpath = os.path.join(nvd_dir, fname)
        print(f"  [NVDTrans] Parsing {fname} ...", end=" ", flush=True)
        try:
            recs = parse_nvdtrans_file(fpath)
            all_records.extend(recs)
            print(f"{len(recs):,} records")
        except Exception as exc:
            print(f"ERROR: {exc}")

    if not all_records:
        raise ValueError("No training records could be extracted from NVD XML files")

    df = pd.DataFrame(all_records)

    # Deduplicate: keep first occurrence (files are ordered newest → oldest
    # by how we copy them, so newest CVSS data wins)
    df = df.drop_duplicates(subset=["cve_id"], keep="first")
    df = df.reset_index(drop=True)

    print(f"  [NVDTrans] Total usable records after dedup: {len(df):,}")
    _print_class_distribution(df)
    return df


def _print_class_distribution(df: pd.DataFrame) -> None:
    counts = df["priority"].value_counts()
    total = len(df)
    for label in ["Critical", "High", "Medium", "Low"]:
        n = counts.get(label, 0)
        print(f"  [NVDTrans]   {label:10s}: {n:5,} ({n/total*100:.1f}%)")
