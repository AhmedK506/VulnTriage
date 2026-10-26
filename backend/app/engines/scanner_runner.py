"""
Scanner runner — optional orchestration layer (Auto Scan).

VulnTriage's core remains a *triage* system over existing scanner output; this
module lets the app optionally DRIVE scanners against a target and collect their
native reports, which then feed the normal ingest+triage pipeline. It does not
implement any scanning itself — it shells out to the real tools.

Auto Scan supports **OWASP ZAP** and **Nuclei** (both run headless with no extra
setup). Nessus is intentionally NOT auto-launched: Nessus Essentials/Professional
block scan creation via the REST API, so Nessus is used in VulnTriage via the
normal flow instead — run it in the Nessus UI, export the .nessus file, and
upload it. (The nessus parser handles that report like any other.)

⚠️  Active scanning is intrusive. Only run against assets you are authorised to
test. The orchestrator enforces an authorisation acknowledgement / scope.

Each adapter returns the path to a native report file the existing parsers can
read (ZAP XML, Nuclei JSONL), or raises ScannerError.
"""

import os
import re
import shutil
import socket
import subprocess
from urllib.parse import urlsplit, urlunsplit

# Tool locations (allow override via env for non-standard installs).
ZAP_BIN = os.environ.get("ZAP_BIN") or shutil.which("zaproxy") or shutil.which("zap.sh")
NUCLEI_BIN = os.environ.get("NUCLEI_BIN") or shutil.which("nuclei") \
    or os.path.expanduser("~/go-workspace/bin/nuclei")

# Default per-scanner wall-clock limits (seconds); override via env. Generous by
# default — a full active scan of a large real app (e.g. Juice Shop) can take
# 20-40 min. The timeout is a ceiling, so small targets still finish quickly.
ZAP_TIMEOUT = int(os.environ.get("ZAP_TIMEOUT", "2400"))
NUCLEI_TIMEOUT = int(os.environ.get("NUCLEI_TIMEOUT", "1200"))

# Cap the ZAP JVM heap so a big active scan can't balloon into swap and freeze
# the whole VM. zap.sh treats -Xmx as a passthrough to the java launcher.
ZAP_XMX = os.environ.get("ZAP_XMX", "2g")

# Refuse to start a ZAP scan unless this much disk is free on the scan volume.
# ZAP writes its scan session as an on-disk DB that grows through the scan; on a
# near-full disk it fills to 0 bytes mid-scan and can take the host down. Fail
# fast with a clear message instead. Override via env (bytes).
ZAP_MIN_FREE_BYTES = int(os.environ.get("ZAP_MIN_FREE_BYTES", str(2 * 1024**3)))

# Scanners Auto Scan can drive. (Nessus is supported via manual export+upload.)
SUPPORTED_SCANNERS = ("zap", "nuclei")


class ScannerError(RuntimeError):
    pass


def normalise_target(target: str) -> str:
    """Clean a user-supplied target URL before handing it to a scanner.

    - trims surrounding whitespace;
    - defaults the scheme to ``http://`` when omitted (e.g. ``localhost:3000``);
    - **drops any URL fragment** (``#/...``). A fragment is a client-side SPA
      route that is never sent to the server; if it is left on the target it
      poisons ZAP's context ``includePaths`` regex (which is built from the
      target) so no crawled server URL matches the scope, and the active scan
      finds nothing. Stripping it here fixes the common "0 findings" case when a
      user pastes a single-page-app URL such as ``.../#/``.

    The function is idempotent, so it is safe to call more than once.
    """
    if not target or not target.strip():
        return target
    t = target.strip()
    if "://" not in t:
        t = "http://" + t
    p = urlsplit(t)
    return urlunsplit((p.scheme, p.netloc, p.path, p.query, ""))  # fragment dropped


# ───────────────────────── availability ─────────────────────────
def _nuclei_ok() -> bool:
    return bool(NUCLEI_BIN and os.path.exists(NUCLEI_BIN))


def _zap_ok() -> bool:
    return bool(ZAP_BIN and os.path.exists(ZAP_BIN))


def scanner_availability() -> dict:
    """Which Auto Scan scanners can actually run right now."""
    return {
        "zap": {"available": _zap_ok(),
                "reason": "" if _zap_ok() else "zaproxy/zap.sh not found"},
        "nuclei": {"available": _nuclei_ok(),
                   "reason": "" if _nuclei_ok() else "nuclei binary not found"},
    }


# ───────────────────────── Nuclei ─────────────────────────
def run_nuclei(target: str, out_dir: str) -> str:
    if not _nuclei_ok():
        raise ScannerError("nuclei binary not found")
    out = os.path.join(out_dir, "nuclei.jsonl")
    cmd = [NUCLEI_BIN, "-u", target, "-jsonl", "-o", out, "-silent", "-no-color"]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=NUCLEI_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise ScannerError(f"nuclei timed out after {NUCLEI_TIMEOUT}s")
    except OSError as e:
        raise ScannerError(f"nuclei failed to start: {e}")
    if not os.path.exists(out):
        # Nuclei writes nothing when there are zero matches — emit an empty file
        # so the ingest step records a clean (0-finding) upload rather than error.
        open(out, "w").close()
    return out


# ───────────────────────── OWASP ZAP ─────────────────────────
def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# Per-phase caps (minutes) for the ZAP automation plan; override via env. Kept
# modest so a large app (e.g. Juice Shop) completes and the report is written —
# the active scan uses Low attack strength + a per-rule cap to stay bounded.
ZAP_SPIDER_MINS = int(os.environ.get("ZAP_SPIDER_MINS", "2"))
ZAP_AJAX_MINS = int(os.environ.get("ZAP_AJAX_MINS", "3"))
ZAP_ASCAN_MINS = int(os.environ.get("ZAP_ASCAN_MINS", "8"))


def _zap_plan(target: str, out_dir: str) -> str:
    """ZAP Automation Framework plan: traditional spider + AJAX spider (for SPAs)
    + active scan, then a classic XML report the zap_parser reads."""
    return f"""---
env:
  contexts:
    - name: target
      urls: ["{target}"]
      includePaths: ["{re.escape(target)}.*"]
  parameters:
    failOnError: false
    progressToStdout: true
jobs:
  - type: spider
    parameters: {{ context: target, url: "{target}", maxDuration: {ZAP_SPIDER_MINS} }}
  - type: spiderAjax
    parameters: {{ context: target, url: "{target}", maxDuration: {ZAP_AJAX_MINS},
                   browserId: firefox-headless, numberOfBrowsers: 1 }}
  - type: passiveScan-wait
    parameters: {{ maxDuration: 2 }}
  - type: activeScan
    parameters:
      context: target
      # Cap the WHOLE active scan and EACH rule — maxScanDurationInMins alone is a
      # soft cap that overruns badly on big apps (many endpoints x rules), which
      # blows the subprocess timeout and loses the report (report job runs last).
      maxScanDurationInMins: {ZAP_ASCAN_MINS}
      maxRuleDurationInMins: 1
      policyDefinition:
        defaultThreshold: Medium
        defaultStrength: Low
  - type: report
    parameters:
      template: traditional-xml
      reportDir: "{out_dir}"
      reportFile: zap
      reportTitle: VulnTriage ZAP Scan
"""


def run_zap(target: str, out_dir: str) -> str:
    if not _zap_ok():
        raise ScannerError("zaproxy/zap.sh not found")
    # Fail fast on a near-full disk: ZAP's on-disk scan session grows through the
    # scan, and filling the volume mid-scan can freeze the whole VM.
    free = shutil.disk_usage(out_dir).free
    if free < ZAP_MIN_FREE_BYTES:
        raise ScannerError(
            f"insufficient disk to run ZAP safely: {free // 1024**2} MiB free, "
            f"need {ZAP_MIN_FREE_BYTES // 1024**2} MiB "
            f"(free space, e.g. clear ~/.ZAP/sessions, or lower ZAP_MIN_FREE_BYTES)")
    # Isolate each run: a private ZAP home dir + a free proxy port so concurrent/
    # stale ZAP instances can't collide on port 8080 or the ~/.ZAP session lock.
    home = os.path.join(out_dir, "zaphome")
    os.makedirs(home, exist_ok=True)
    plan = os.path.join(out_dir, "zap_plan.yaml")
    with open(plan, "w") as f:
        f.write(_zap_plan(target, out_dir))

    # -Xmx caps the JVM heap (bounds RAM); zap.sh passes it through to java.
    cmd = [ZAP_BIN, f"-Xmx{ZAP_XMX}",
           "-cmd", "-dir", home, "-port", str(_free_port()), "-autorun", plan]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=ZAP_TIMEOUT)
    except subprocess.TimeoutExpired as e:
        # progressToStdout logs each job's start/finish, so the tail shows which
        # phase was still running when the ceiling was hit.
        out = (e.stdout or b"")
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        phase = " | ".join(l for l in out.splitlines() if "Job " in l)[-300:]
        raise ScannerError(f"ZAP timed out after {ZAP_TIMEOUT}s (lower ZAP_ASCAN_MINS). "
                           f"Last phases: {phase or 'n/a'}")
    except OSError as e:
        raise ScannerError(f"ZAP failed to start: {e}")

    # The report job writes reportFile + the template's extension (.xml).
    report = os.path.join(out_dir, "zap.xml")
    if not os.path.exists(report):
        found = [f for f in os.listdir(out_dir) if f.lower().endswith(".xml")]
        if found:
            report = os.path.join(out_dir, found[0])
        else:
            msg = (proc.stderr or proc.stdout or "").strip().splitlines()
            tail = " ".join(msg[-4:])[:400] if msg else "no output"
            raise ScannerError(f"ZAP produced no report (exit {proc.returncode}): {tail}")
    return report


_RUNNERS = {"nuclei": run_nuclei, "zap": run_zap}


def run_scanner(name: str, target: str, out_dir: str) -> str:
    """Run one scanner by name and return its native report path."""
    runner = _RUNNERS.get(name)
    if not runner:
        raise ScannerError(
            f"'{name}' is not an Auto Scan scanner. Supported: "
            f"{', '.join(SUPPORTED_SCANNERS)}. (Nessus: export a .nessus report "
            f"from the Nessus UI and upload it instead.)")
    os.makedirs(out_dir, exist_ok=True)
    return runner(normalise_target(target), out_dir)
