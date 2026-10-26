"""
PoC Validation Engine

Performs safe, non-destructive validation checks to confirm whether a
vulnerability actually exists on the target. Only passive/benign techniques
are used — no exploitation, no data modification, no writes.

Validation types:
  - xss_check        : reflect XSS payloads and detect unencoded output
  - sqli_check       : error-based + boolean-based SQL injection detection
  - header_check     : verify presence/absence of security headers
  - cors_check       : detect permissive CORS configuration
  - payload_reflection: generic benign marker reflection
  - response_analysis: version disclosure via Server/X-Powered-By headers
"""

import re
import os
import time
import requests
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from app import db
from app.models.normalized_finding import NormalizedFinding
from app.models.poc_validation import PocValidation
from app.engines.confidence_engine import ConfidenceEngine

REQUEST_TIMEOUT  = 8   # seconds per request
REFLECTION_MARKER = "VT-PROBE-7x3k"

# ── XSS payloads (benign — no alert() execution needed, just reflection) ─────
XSS_PAYLOADS = [
    '<script>/*vt-xss*/</script>',
    '"><img src=x id=vt-xss>',
    "'><svg/id=vt-xss>",
    '<body onload=/*vt-xss*/>',
    'javascript:/*vt-xss*/',
]
# Signatures that indicate unencoded reflection (payload made it into HTML context)
XSS_REFLECTION_PATTERNS = [
    re.compile(r'<script>\s*/\*vt-xss\*/\s*</script>', re.I),
    re.compile(r'<img\s[^>]*id=vt-xss',               re.I),
    re.compile(r'<svg[^>]*/id=vt-xss',                re.I),
    re.compile(r'<body\s[^>]*onload=\s*/\*vt-xss\*/', re.I),
    re.compile(r'javascript:\s*/\*vt-xss\*/',          re.I),
]

# ── SQL injection payloads (error-based, non-destructive) ─────────────────────
SQLI_ERROR_PAYLOADS = [
    "'",
    '"',
    "1'--",
    "1 AND 1=1--",
    "' OR '1'='1",
]
# Boolean contrast pair: true condition vs false condition
SQLI_BOOL_TRUE  = "1 AND 1=1"
SQLI_BOOL_FALSE = "1 AND 1=2"

# Patterns that indicate a SQL error was thrown
SQLI_ERROR_RE = re.compile(
    r"sql\s+syntax|mysql_fetch|ora-\d{4}|microsoft\s+sql\s+server"
    r"|sqlite.*error|pg_query|postgresql.*error|unclosed\s+quotation"
    r"|quoted\s+string\s+not\s+properly\s+terminated"
    r"|you\s+have\s+an\s+error\s+in\s+your\s+sql"
    r"|warning.*mysql|warning.*mssql|odbc.*driver",
    re.I,
)

# ── Time-based blind SQLi (sleep payloads — benign, only delays a response) ──
SQLI_SLEEP_SECONDS = 5
SQLI_TIME_PAYLOADS = [
    f"1' AND SLEEP({SQLI_SLEEP_SECONDS})-- -",       # MySQL
    f"1) AND SLEEP({SQLI_SLEEP_SECONDS})-- -",        # MySQL (paren context)
    f"1';SELECT pg_sleep({SQLI_SLEEP_SECONDS})-- -",  # PostgreSQL
    f"1 WAITFOR DELAY '0:0:{SQLI_SLEEP_SECONDS}'-- -",# MSSQL
]

# ── Open redirect (CWE-601) ─────────────────────────────────────────────────
OPEN_REDIRECT_TARGET = "https://vt-redirect-probe.example.org/poc"
OPEN_REDIRECT_HOST = "vt-redirect-probe.example.org"

# ── Path traversal / LFI (CWE-22/98) — read-only /etc/passwd signature ──────
LFI_PAYLOADS = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
]
LFI_SIGNATURE_RE = re.compile(r"root:.*?:0:0:", re.I)


class PocValidator:
    """Runs targeted PoC checks against scanner-reported vulnerabilities."""

    def __init__(self, scope=None):
        self.session = requests.Session()
        self.session.verify = False   # targets may use self-signed certs
        self.session.headers["User-Agent"] = "VulnTriage-PoC-Validator/1.0"
        self.confidence_engine = ConfidenceEngine()

        # Authorisation scope — active payloads only fire at hosts the operator
        # has authorised. Provide via the `scope` arg (str/list of hosts) or the
        # POC_SCOPE env var (comma-separated). When EMPTY, scope is unrestricted
        # (legacy behaviour); pentesters SHOULD set it to stay in-scope.
        raw = scope if scope is not None else os.environ.get("POC_SCOPE", "")
        entries = raw.split(",") if isinstance(raw, str) else (raw or [])
        # Normalise each entry to a bare host: findings are matched against a
        # urlparse hostname (port-stripped), so a scope entry that keeps a port
        # or scheme (e.g. "localhost:3000" or "http://localhost:3000") would
        # never match and would silently skip every PoC. Strip both here.
        self.scope = [h for h in (self._norm_host(e) for e in entries) if h]

    @staticmethod
    def _norm_host(entry) -> str:
        e = str(entry).strip().lower()
        if not e:
            return ""
        if "://" in e:
            return (urlparse(e).hostname or "").strip()
        e = e.split("/", 1)[0]          # drop any path
        if e.count(":") == 1:           # drop :port (leave bare IPv6 alone)
            e = e.split(":", 1)[0]
        return e

    def _in_scope(self, url: str) -> bool:
        if not self.scope:
            return True   # unrestricted (no scope configured)
        host = (urlparse(url).hostname or "").lower()
        return any(host == s or host.endswith("." + s) for s in self.scope)

    # ── Public API ─────────────────────────────────────────────────────────────

    def validate_finding(self, finding: NormalizedFinding) -> PocValidation:
        """Select and run the best-fit validation for this finding."""
        vtype = self._select_type(finding)

        # Re-validation REPLACES this finding's prior PoC results instead of
        # appending. Without this, repeated pipeline runs pile up duplicate rows
        # in the report (e.g. a failed run while the target was down, followed by
        # a successful one, would show both the stale errors and the real result).
        PocValidation.query.filter_by(finding_id=finding.id).delete(
            synchronize_session=False)

        # Authorisation gate: never send probes to an out-of-scope host.
        if finding.url and not self._in_scope(finding.url):
            host = urlparse(finding.url).hostname
            result = self._build(
                finding, "skipped", vtype,
                evidence=(f"Target host '{host}' is outside the authorised PoC scope "
                          f"({', '.join(self.scope)}). Add it to POC_SCOPE to authorise."),
            )
            db.session.add(result)
            db.session.flush()
            self.confidence_engine.rescore_finding(finding)
            return result

        dispatch = {
            "xss_check":          self._xss_check,
            "sqli_check":         self._sqli_check,
            "open_redirect_check":self._open_redirect_check,
            "lfi_check":          self._lfi_check,
            "header_check":       self._header_check,
            "cors_check":         self._cors_check,
            "payload_reflection": self._reflection_check,
            "response_analysis":  self._response_analysis,
        }
        fn = dispatch.get(vtype)
        if fn:
            result = fn(finding)
        else:
            result = self._build(finding, "skipped", vtype,
                                 evidence="No applicable PoC for this vulnerability type")

        db.session.add(result)
        db.session.flush()
        self.confidence_engine.rescore_finding(finding)
        return result

    # ── Strategy selector ──────────────────────────────────────────────────────

    @staticmethod
    def _select_type(finding: NormalizedFinding) -> str:
        cwe   = (finding.cwe_id or "").upper()
        title = (finding.title   or "").lower()

        # SQL Injection
        if cwe in ("CWE-89", "CWE-564") or any(k in title for k in ("sql", "injection", "sqli")):
            return "sqli_check"

        # XSS
        if cwe in ("CWE-79", "CWE-80", "CWE-83", "CWE-87") or any(
            k in title for k in ("xss", "cross-site script", "reflected", "stored script")
        ):
            return "xss_check"

        # Open redirect
        if cwe == "CWE-601" or any(k in title for k in ("open redirect", "url redirect")):
            return "open_redirect_check"

        # Path traversal / Local File Inclusion
        if cwe in ("CWE-22", "CWE-23", "CWE-36", "CWE-98") or any(
            k in title for k in ("traversal", "local file inclusion", "lfi", "file inclusion")
        ):
            return "lfi_check"

        # Security headers / clickjacking / cookie flags
        if cwe in ("CWE-1004", "CWE-311", "CWE-1021", "CWE-16") or any(
            k in title for k in ("header", "hsts", "cookie", "clickjack")
        ):
            return "header_check"

        # CORS
        if cwe == "CWE-942" or "cors" in title:
            return "cors_check"

        # Generic reflection (other injection types with a parameter)
        if finding.parameter:
            return "payload_reflection"

        return "response_analysis"

    # ── XSS check ──────────────────────────────────────────────────────────────

    def _xss_check(self, finding: NormalizedFinding) -> PocValidation:
        url   = finding.url
        param = finding.parameter
        if not url:
            return self._build(finding, "skipped", "xss_check",
                               evidence="No URL available for XSS validation")
        if not param:
            # Fall back to generic reflection if no parameter known
            return self._reflection_check(finding)

        tried = []
        for payload in XSS_PAYLOADS:
            tried.append(payload)
            resp, probe, method = self._fetch(finding, payload)
            if resp is None:
                continue
            for pat in XSS_REFLECTION_PATTERNS:
                m = pat.search(resp.text)
                if m:
                    start = max(0, m.start() - 60)
                    snippet = resp.text[start: m.end() + 60]
                    return self._build(
                        finding, "confirmed", "xss_check",
                        url=probe, payload=payload, method=method,
                        response_code=resp.status_code,
                        response_snippet=snippet[:800],
                        evidence=(
                            f"XSS payload reflected unencoded in response.\n"
                            f"Method  : {method}\n"
                            f"Payload : {payload}\n"
                            f"Pattern : {pat.pattern}"
                        ),
                    )

        return self._build(
            finding, "not_confirmed", "xss_check",
            url=url, method=(finding.method or "GET").upper(),
            evidence=f"No XSS reflection detected. Payloads tried: {len(tried)}",
        )

    # ── SQL injection check ────────────────────────────────────────────────────

    def _sqli_check(self, finding: NormalizedFinding) -> PocValidation:
        url   = finding.url
        param = finding.parameter
        if not url:
            return self._build(finding, "skipped", "sqli_check",
                               evidence="No URL available for SQLi validation")
        if not param:
            return self._build(finding, "skipped", "sqli_check",
                               evidence="No parameter known — cannot inject SQL payload")

        method = (finding.method or "GET").upper()

        # ── Phase 1: Error-based detection ─────────────────────────────────────
        for payload in SQLI_ERROR_PAYLOADS:
            resp, probe, _ = self._fetch(finding, payload)
            if resp is None:
                continue
            m = SQLI_ERROR_RE.search(resp.text)
            if m:
                start   = max(0, m.start() - 80)
                snippet = resp.text[start: m.end() + 80]
                return self._build(
                    finding, "confirmed", "sqli_check",
                    url=probe, payload=payload, method=method,
                    response_code=resp.status_code,
                    response_snippet=snippet[:800],
                    evidence=(
                        f"SQL error string detected in response (error-based).\n"
                        f"Payload : {payload}\n"
                        f"Matched : {m.group(0)}"
                    ),
                )

        # ── Phase 2: Boolean-based detection ───────────────────────────────────
        resp_true, url_true, _ = self._fetch(finding, SQLI_BOOL_TRUE)
        resp_false, _, _ = self._fetch(finding, SQLI_BOOL_FALSE)
        if resp_true is not None and resp_false is not None:
            len_true  = len(resp_true.text)
            len_false = len(resp_false.text)
            diff = abs(len_true - len_false)
            if (diff > 50 and resp_true.status_code != resp_false.status_code) or diff > 200:
                return self._build(
                    finding, "confirmed", "sqli_check",
                    url=url_true, payload=f"{SQLI_BOOL_TRUE} vs {SQLI_BOOL_FALSE}",
                    method=method, response_code=resp_true.status_code,
                    evidence=(
                        f"Boolean-based SQLi detected — response length differs.\n"
                        f"TRUE condition  ({SQLI_BOOL_TRUE}): {len_true} bytes\n"
                        f"FALSE condition ({SQLI_BOOL_FALSE}): {len_false} bytes\n"
                        f"Difference: {diff} bytes"
                    ),
                )

        # ── Phase 3: Time-based blind detection ────────────────────────────────
        # A benign baseline request establishes normal latency; a SLEEP payload
        # that delays the response by ~SQLI_SLEEP_SECONDS confirms injection.
        baseline, _, _ = self._fetch(finding, "1")
        base_t = baseline.elapsed.total_seconds() if baseline is not None else 0.3
        for payload in SQLI_TIME_PAYLOADS:
            t0 = time.time()
            resp, probe, _ = self._fetch(finding, payload, timeout=SQLI_SLEEP_SECONDS + REQUEST_TIMEOUT)
            elapsed = time.time() - t0
            if resp is not None and elapsed >= (base_t + SQLI_SLEEP_SECONDS - 1.5):
                return self._build(
                    finding, "confirmed", "sqli_check",
                    url=probe, payload=payload, method=method,
                    response_code=resp.status_code,
                    evidence=(
                        f"Time-based blind SQLi detected.\n"
                        f"Payload  : {payload}\n"
                        f"Baseline : {base_t:.2f}s | Delayed: {elapsed:.2f}s "
                        f"(expected +{SQLI_SLEEP_SECONDS}s)"
                    ),
                )

        return self._build(
            finding, "not_confirmed", "sqli_check",
            url=url, method=method,
            evidence="No SQL errors, boolean difference, or time delay observed "
                     "across error/boolean/time-based probes. Manual verification recommended.",
        )

    # ── Open redirect check (CWE-601) ──────────────────────────────────────────

    def _open_redirect_check(self, finding: NormalizedFinding) -> PocValidation:
        url = finding.url
        param = finding.parameter
        if not url:
            return self._build(finding, "skipped", "open_redirect_check",
                               evidence="No URL available")
        # Try the reported parameter, then common redirect parameter names.
        candidates = [param] if param else []
        candidates += [c for c in ("url", "next", "redirect", "return", "dest", "r")
                       if c not in candidates]
        for p in candidates:
            probe = self._inject(url, p, OPEN_REDIRECT_TARGET)
            try:
                resp = self.session.get(probe, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            except requests.RequestException:
                continue
            location = resp.headers.get("Location", "")
            if resp.is_redirect and OPEN_REDIRECT_HOST in location:
                return self._build(
                    finding, "confirmed", "open_redirect_check",
                    url=probe, payload=OPEN_REDIRECT_TARGET, method="GET",
                    response_code=resp.status_code,
                    evidence=(f"Open redirect confirmed via parameter '{p}'.\n"
                              f"Response {resp.status_code} Location: {location}"),
                )
        return self._build(
            finding, "not_confirmed", "open_redirect_check",
            url=url, method="GET",
            evidence=f"No external redirect observed (tried params: {candidates}).",
        )

    # ── Path traversal / LFI check (CWE-22/98) ─────────────────────────────────

    def _lfi_check(self, finding: NormalizedFinding) -> PocValidation:
        """Read-only /etc/passwd signature probe — never writes or modifies."""
        url = finding.url
        param = finding.parameter
        if not url:
            return self._build(finding, "skipped", "lfi_check",
                               evidence="No URL available")
        if not param:
            return self._build(finding, "skipped", "lfi_check",
                               evidence="No parameter known — cannot inject traversal path")
        for payload in LFI_PAYLOADS:
            resp, probe, method = self._fetch(finding, payload)
            if resp is None:
                continue
            m = LFI_SIGNATURE_RE.search(resp.text)
            if m:
                start = max(0, m.start() - 20)
                snippet = resp.text[start: m.end() + 120]
                return self._build(
                    finding, "confirmed", "lfi_check",
                    url=probe, payload=payload, method=method,
                    response_code=resp.status_code,
                    response_snippet=snippet[:800],
                    evidence=(f"Path traversal/LFI confirmed — /etc/passwd contents "
                              f"returned (read-only probe).\nPayload: {payload}"),
                )
        return self._build(
            finding, "not_confirmed", "lfi_check",
            url=url, method=(finding.method or "GET").upper(),
            evidence=f"No /etc/passwd signature returned. Payloads tried: {len(LFI_PAYLOADS)}",
        )

    # ── Security header check ──────────────────────────────────────────────────

    def _header_check(self, finding: NormalizedFinding) -> PocValidation:
        url = finding.url
        if not url:
            return self._build(finding, "skipped", "header_check",
                               evidence="No URL available")
        try:
            resp = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        except requests.RequestException as e:
            return self._build(finding, "error", "header_check", error=str(e))

        hdrs   = {k.lower(): v for k, v in resp.headers.items()}
        wanted = [
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "content-security-policy",
        ]
        missing = [h for h in wanted if h not in hdrs]

        cwe       = finding.cwe_id or ""
        confirmed = bool(missing)
        if cwe == "CWE-1004" and "set-cookie" in hdrs:
            confirmed = "httponly" not in hdrs["set-cookie"].lower()

        snippet  = "\n".join(f"{k}: {v}" for k, v in list(resp.headers.items())[:20])
        evidence = (
            f"Missing security headers: {missing}"
            if missing else "All checked security headers present"
        )
        return self._build(
            finding,
            "confirmed" if confirmed else "not_confirmed",
            "header_check",
            url=url, method="GET",
            response_code=resp.status_code,
            response_snippet=snippet[:800],
            evidence=evidence,
        )

    # ── CORS check ─────────────────────────────────────────────────────────────

    def _cors_check(self, finding: NormalizedFinding) -> PocValidation:
        url = finding.url
        if not url:
            return self._build(finding, "skipped", "cors_check",
                               evidence="No URL available")
        try:
            resp = self.session.options(
                url,
                headers={
                    "Origin": "https://evil.example.com",
                    "Access-Control-Request-Method": "GET",
                },
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as e:
            return self._build(finding, "error", "cors_check", error=str(e))

        acao      = resp.headers.get("Access-Control-Allow-Origin", "")
        acac      = resp.headers.get("Access-Control-Allow-Credentials", "")
        confirmed = acao in ("*", "https://evil.example.com")
        evidence  = (
            f"Access-Control-Allow-Origin: {acao or '(not set)'}\n"
            f"Access-Control-Allow-Credentials: {acac or '(not set)'}"
        )
        return self._build(
            finding,
            "confirmed" if confirmed else "not_confirmed",
            "cors_check",
            url=url, method="OPTIONS",
            response_code=resp.status_code,
            evidence=evidence,
        )

    # ── Generic reflection check ───────────────────────────────────────────────

    def _reflection_check(self, finding: NormalizedFinding) -> PocValidation:
        url   = finding.url
        param = finding.parameter
        if not url or not param:
            return self._build(finding, "skipped", "payload_reflection",
                               evidence="URL or parameter not available")
        probe = self._inject(url, param, REFLECTION_MARKER)
        try:
            resp = self.session.get(probe, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as e:
            return self._build(finding, "error", "payload_reflection", error=str(e))

        confirmed = REFLECTION_MARKER in resp.text
        snippet   = ""
        if confirmed:
            idx     = resp.text.find(REFLECTION_MARKER)
            snippet = resp.text[max(0, idx - 50): idx + len(REFLECTION_MARKER) + 50]

        return self._build(
            finding,
            "confirmed" if confirmed else "not_confirmed",
            "payload_reflection",
            url=probe, payload=REFLECTION_MARKER, method="GET",
            response_code=resp.status_code,
            response_snippet=snippet,
            evidence=f"Marker '{REFLECTION_MARKER}' reflected in response: {confirmed}",
        )

    # ── Response / version analysis ────────────────────────────────────────────

    def _response_analysis(self, finding: NormalizedFinding) -> PocValidation:
        url = finding.url
        if not url:
            return self._build(finding, "skipped", "response_analysis",
                               evidence="No URL available")
        try:
            resp = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        except requests.RequestException as e:
            return self._build(finding, "error", "response_analysis", error=str(e))

        server      = resp.headers.get("Server", "")
        x_powered   = resp.headers.get("X-Powered-By", "")
        ver_re      = re.compile(r"\d+\.\d+\.?\d*")
        versions    = ver_re.findall(server + " " + x_powered)
        confirmed   = bool(versions)

        evidence = (
            f"Server: {server or '(not set)'}\n"
            f"X-Powered-By: {x_powered or '(not set)'}\n"
            f"Versions disclosed: {versions}"
        )
        return self._build(
            finding,
            "confirmed" if confirmed else "not_confirmed",
            "response_analysis",
            url=url, method="GET",
            response_code=resp.status_code,
            response_snippet=resp.text[:300],
            evidence=evidence,
        )

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _inject(url: str, param: str, value: str) -> str:
        """Set `param` to `value` in the URL's query string.

        Must REPLACE an existing value, not append — scanner-derived finding URLs
        usually already contain the parameter (with the scanner's own attack
        payload). Appending `&param=...` creates a duplicate and most servers use
        the *first* occurrence, so the PoC's payload would be silently ignored.
        """
        parts = urlparse(url)
        qs = parse_qs(parts.query, keep_blank_values=True)
        qs[param] = [value]   # replace any existing value(s)
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parts._replace(query=new_query))

    @staticmethod
    def _strip_query(url: str) -> str:
        """Return the URL without its query string (for POST bodies)."""
        parts = urlparse(url)
        return urlunparse(parts._replace(query="", fragment=""))

    def _fetch(self, finding: NormalizedFinding, value: str, timeout: int = REQUEST_TIMEOUT):
        """Send one probe carrying `value` in the finding's parameter, honouring
        the finding's HTTP method (GET query-string vs POST form body).
        Returns (response|None, probe_url, method)."""
        url = finding.url
        param = finding.parameter
        method = (finding.method or "GET").upper()
        try:
            if method == "POST" and param:
                target = self._strip_query(url)
                resp = self.session.post(target, data={param: value}, timeout=timeout)
                return resp, target, "POST"
            probe = self._inject(url, param, value) if param else url
            resp = self.session.get(probe, timeout=timeout)
            return resp, probe, "GET"
        except requests.RequestException:
            return None, url, method

    @staticmethod
    def _build(
        finding: NormalizedFinding,
        result:   str,
        vtype:    str,
        url:      str  = None,
        payload:  str  = None,
        method:   str  = None,
        response_code: int  = None,
        response_snippet: str = None,
        evidence: str  = None,
        error:    str  = None,
    ) -> PocValidation:
        return PocValidation(
            finding_id       = finding.id,
            validation_type  = vtype,
            target_url       = url or finding.url,
            payload_used     = payload,
            http_method      = method,
            result           = result,
            response_code    = response_code,
            response_snippet = response_snippet,
            evidence         = evidence,
            error_message    = error,
            validated_at     = datetime.utcnow(),
        )
