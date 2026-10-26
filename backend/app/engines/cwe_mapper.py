"""
CWE Mapper

Maps vulnerability names and descriptions to CWE IDs using:
1. Exact CWE-NNN matches already present on the finding
2. A static keyword -> CWE lookup table for common web vulnerabilities
3. The CweMapping reference table in the database

This enables structured weakness categorisation even when scanners
don't provide CWE information directly.
"""

import re
from app import db
from app.models.normalized_finding import NormalizedFinding
from app.models.cwe_mapping import CweMapping

# Keyword -> CWE mappings for common web/infra findings.
#
# ORDER MATTERS: the first matching pattern wins, so patterns are grouped
# specific -> general. A specific alert (e.g. "cookie without Secure flag")
# must appear before the general one it would otherwise be swallowed by
# (e.g. a bare "cookie"). Short acronyms are anchored with \b so they don't
# match as substrings (e.g. \brce\b must not fire on "souRCE code disclosure").
KEYWORD_CWE_MAP = [
    # ── Injection & server-side execution ──────────────────────────────────
    (r"sql.?inject", "CWE-89"),
    (r"nosql.?inject|mongo.?inject", "CWE-943"),
    (r"ldap.?inject", "CWE-90"),
    (r"xpath.?inject", "CWE-643"),
    (r"command.?inject|os.?command|shell.?inject", "CWE-78"),
    (r"expression.?language.?inject|\bel.?inject", "CWE-917"),
    (r"template.?inject|\bssti\b", "CWE-1336"),
    (r"remote.?code.?execut|\brce\b|code.?inject", "CWE-94"),
    (r"xml.?external.?entity|\bxxe\b", "CWE-611"),
    (r"crlf.?inject|response.?splitting|header.?inject", "CWE-113"),
    (r"host.?header", "CWE-644"),
    (r"server.?side.?request.?forgery|\bssrf\b", "CWE-918"),
    (r"open.?redirect|unvalidated.?redirect", "CWE-601"),
    (r"prototype.?pollution", "CWE-1321"),
    (r"insecure.?deseri|deserializ", "CWE-502"),
    (r"unrestricted.?file.?upload|file.?upload", "CWE-434"),
    (r"local.?file.?inclus|remote.?file.?inclus|\blfi\b|\brfi\b", "CWE-98"),
    (r"path.?traversal|directory.?traversal", "CWE-22"),
    (r"\bdom.?based\b.*xss|reflected.?xss|stored.?xss|cross.?site.?script|\bxss\b", "CWE-79"),
    (r"cross.?site.?request.?forgery|\bcsrf\b", "CWE-352"),
    (r"insecure.?direct.?object|\bidor\b|authoriz.*object", "CWE-639"),

    # ── Security headers, cookies, session, CORS, misconfig ────────────────
    (r"clickjack|anti.?clickjack|x.frame.?options", "CWE-1021"),
    (r"content.?security.?policy|\bcsp\b", "CWE-693"),
    (r"x.content.?type|nosniff|mime.?sniff", "CWE-693"),
    (r"permissions.?policy|feature.?policy", "CWE-693"),
    (r"referrer.?policy", "CWE-200"),
    (r"cross.?site.?tracing|\bxst\b|trace.?method|http.?trace", "CWE-693"),
    (r"cacheable|cache.?control|browser.?cache", "CWE-525"),
    (r"cookie.*secure.?flag|secure.?flag.*cookie|cookie.*without.?secure", "CWE-614"),
    (r"cookie.*samesite|samesite.*cookie", "CWE-1275"),
    (r"cookie.*http.?only|http.?only.*cookie|cookie.*httponly", "CWE-1004"),
    (r"session.?id.*url|session.*url.?rewrite|sensitive.*query.?string", "CWE-598"),
    (r"session.?fixation", "CWE-384"),
    (r"\bcors\b|cross.?domain.?miscon|access.?control.?allow.?origin", "CWE-942"),
    (r"directory.?listing|directory.?brows|directory.?index", "CWE-548"),
    (r"http.?method|dangerous.?method|\bput\b.?method|\bdelete\b.?method|webdav", "CWE-650"),
    (r"security.?misconfigur|misconfigur", "CWE-16"),

    # ── Transport / cryptography ───────────────────────────────────────────
    (r"certificate.*(expir|invalid|self.?sign|mismatch|untrust)|invalid.?cert", "CWE-295"),
    (r"weak.?cipher|weak.?ssl|weak.?tls|sslv2|sslv3|\brc4\b|weak.?protocol|insecure.?cipher", "CWE-326"),
    (r"\bmd5\b|sha.?1\b|weak.?hash|broken.?crypto|risky.?crypto", "CWE-327"),
    (r"mixed.?content", "CWE-311"),
    (r"hsts|strict.?transport", "CWE-311"),
    (r"cleartext|plain.?text.?password", "CWE-312"),
    (r"insecure.?random|predictable.?random|weak.?random", "CWE-330"),
    (r"subresource.?integrity|missing.?sri", "CWE-353"),

    # ── Authentication & credentials ───────────────────────────────────────
    (r"default.?credential|default.?password", "CWE-1392"),
    (r"hard.?coded.?(credential|password|secret)|exposed.?(api.?key|secret|token)", "CWE-798"),
    (r"weak.?password|password.?complexity|password.?policy", "CWE-521"),
    (r"broken.?auth|authentication.?bypass|auth.?bypass", "CWE-287"),
    (r"missing.?auth|no.?authentication|unauthenticated.?access", "CWE-306"),
    (r"privilege.?escal|broken.?access|improper.?access", "CWE-269"),

    # ── Information disclosure (general — keep AFTER the specifics above) ───
    (r"stack.?trace|error.?message|application.?error|debug.?message|verbose.?error", "CWE-209"),
    (r"debug.?mode|debug.?enabled|active.?debug", "CWE-489"),
    (r"source.?code.?disclos|source.?code.?leak", "CWE-540"),
    (r"backup.?file|\.bak\b|old.?file.?disclos", "CWE-530"),
    (r"suspicious.?comment|html.?comment|source.?comment", "CWE-615"),
    (r"autocomplete", "CWE-522"),
    (r"sensitive.?data|information.?disclos|info.?leak|version.?disclos|banner.?disclos"
     r"|private.?ip|internal.?ip|timestamp.?disclos|swagger|api.?docs|graphql.?introspect", "CWE-200"),

    # ── Memory safety (non-web, kept for infra/binary findings) ────────────
    (r"use.?after.?free", "CWE-416"),
    (r"buffer.?overflow", "CWE-120"),
    (r"integer.?overflow", "CWE-190"),
    (r"race.?condition", "CWE-362"),
    (r"null.?pointer|null.?deref", "CWE-476"),
]

# Static CWE descriptions for the reference table seed
CWE_DESCRIPTIONS = {
    "CWE-89": ("SQL Injection", "Web", "A2 Injection"),
    "CWE-79": ("Cross-site Scripting (XSS)", "Web", "A7 XSS"),
    "CWE-352": ("CSRF", "Web", "A1 Broken Access Control"),
    "CWE-22": ("Path Traversal", "Web", "A1 Broken Access Control"),
    "CWE-78": ("OS Command Injection", "Web", "A2 Injection"),
    "CWE-611": ("XML External Entity (XXE)", "Web", "A2 Injection"),
    "CWE-502": ("Insecure Deserialization", "Web", "A8 Software Integrity"),
    "CWE-918": ("SSRF", "Web", "A10 SSRF"),
    "CWE-601": ("Open Redirect", "Web", "A1 Broken Access Control"),
    "CWE-90": ("LDAP Injection", "Web", "A2 Injection"),
    "CWE-94": ("Code Injection / RCE", "Web", "A2 Injection"),
    "CWE-434": ("Unrestricted File Upload", "Web", "A4 Insecure Design"),
    "CWE-287": ("Improper Authentication", "Web", "A7 Auth Failures"),
    "CWE-306": ("Missing Authentication", "Web", "A7 Auth Failures"),
    "CWE-269": ("Improper Privilege Management", "Web", "A1 Broken Access Control"),
    "CWE-200": ("Exposure of Sensitive Information", "Web", "A2 Cryptographic Failures"),
    "CWE-1021": ("Improper Restriction of Rendered UI Layers (Clickjacking)", "Web", "A5 Security Misconfiguration"),
    "CWE-16": ("Configuration", "Web", "A5 Security Misconfiguration"),
    "CWE-521": ("Weak Password Requirements", "Web", "A7 Auth Failures"),
    "CWE-312": ("Cleartext Storage of Sensitive Information", "Web", "A2 Cryptographic Failures"),
    "CWE-1004": ("Sensitive Cookie Without HttpOnly Flag", "Web", "A5 Security Misconfiguration"),
    "CWE-311": ("Missing Encryption of Sensitive Data", "Web", "A2 Cryptographic Failures"),
    "CWE-942": ("Permissive CORS Policy", "Web", "A5 Security Misconfiguration"),
    "CWE-943": ("NoSQL / Data Query Injection", "Web", "A3 Injection"),
    "CWE-917": ("Expression Language Injection", "Web", "A3 Injection"),
    "CWE-1336": ("Server-Side Template Injection", "Web", "A3 Injection"),
    "CWE-113": ("HTTP Response Splitting (CRLF)", "Web", "A3 Injection"),
    "CWE-644": ("Improper Neutralization of HTTP Headers", "Web", "A3 Injection"),
    "CWE-1321": ("Prototype Pollution", "Web", "A8 Software Integrity"),
    "CWE-98": ("File Inclusion (LFI/RFI)", "Web", "A3 Injection"),
    "CWE-639": ("Authorization Bypass (IDOR)", "Web", "A1 Broken Access Control"),
    "CWE-643": ("XPath Injection", "Web", "A3 Injection"),
    "CWE-693": ("Protection Mechanism Failure (missing security header)", "Web", "A5 Security Misconfiguration"),
    "CWE-525": ("Sensitive Information in Browser Cache", "Web", "A5 Security Misconfiguration"),
    "CWE-614": ("Sensitive Cookie Without Secure Flag", "Web", "A5 Security Misconfiguration"),
    "CWE-1275": ("Sensitive Cookie With Improper SameSite Attribute", "Web", "A5 Security Misconfiguration"),
    "CWE-598": ("Sensitive Data in GET Query String / URL", "Web", "A2 Cryptographic Failures"),
    "CWE-384": ("Session Fixation", "Web", "A7 Auth Failures"),
    "CWE-548": ("Information Exposure Through Directory Listing", "Web", "A5 Security Misconfiguration"),
    "CWE-650": ("Trusting HTTP Permission Methods on the Server", "Web", "A5 Security Misconfiguration"),
    "CWE-295": ("Improper Certificate Validation", "Web", "A2 Cryptographic Failures"),
    "CWE-326": ("Inadequate Encryption Strength", "Web", "A2 Cryptographic Failures"),
    "CWE-327": ("Broken or Risky Cryptographic Algorithm", "Web", "A2 Cryptographic Failures"),
    "CWE-330": ("Use of Insufficiently Random Values", "Web", "A2 Cryptographic Failures"),
    "CWE-353": ("Missing Support for Integrity Check (SRI)", "Web", "A8 Software Integrity"),
    "CWE-798": ("Use of Hard-coded Credentials", "Web", "A7 Auth Failures"),
    "CWE-209": ("Error Message Containing Sensitive Information", "Web", "A5 Security Misconfiguration"),
    "CWE-489": ("Active Debug Code", "Web", "A5 Security Misconfiguration"),
    "CWE-540": ("Sensitive Information in Source Code", "Web", "A5 Security Misconfiguration"),
    "CWE-530": ("Exposure of Backup File", "Web", "A5 Security Misconfiguration"),
    "CWE-615": ("Sensitive Information in Source Code Comments", "Web", "A5 Security Misconfiguration"),
    "CWE-522": ("Insufficiently Protected Credentials", "Web", "A7 Auth Failures"),
    "CWE-1392": ("Use of Default Credentials", "Web", "A7 Auth Failures"),
    "CWE-416": ("Use After Free", "Memory", "A6 Vulnerable Components"),
    "CWE-120": ("Buffer Overflow", "Memory", "A6 Vulnerable Components"),
    "CWE-190": ("Integer Overflow", "Memory", "A6 Vulnerable Components"),
    "CWE-362": ("Race Condition", "Concurrency", "A4 Insecure Design"),
    "CWE-476": ("NULL Pointer Dereference", "Memory", "A6 Vulnerable Components"),
}

# Precompiled for speed (map_all_unclassified iterates many findings x patterns).
_COMPILED_CWE_MAP = [(re.compile(p, re.I), cwe) for p, cwe in KEYWORD_CWE_MAP]


class CweMapper:
    def map_finding(self, finding: NormalizedFinding) -> str | None:
        """Return a CWE ID for a finding, updating the finding in place."""
        if finding.cwe_id:
            return finding.cwe_id

        text = " ".join(filter(None, [finding.title, finding.description]))
        cwe_id = self._keyword_match(text)

        if cwe_id:
            finding.cwe_id = cwe_id
            db.session.add(finding)

        return cwe_id

    def map_all_unclassified(self) -> int:
        """Process all findings missing a CWE ID. Returns count updated."""
        findings = NormalizedFinding.query.filter(
            NormalizedFinding.cwe_id.is_(None)
        ).all()
        updated = 0
        for f in findings:
            if self.map_finding(f):
                updated += 1
        db.session.commit()
        return updated

    @staticmethod
    def _keyword_match(text: str) -> str | None:
        text_lower = text.lower()
        for pattern, cwe in _COMPILED_CWE_MAP:
            if pattern.search(text_lower):
                return cwe
        return None

    @staticmethod
    def seed_cwe_table() -> int:
        """Populate CweMapping reference table if empty."""
        if CweMapping.query.count() > 0:
            return 0
        added = 0
        for cwe_id, (name, category, owasp) in CWE_DESCRIPTIONS.items():
            mapping = CweMapping(
                cwe_id=cwe_id,
                name=name,
                category=category,
                owasp_category=owasp,
            )
            db.session.add(mapping)
            added += 1
        db.session.commit()
        return added
