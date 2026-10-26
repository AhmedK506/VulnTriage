"""
Lightweight test double for the Confidence Engine unit tests.

`FindingStub` duck-types the subset of `NormalizedFinding` that
`ConfidenceEngine.compute_score` reads, so the engine's scoring logic can be
unit-tested on defined inputs without a database or app context. It carries no
evaluation dataset — each test constructs the specific finding it needs.
"""

from dataclasses import dataclass, field


@dataclass
class _MLPred:
    predicted_priority: str | None = None


@dataclass
class _PoC:
    result: str  # "confirmed" | "not_confirmed" | "error"
    # A strong, vuln-specific type by default so a "confirmed" PoC exercises the
    # hard-override (see ConfidenceEngine.STRONG_POC_TYPES).
    validation_type: str = "sqli_check"


@dataclass
class _PoCManager:
    """Mimics finding.poc_validations (a dynamic relationship with .all())."""
    items: list = field(default_factory=list)

    def all(self):
        return self.items


@dataclass
class _Vuln:
    raw_data: dict = field(default_factory=dict)


@dataclass
class FindingStub:
    title: str
    is_true_positive: bool
    severity: str = "Medium"
    scanner_count: int = 1
    scanner_sources: list = field(default_factory=list)
    cve_id: str | None = None
    cwe_id: str | None = None
    attack_vector: str | None = None          # presence => CVSS vector available
    exploit_available: bool = False
    _ml_priority: str | None = None
    _poc_results: list = field(default_factory=list)
    _poc_type: str = "sqli_check"      # strong by default; set weak to test override
    _raw_exploit: str | None = None

    # --- duck-typed accessors the engine expects -------------------------
    @property
    def ml_prediction(self):
        return _MLPred(self._ml_priority) if self._ml_priority else None

    @property
    def poc_validations(self):
        return _PoCManager([_PoC(r, self._poc_type) for r in self._poc_results])

    @property
    def source_vulnerability(self):
        if self._raw_exploit is not None:
            return _Vuln({"exploit_available": self._raw_exploit})
        return None

    # engine never reads these on a stub, but keep the attribute surface sane
    confidence_score = None
    classification = None
    id = None
