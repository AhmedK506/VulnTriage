"""
Auto Scan orchestrator (optional orchestration layer).

Drives the external scanners against a target, ingests each native report through
the normal parser, then runs the **unified** triage pipeline once across ALL
findings — so cross-scanner duplicates merge (raising scanner_count → confidence)
exactly as if the reports had been uploaded manually.

Authorisation: a target is required and the caller must pass authorise=True
(the CLI/GUI surface an explicit acknowledgement). Active scanning is intrusive.

Reuses: app.parsers.parse_scanner_file + the existing engines + ReportGenerator.
"""

import os
import uuid
import tempfile
from datetime import datetime

from app import db
from app.models.user import User
from app.models.scanner_upload import ScannerUpload
from app.parsers import parse_scanner_file
from app.engines.scanner_runner import (
    run_scanner, ScannerError, scanner_availability, normalise_target)

from app.engines.normalisation import NormalisationEngine
from app.engines.deduplication import DeduplicationEngine
from app.engines.cwe_mapper import CweMapper
from app.engines.nvd_enrichment import NvdEnrichmentEngine
from app.engines.cwe_cvss_enrichment import CweCvssEnrichmentEngine
from app.engines.confidence_engine import ConfidenceEngine

_EXT = {"zap": "xml", "nuclei": "jsonl"}


class AutoScanError(RuntimeError):
    pass


class AutoScanOrchestrator:
    def run(self, target: str, scanners: list[str], user_id: int,
            authorise: bool = False, search_exploits: bool = False,
            run_poc: bool = False, poc_scope=None, progress=None) -> dict:
        if not target:
            raise AutoScanError("target is required")
        if not authorise:
            raise AutoScanError("active scanning not authorised — pass authorise=True")
        if not scanners:
            raise AutoScanError("no scanners selected")

        # Clean the target once (drop SPA '#/...' fragment, default the scheme) so
        # every scanner, the emitted progress, and the stored result agree on it.
        target = normalise_target(target)

        def emit(msg):
            if progress:
                progress(msg)

        avail = scanner_availability()
        results = {"target": target, "scanners": {}, "upload_ids": []}
        upload_ids = []

        with tempfile.TemporaryDirectory(prefix="vt_autoscan_") as workdir:
            for name in scanners:
                if not avail.get(name, {}).get("available"):
                    results["scanners"][name] = {"status": "unavailable",
                                                 "reason": avail.get(name, {}).get("reason", "n/a")}
                    emit(f"{name}: unavailable — {results['scanners'][name]['reason']}")
                    continue
                emit(f"Running {name} against {target} …")
                try:
                    report_path = run_scanner(name, target, workdir)
                except ScannerError as e:
                    results["scanners"][name] = {"status": "error", "reason": str(e)}
                    emit(f"{name}: error — {e}")
                    continue

                upload = self._ingest(report_path, name, user_id)
                NormalisationEngine().normalise_upload(upload.id)
                upload_ids.append(upload.id)
                results["scanners"][name] = {"status": "ok",
                                             "findings": upload.vulnerability_count,
                                             "upload_id": upload.id}
                emit(f"{name}: {upload.vulnerability_count} findings ingested")

        if not upload_ids:
            detail = "; ".join(
                f"{n}: {i.get('status')}" + (f" ({i['reason']})" if i.get("reason") else "")
                for n, i in results["scanners"].items()
            )
            raise AutoScanError(f"No scanner produced ingestable results — {detail}")
        results["upload_ids"] = upload_ids

        # ── Unified triage across all scanners' findings ──────────────────────
        emit("Deduplicating across scanners …")
        results["duplicates_removed"] = DeduplicationEngine().merge_duplicates()
        emit("Mapping CWEs …");            CweMapper().map_all_unclassified()
        emit("Enriching from NVD …")
        try:
            NvdEnrichmentEngine().enrich_all_pending()
        except Exception as e:
            results["nvd_warning"] = str(e)
        emit("Inferring CVSS vectors from CWE …")
        results["cwe_vector_inferred"] = CweCvssEnrichmentEngine().enrich_all_pending()

        emit("ML prioritising …")
        try:
            from app.ml.predictor import VulnerabilityPredictor
            results["ml_predicted"] = VulnerabilityPredictor().predict_all_unpredicted()
        except FileNotFoundError as e:
            results["ml_warning"] = str(e)

        if search_exploits:
            emit("Searching Exploit-DB …")
            from app.engines.exploit_search import ExploitSearchEngine
            results["exploit_search"] = ExploitSearchEngine().enrich_all()

        emit("Confidence scoring …")
        results["confidence_scored"] = ConfidenceEngine().score_all()

        if run_poc:
            emit("Running PoC validation …")
            results["poc_validated"] = self._run_poc(upload_ids, poc_scope)

        emit("Generating report …")
        results["report_id"] = self._report(upload_ids, user_id, target)
        return results

    # ── helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _ingest(report_path: str, scanner: str, user_id: int) -> ScannerUpload:
        import shutil
        from flask import current_app
        upload_dir = current_app.config["UPLOAD_FOLDER"]
        os.makedirs(upload_dir, exist_ok=True)
        unique = f"{uuid.uuid4().hex}.{_EXT.get(scanner, 'dat')}"
        dest = os.path.join(upload_dir, unique)
        # Copy out of the temp workdir into the managed upload folder.
        shutil.copyfile(report_path, dest)
        upload = ScannerUpload(
            user_id=user_id, filename=unique,
            original_filename=os.path.basename(report_path),
            scanner_type=scanner, file_size=os.path.getsize(dest),
            file_path=dest, status="processing",
        )
        db.session.add(upload)
        db.session.commit()
        try:
            count = parse_scanner_file(upload, dest, scanner)
            upload.status = "completed"
            upload.vulnerability_count = count
            upload.processed_at = datetime.utcnow()
        except Exception as exc:
            upload.status = "failed"
            upload.error_message = str(exc)
        db.session.commit()
        return upload

    @staticmethod
    def _run_poc(upload_ids: list[int], poc_scope) -> int:
        from app.engines.poc_validator import PocValidator
        from app.models.normalized_finding import NormalizedFinding
        from app.models.vulnerability import Vulnerability
        validator = PocValidator(scope=poc_scope)
        findings = (NormalizedFinding.query
                    .join(NormalizedFinding.source_vulnerability)
                    .filter(Vulnerability.upload_id.in_(upload_ids))
                    .filter(NormalizedFinding.url.isnot(None)).limit(40).all())
        n = 0
        for f in findings:
            try:
                validator.validate_finding(f); n += 1
            except Exception:
                pass
        db.session.commit()
        return n

    @staticmethod
    def _report(upload_ids: list[int], user_id: int, target: str) -> int | None:
        from app.engines.report_generator import ReportGenerator
        from app.models.report import Report
        rpt = Report(user_id=user_id,
                     title=f"Auto Scan Report — {target} — {datetime.utcnow().strftime('%d %b %Y')}",
                     report_type="pdf", status="pending", upload_ids=upload_ids)
        db.session.add(rpt)
        db.session.commit()
        try:
            ReportGenerator().generate(rpt.id, ai_summary=True)
            return rpt.id
        except Exception:
            return None
