"""
Deduplication Engine

Two findings are considered duplicates when they share the same:
  - Vulnerability name (normalised)
  - Target URL (normalised)
  - Parameter
  - CWE ID

A SHA-256 hash of these four fields is the group_hash.
Findings with the same group_hash from different scanners are merged:
  - scanner_count is incremented
  - scanner_sources list is extended
  - The highest CVSS score is kept
"""

import hashlib
import re
from app import db
from app.models.normalized_finding import NormalizedFinding


class DeduplicationEngine:
    @staticmethod
    def compute_hash(
        name: str,
        url: str | None,
        parameter: str | None,
        cwe_id: str | None,
    ) -> str:
        name_norm = DeduplicationEngine._normalise_name(name)
        url_norm = DeduplicationEngine._normalise_url(url)
        param_norm = (parameter or "").strip().lower()
        cwe_norm = (cwe_id or "").strip().upper()

        raw = f"{name_norm}|{url_norm}|{param_norm}|{cwe_norm}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _normalise_name(name: str) -> str:
        if not name:
            return ""
        # Lowercase, collapse whitespace, strip non-alphanumeric except spaces
        n = name.lower().strip()
        n = re.sub(r"\s+", " ", n)
        n = re.sub(r"[^a-z0-9 ]", "", n)
        return n

    @staticmethod
    def _normalise_url(url: str | None) -> str:
        if not url:
            return ""
        # Strip query string and fragment to match on path only
        u = url.strip().lower().split("?")[0].split("#")[0]
        # Remove trailing slash
        return u.rstrip("/")

    def merge_duplicates(self) -> int:
        """
        After normalisation, find NormalizedFindings that share a group_hash
        and merge the non-primary ones into the primary (lowest id).
        Returns the number of duplicate rows removed.
        """
        from sqlalchemy import func

        # Find group_hashes that appear more than once
        duplicated = (
            db.session.query(NormalizedFinding.group_hash)
            .group_by(NormalizedFinding.group_hash)
            .having(func.count(NormalizedFinding.id) > 1)
            .all()
        )

        removed = 0
        for (group_hash,) in duplicated:
            findings = (
                NormalizedFinding.query
                .filter_by(group_hash=group_hash)
                .order_by(NormalizedFinding.id)
                .all()
            )
            primary = findings[0]
            duplicates = findings[1:]

            # Merge scanner sources and counts into primary
            all_sources = set(primary.scanner_sources or [])
            for dup in duplicates:
                all_sources.update(dup.scanner_sources or [])
                # Keep highest CVSS
                if dup.cvss_score and (
                    primary.cvss_score is None or dup.cvss_score > primary.cvss_score
                ):
                    primary.cvss_score = dup.cvss_score
                    primary.cvss_vector = dup.cvss_vector

            primary.scanner_sources = sorted(all_sources)
            primary.scanner_count = len(all_sources)

            for dup in duplicates:
                db.session.delete(dup)
                removed += 1

        db.session.commit()
        return removed
