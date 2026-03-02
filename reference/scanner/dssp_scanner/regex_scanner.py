"""Regex-based PII scanner with comprehensive pattern library."""

from __future__ import annotations

import re
import time
from .scanner import ResultScanner, ScanVerdict, ScanFinding

# PII regex patterns — comprehensive library
PII_PATTERNS: dict[str, list[re.Pattern]] = {
    "SSN": [
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        re.compile(r"\b\d{9}\b"),  # Unformatted SSN (more false positives)
    ],
    "CREDIT_CARD": [
        re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b"
        ),
    ],
    "IBAN": [
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),
    ],
    "EMAIL": [
        re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    ],
    "PHONE": [
        re.compile(r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b"),
        re.compile(r"\b\+?[0-9]{1,3}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{4,10}\b"),
    ],
    "IP_ADDRESS": [
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ),
    ],
    "PASSPORT": [
        re.compile(r"\b[A-Z]{1,2}[0-9]{6,9}\b"),
    ],
    "BSN": [  # Dutch citizen service number
        re.compile(r"\b[0-9]{9}\b"),
    ],
    "DATE_OF_BIRTH": [
        re.compile(
            r"\b(?:0[1-9]|[12][0-9]|3[01])[-/](?:0[1-9]|1[0-2])[-/](?:19|20)\d{2}\b"
        ),
        re.compile(
            r"\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12][0-9]|3[01])\b"
        ),
    ],
}


class RegexScanner(ResultScanner):
    """Regex-based PII scanner using pattern matching."""

    def __init__(self, patterns: dict[str, list[re.Pattern]] | None = None):
        self._patterns = patterns or PII_PATTERNS

    @property
    def scanner_type(self) -> str:
        return "regex"

    @property
    def scanner_version(self) -> str:
        return "1.0.0"

    def scan(self, result: dict, contract: dict | None = None) -> ScanVerdict:
        start = time.monotonic()
        findings: list[ScanFinding] = []
        allowed_fields = set()

        # Build set of allowed PII fields from contract
        if contract:
            rules = (
                contract.get("restrictions", {})
                .get("result_policy", {})
                .get("pii_redaction_rules", {})
            )
            for field_type, method in rules.items():
                if method == "allow":
                    allowed_fields.add(field_type.lower())

        # Scan all text values
        text_values = self._extract_text_values(result)
        stats = {
            "fields_scanned": len(text_values),
            "patterns_checked": len(self._patterns),
        }

        for path, value in text_values:
            for entity_type, patterns in self._patterns.items():
                # Skip if this entity type is explicitly allowed
                if entity_type.lower() in allowed_fields:
                    continue
                for pattern in patterns:
                    if pattern.search(value):
                        snippet = value[:3] + "..." if len(value) > 3 else value
                        findings.append(
                            ScanFinding(
                                field_path=path,
                                entity_type=entity_type,
                                confidence=0.9,  # Regex matches are high confidence
                                value_snippet=snippet,
                                scanner_type="regex",
                            )
                        )
                        break  # One match per entity type per field is enough

        elapsed_ms = int((time.monotonic() - start) * 1000)
        stats["findings_count"] = len(findings)

        return ScanVerdict(
            scanner_type="regex",
            scanner_version=self.scanner_version,
            passed=len(findings) == 0,
            findings=findings,
            statistics=stats,
            action_taken="blocked" if findings else "none",
            scan_duration_ms=elapsed_ms,
        )
