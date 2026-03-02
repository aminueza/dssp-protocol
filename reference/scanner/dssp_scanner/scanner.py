"""Base scanner interface and result types."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class ScanFinding:
    """A single PII finding from a scanner."""

    field_path: (
        str  # JSONPath to the field (e.g., "extractions[0].fields.account_holder")
    )
    entity_type: str  # Type of PII found (e.g., "PERSON", "IBAN", "SSN")
    confidence: float  # Scanner confidence (0.0-1.0)
    value_snippet: str  # Truncated value for logging (first 3 chars + "...")
    scanner_type: str  # Which scanner found this

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanVerdict:
    """Result of a single scanner run."""

    scanner_type: str
    scanner_version: str
    passed: bool
    findings: list[ScanFinding] = field(default_factory=list)
    statistics: dict[str, Any] = field(default_factory=dict)
    action_taken: str = "none"  # "none", "redacted", "blocked", "flagged"
    scan_duration_ms: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


class ResultScanner(ABC):
    """Base class for DSSP result scanners."""

    @property
    @abstractmethod
    def scanner_type(self) -> str:
        """Return the scanner type identifier."""
        ...

    @property
    @abstractmethod
    def scanner_version(self) -> str:
        """Return the scanner version."""
        ...

    @abstractmethod
    def scan(self, result: dict, contract: dict | None = None) -> ScanVerdict:
        """
        Scan a DSSP result envelope for PII leakage.

        Args:
            result: The DSSP result envelope (parsed JSON).
            contract: Optional contract for context (redaction rules, allowed fields).

        Returns:
            ScanVerdict with findings and pass/fail status.
        """
        ...

    def _extract_text_values(self, result: dict) -> list[tuple[str, str]]:
        """Extract all text values from a result envelope with their JSON paths."""
        values = []
        for i, extraction in enumerate(result.get("extractions", [])):
            # Fields
            for key, val in extraction.get("fields", {}).items():
                if isinstance(val, str):
                    values.append((f"extractions[{i}].fields.{key}", val))

            # Tables
            for j, table in enumerate(extraction.get("tables", [])):
                for k, row in enumerate(table.get("rows", [])):
                    for col_idx, cell in enumerate(row):
                        if isinstance(cell, str):
                            col_name = (
                                table.get("columns", [{}])[col_idx].get(
                                    "name", f"col{col_idx}"
                                )
                                if col_idx < len(table.get("columns", []))
                                else f"col{col_idx}"
                            )
                            values.append(
                                (
                                    f"extractions[{i}].tables[{j}].rows[{k}][{col_idx}]({col_name})",
                                    cell,
                                )
                            )

            # Classification labels
            for j, cls in enumerate(extraction.get("classifications", [])):
                label = cls.get("label", "")
                if isinstance(label, str):
                    values.append(
                        (f"extractions[{i}].classifications[{j}].label", label)
                    )

        return values

    def _extract_numeric_values(self, result: dict) -> list[tuple[str, float]]:
        """Extract all numeric values from a result envelope with their JSON paths."""
        values = []
        for i, extraction in enumerate(result.get("extractions", [])):
            for key, val in extraction.get("fields", {}).items():
                if isinstance(val, (int, float)):
                    values.append((f"extractions[{i}].fields.{key}", float(val)))

            for j, table in enumerate(extraction.get("tables", [])):
                for k, row in enumerate(table.get("rows", [])):
                    for col_idx, cell in enumerate(row):
                        if isinstance(cell, (int, float)):
                            values.append(
                                (
                                    f"extractions[{i}].tables[{j}].rows[{k}][{col_idx}]",
                                    float(cell),
                                )
                            )

        # Attestation numeric fields
        claims = result.get("attestation", {}).get("claims", {})
        for key in [
            "processing_duration_ms",
            "memory_peak_bytes",
            "network_egress_bytes",
        ]:
            if key in claims and isinstance(claims[key], (int, float)):
                values.append((f"attestation.claims.{key}", float(claims[key])))

        for i, ext in enumerate(result.get("extractions", [])):
            if "confidence" in ext:
                values.append(
                    (f"extractions[{i}].confidence", float(ext["confidence"]))
                )

        return values
