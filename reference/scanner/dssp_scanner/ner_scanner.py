"""NER-based PII scanner wrapping Microsoft Presidio."""

from __future__ import annotations

import time
from .scanner import ResultScanner, ScanVerdict, ScanFinding

try:
    from presidio_analyzer import AnalyzerEngine

    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False


class NERScanner(ResultScanner):
    """Named Entity Recognition scanner using Presidio."""

    def __init__(
        self,
        languages: list[str] | None = None,
        entity_types: list[str] | None = None,
        confidence_threshold: float = 0.7,
    ):
        self._languages = languages or ["en"]
        self._entity_types = entity_types or [
            "PERSON",
            "PHONE_NUMBER",
            "EMAIL_ADDRESS",
            "CREDIT_CARD",
            "IBAN_CODE",
            "US_SSN",
            "LOCATION",
            "ORGANIZATION",
        ]
        self._confidence_threshold = confidence_threshold
        self._analyzer: AnalyzerEngine | None = None

    def _get_analyzer(self) -> AnalyzerEngine:
        if not PRESIDIO_AVAILABLE:
            raise RuntimeError(
                "presidio-analyzer is not installed. "
                "Install with: pip install presidio-analyzer presidio-anonymizer spacy && "
                "python -m spacy download en_core_web_lg"
            )
        if self._analyzer is None:
            self._analyzer = AnalyzerEngine()
        return self._analyzer

    @property
    def scanner_type(self) -> str:
        return "ner"

    @property
    def scanner_version(self) -> str:
        version = "1.0.0"
        if PRESIDIO_AVAILABLE:
            try:
                import presidio_analyzer

                version = f"1.0.0+presidio-{presidio_analyzer.__version__}"
            except Exception:
                pass
        return version

    def scan(self, result: dict, contract: dict | None = None) -> ScanVerdict:
        start = time.monotonic()
        findings: list[ScanFinding] = []

        text_values = self._extract_text_values(result)
        stats = {
            "fields_scanned": len(text_values),
            "presidio_available": PRESIDIO_AVAILABLE,
            "languages": self._languages,
            "entity_types": self._entity_types,
            "confidence_threshold": self._confidence_threshold,
        }

        if not PRESIDIO_AVAILABLE:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return ScanVerdict(
                scanner_type="ner",
                scanner_version=self.scanner_version,
                passed=False,
                findings=[],
                statistics={**stats, "error": "presidio not available"},
                action_taken="error",
                scan_duration_ms=elapsed_ms,
            )

        analyzer = self._get_analyzer()

        for path, value in text_values:
            if not value or len(value) < 2:
                continue

            for lang in self._languages:
                try:
                    results = analyzer.analyze(
                        text=value,
                        language=lang,
                        entities=self._entity_types,
                        score_threshold=self._confidence_threshold,
                    )
                except Exception:
                    continue

                for r in results:
                    snippet = value[:3] + "..." if len(value) > 3 else value
                    findings.append(
                        ScanFinding(
                            field_path=path,
                            entity_type=r.entity_type,
                            confidence=r.score,
                            value_snippet=snippet,
                            scanner_type="ner",
                        )
                    )

        elapsed_ms = int((time.monotonic() - start) * 1000)
        stats["findings_count"] = len(findings)

        return ScanVerdict(
            scanner_type="ner",
            scanner_version=self.scanner_version,
            passed=len(findings) == 0,
            findings=findings,
            statistics=stats,
            action_taken="blocked" if findings else "none",
            scan_duration_ms=elapsed_ms,
        )
