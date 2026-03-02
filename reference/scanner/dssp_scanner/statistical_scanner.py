"""Statistical scanner for detecting steganographic encoding in numeric fields."""

from __future__ import annotations

import time
from collections import Counter
from .scanner import ResultScanner, ScanVerdict, ScanFinding


# Benford's law expected distribution for first digits
BENFORD_EXPECTED = {
    1: 0.301,
    2: 0.176,
    3: 0.125,
    4: 0.097,
    5: 0.079,
    6: 0.067,
    7: 0.058,
    8: 0.051,
    9: 0.046,
}


class StatisticalScanner(ResultScanner):
    """Statistical scanner for detecting data encoding in numeric fields."""

    def __init__(
        self,
        max_decimal_places: int = 2,
        max_significant_digits: int = 12,
        benford_chi2_threshold: float = 15.51,  # chi-squared critical value for df=8, p=0.05
    ):
        self._max_decimal_places = max_decimal_places
        self._max_significant_digits = max_significant_digits
        self._benford_threshold = benford_chi2_threshold

    @property
    def scanner_type(self) -> str:
        return "statistical"

    @property
    def scanner_version(self) -> str:
        return "1.0.0"

    def _count_decimal_places(self, value: float) -> int:
        """Count the number of decimal places in a float.

        Uses str() for faithful representation — avoids IEEE 754 artifacts
        from format specifiers like .20g which turn 892341.2 into
        892341.19999999995...
        """
        s = str(value)
        if "." not in s:
            return 0
        return len(s.split(".")[1].rstrip("0"))

    def _count_significant_digits(self, value: float) -> int:
        """Count significant digits."""
        if value == 0:
            return 1
        s = str(abs(value))
        s = s.replace(".", "").lstrip("0")
        return len(s.rstrip("0")) if s else 1

    def _benford_test(self, values: list[float]) -> tuple[float, bool]:
        """Run Benford's law test on first digits. Returns (chi2, passed)."""
        first_digits = []
        for v in values:
            if v == 0:
                continue
            s = f"{abs(v):.20g}".lstrip("0").lstrip(".")
            if s and s[0].isdigit() and s[0] != "0":
                first_digits.append(int(s[0]))

        if len(first_digits) < 30:  # Need minimum sample size
            return 0.0, True

        n = len(first_digits)
        counts = Counter(first_digits)
        chi2 = 0.0
        for digit in range(1, 10):
            observed = counts.get(digit, 0)
            expected = BENFORD_EXPECTED[digit] * n
            if expected > 0:
                chi2 += (observed - expected) ** 2 / expected

        return chi2, chi2 < self._benford_threshold

    def scan(self, result: dict, contract: dict | None = None) -> ScanVerdict:
        start = time.monotonic()
        findings: list[ScanFinding] = []

        # Get precision policy from contract if available
        if contract:
            policy = (
                contract.get("restrictions", {})
                .get("result_policy", {})
                .get("numeric_precision_policy", {})
            )
            if "max_decimal_places" in policy:
                self._max_decimal_places = policy["max_decimal_places"]
            if "max_significant_digits" in policy:
                self._max_significant_digits = policy["max_significant_digits"]

        numeric_values = self._extract_numeric_values(result)
        stats = {
            "numeric_fields_scanned": len(numeric_values),
            "max_decimal_places": self._max_decimal_places,
            "max_significant_digits": self._max_significant_digits,
        }

        # Check individual field precision
        for path, value in numeric_values:
            dp = self._count_decimal_places(value)
            if dp > self._max_decimal_places:
                findings.append(
                    ScanFinding(
                        field_path=path,
                        entity_type="PRECISION_VIOLATION",
                        confidence=1.0,
                        value_snippet=f"{value:.6g}",
                        scanner_type="statistical",
                    )
                )

            sd = self._count_significant_digits(value)
            if sd > self._max_significant_digits:
                findings.append(
                    ScanFinding(
                        field_path=path,
                        entity_type="SIGNIFICANT_DIGITS_VIOLATION",
                        confidence=1.0,
                        value_snippet=f"{value:.6g}",
                        scanner_type="statistical",
                    )
                )

        # Benford's law test on all numeric values
        all_values = [v for _, v in numeric_values]
        if all_values:
            chi2, benford_passed = self._benford_test(all_values)
            stats["benford_chi2"] = round(chi2, 4)
            stats["benford_passed"] = benford_passed
            if not benford_passed:
                findings.append(
                    ScanFinding(
                        field_path="(aggregate)",
                        entity_type="ENTROPY_ANOMALY",
                        confidence=0.8,
                        value_snippet=f"chi2={chi2:.2f}",
                        scanner_type="statistical",
                    )
                )

        elapsed_ms = int((time.monotonic() - start) * 1000)
        stats["findings_count"] = len(findings)

        return ScanVerdict(
            scanner_type="statistical",
            scanner_version=self.scanner_version,
            passed=len(findings) == 0,
            findings=findings,
            statistics=stats,
            action_taken="blocked" if findings else "none",
            scan_duration_ms=elapsed_ms,
        )
