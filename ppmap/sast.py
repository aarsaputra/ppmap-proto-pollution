"""
Static Application Security Testing (SAST) Module for PPMAP v5.0
Scan JavaScript files for potential prototype pollution sinks without execution.
"""

import os
import re
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


@dataclass
class SASTFinding:
    """SAST vulnerability finding."""

    filepath: str
    line_number: int
    sink_type: str
    code_snippet: str
    severity: str = "MEDIUM"
    confidence: str = "medium"
    context: str = ""
    recommendation: str = ""


# Dangerous sinks that can lead to prototype pollution
DANGEROUS_SINKS = {
    # jQuery
    "$.extend": {
        "pattern": r"\$\.extend\s*\(",
        "severity": "HIGH",
        "cve": "CVE-2019-11358",
        "recommendation": "Use $.extend(true, {}, obj) with empty target or upgrade jQuery",
    },
    "jQuery.extend": {
        "pattern": r"jQuery\.extend\s*\(",
        "severity": "HIGH",
        "cve": "CVE-2019-11358",
        "recommendation": "Use jQuery.extend(true, {}, obj) with empty target",
    },
    # Lodash/Underscore
    "_.merge": {
        "pattern": r"_\.merge\s*\(",
        "severity": "HIGH",
        "cve": "CVE-2018-16487",
        "recommendation": "Update Lodash to >= 4.17.11",
    },
    "_.defaultsDeep": {
        "pattern": r"_\.defaultsDeep\s*\(",
        "severity": "HIGH",
        "cve": "CVE-2019-10744",
        "recommendation": "Update Lodash to >= 4.17.12",
    },
    "_.set": {
        "pattern": r"_\.set\s*\(",
        "severity": "MEDIUM",
        "recommendation": "Validate key path before using _.set",
    },
    "lodash.merge": {
        "pattern": r"merge\s*\([^)]*\)",
        "severity": "MEDIUM",
        "recommendation": "Validate objects before merging",
    },
    # Native JavaScript
    "Object.assign": {
        "pattern": r"Object\.assign\s*\(",
        "severity": "MEDIUM",
        "recommendation": "Ensure target is a fresh object, not Object.prototype",
    },
    "Object.defineProperty": {
        "pattern": r"Object\.defineProperty\s*\(",
        "severity": "HIGH",
        "recommendation": "Validate property names to prevent __proto__ injection",
    },
    "Object.setPrototypeOf": {
        "pattern": r"Object\.setPrototypeOf\s*\(",
        "severity": "CRITICAL",
        "recommendation": "Avoid dynamic prototype manipulation",
    },
    # JSON parsing
    "JSON.parse": {
        "pattern": r"JSON\.parse\s*\([^)]*\)",
        "severity": "LOW",
        "recommendation": "Consider using JSON.parse with reviver to filter __proto__",
    },
    # Dynamic property access
    "bracket_notation": {
        "pattern": r"\[[\w\s\[\]\.\'\"]+\]\s*=",
        "severity": "MEDIUM",
        "recommendation": "Validate property names before dynamic assignment",
    },
    # Spread operator with user input
    "spread_merge": {
        "pattern": r"\.\.\.\s*\w+",
        "severity": "LOW",
        "recommendation": "Ensure spread source is sanitized",
    },
    # Deep merge libraries
    "deepmerge": {
        "pattern": r"deepmerge\s*\(",
        "severity": "HIGH",
        "recommendation": "Use deepmerge with isMergeableObject option",
    },
    "deep-extend": {
        "pattern": r"deepExtend\s*\(",
        "severity": "HIGH",
        "cve": "CVE-2018-3750",
        "recommendation": "Replace with safer alternative or update",
    },
    "merge-deep": {
        "pattern": r"mergeDeep\s*\(",
        "severity": "HIGH",
        "recommendation": "Validate objects before deep merge",
    },
    # Hoek library
    "Hoek.merge": {
        "pattern": r"Hoek\.merge\s*\(",
        "severity": "HIGH",
        "cve": "CVE-2018-3728",
        "recommendation": "Update Hoek to >= 5.0.3",
    },
}

# Sources that could introduce tainted data
TAINTED_SOURCES = [
    r"req\.body",
    r"req\.query",
    r"req\.params",
    r"request\.body",
    r"location\.hash",
    r"location\.search",
    r"window\.location",
    r"document\.URL",
    r"JSON\.parse\s*\(\s*localStorage",
    r"JSON\.parse\s*\(\s*sessionStorage",
    r"\.getItem\s*\(",
]


class SASTScanner:
    """
    Static analyzer for JavaScript prototype pollution vulnerabilities.

    Features:
    - Scan individual files or directories
    - Detect dangerous sinks
    - Identify tainted sources
    - Generate recommendations
    """

    # File extensions to scan
    JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

    # Directories to skip
    SKIP_DIRS = {"node_modules", ".git", "dist", "build", "vendor", "min"}

    def __init__(
        self,
        max_workers: int = 4,
        skip_minified: bool = True,
        include_low_severity: bool = False,
    ):
        """
        Initialize SAST scanner.

        Args:
            max_workers: Concurrent file scanning threads
            skip_minified: Skip minified JS files
            include_low_severity: Include LOW severity findings
        """
        self.max_workers = max_workers
        self.skip_minified = skip_minified
        self.include_low_severity = include_low_severity
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile regex patterns for performance."""
        for sink_name, sink_info in DANGEROUS_SINKS.items():
            try:
                self._compiled_patterns[sink_name] = re.compile(
                    sink_info["pattern"], re.IGNORECASE
                )
            except re.error as e:
                logger.warning(f"Invalid regex for {sink_name}: {e}")

    def _is_minified(self, filepath: str, content: str) -> bool:
        """Check if file is minified."""
        if ".min." in filepath:
            return True

        # Check average line length
        lines = content.split("\n")
        if lines:
            avg_len = sum(len(l) for l in lines) / len(lines)
            if avg_len > 500:  # Very long lines suggest minification
                return True

        return False

    def scan_file(self, filepath: str) -> List[SASTFinding]:
        """
        Scan a single file for PP vulnerabilities.

        Args:
            filepath: Path to JavaScript file

        Returns:
            List of findings
        """
        findings = []

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            logger.debug(f"Could not read {filepath}: {e}")
            return findings

        # Skip minified files
        if self.skip_minified and self._is_minified(filepath, content):
            logger.debug(f"Skipping minified file: {filepath}")
            return findings

        lines = content.split("\n")

        # Check each dangerous sink
        for sink_name, pattern in self._compiled_patterns.items():
            sink_info = DANGEROUS_SINKS[sink_name]
            severity = sink_info.get("severity", "MEDIUM")

            # Skip low severity if not requested
            if severity == "LOW" and not self.include_low_severity:
                continue

            for line_num, line in enumerate(lines, 1):
                matches = pattern.finditer(line)
                for match in matches:
                    # Get context (surrounding lines)
                    start = max(0, line_num - 2)
                    end = min(len(lines), line_num + 2)
                    context_lines = lines[start:end]

                    finding = SASTFinding(
                        filepath=filepath,
                        line_number=line_num,
                        sink_type=sink_name,
                        code_snippet=line.strip()[:200],
                        severity=severity,
                        confidence=self._calculate_confidence(line, content),
                        context="\n".join(context_lines),
                        recommendation=sink_info.get("recommendation", ""),
                    )
                    findings.append(finding)

        return findings

    def _calculate_confidence(self, line: str, full_content: str) -> str:
        """Calculate confidence based on context."""
        # Check if there are tainted sources nearby
        for source_pattern in TAINTED_SOURCES:
            if re.search(source_pattern, full_content):
                return "high"

        # Check for user input indicators
        if any(
            kw in line.lower() for kw in ["input", "user", "param", "query", "body"]
        ):
            return "high"

        return "medium"

    def scan_directory(
        self, dirpath: str, exclude_patterns: Optional[List[str]] = None
    ) -> List[SASTFinding]:
        """
        Scan a directory for PP vulnerabilities.

        Args:
            dirpath: Directory path to scan
            exclude_patterns: Glob patterns to exclude

        Returns:
            List of all findings
        """
        findings = []
        files_to_scan = []
        exclude_patterns = exclude_patterns or []

        # Collect files to scan
        for root, dirs, files in os.walk(dirpath):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

            for filename in files:
                ext = Path(filename).suffix.lower()
                if ext not in self.JS_EXTENSIONS:
                    continue

                filepath = os.path.join(root, filename)

                # Check exclude patterns
                excluded = False
                for pattern in exclude_patterns:
                    if pattern in filepath:
                        excluded = True
                        break

                if not excluded:
                    files_to_scan.append(filepath)

        logger.info(f"Scanning {len(files_to_scan)} JavaScript files...")

        # Parallel scanning
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.scan_file, f): f for f in files_to_scan}

            for future in as_completed(futures):
                try:
                    file_findings = future.result()
                    findings.extend(file_findings)
                except Exception as e:
                    logger.debug(f"Scan error: {e}")

        logger.info(f"SAST scan complete: {len(findings)} findings")
        return findings

    def generate_report(self, findings: List[SASTFinding]) -> Dict:
        """
        Generate summary report from findings.

        Args:
            findings: List of SAST findings

        Returns:
            Report dict with statistics
        """
        report = {
            "total_findings": len(findings),
            "by_severity": {},
            "by_sink_type": {},
            "files_affected": set(),
            "findings": [],
        }

        for finding in findings:
            # Count by severity
            sev = finding.severity
            report["by_severity"][sev] = report["by_severity"].get(sev, 0) + 1

            # Count by sink type
            sink = finding.sink_type
            report["by_sink_type"][sink] = report["by_sink_type"].get(sink, 0) + 1

            # Track files
            report["files_affected"].add(finding.filepath)

            # Add finding detail
            report["findings"].append(
                {
                    "file": finding.filepath,
                    "line": finding.line_number,
                    "sink": finding.sink_type,
                    "snippet": finding.code_snippet,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "recommendation": finding.recommendation,
                }
            )

        report["files_affected"] = list(report["files_affected"])
        return report


def scan_js(path: str, **kwargs) -> List[Dict]:
    """
    Convenience function to scan JS files for PP.

    Args:
        path: File or directory path
        **kwargs: Additional options

    Returns:
        List of findings as dicts
    """
    scanner = SASTScanner(**kwargs)

    if os.path.isfile(path):
        findings = scanner.scan_file(path)
    else:
        findings = scanner.scan_directory(path)

    return [
        {
            "type": "sast_pp_sink",
            "file": f.filepath,
            "line": f.line_number,
            "sink": f.sink_type,
            "snippet": f.code_snippet,
            "severity": f.severity,
            "confidence": f.confidence,
            "recommendation": f.recommendation,
        }
        for f in findings
    ]
