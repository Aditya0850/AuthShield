from __future__ import annotations

import json

from authshield.core.models import Finding, ScanResult, Severity

SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "AuthShield"
TOOL_VERSION = "0.1.0"
TOOL_URI = "https://github.com/Aditya0850/AuthShield"

# SARIF level mapping per issue spec: CRITICAL/HIGH -> error, MEDIUM -> warning, LOW/INFO -> note
_SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub Code Scanning "security-severity" score (0.0-10.0, CVSS-like)
_SEVERITY_TO_SCORE = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


class SARIFReporter:
    @staticmethod
    def generate(result: ScanResult, output_path: str | None = None) -> str:
        """Generate a SARIF 2.1.0 report for a scan result.

        Follows the same static-reporter pattern as JSONReporter/HTMLReporter:
        returns the serialized report and optionally writes it to output_path.
        """
        rules: list[dict] = []
        rule_index_by_id: dict[str, int] = {}
        results: list[dict] = []

        for finding in result.findings:
            if finding.id not in rule_index_by_id:
                rule_index_by_id[finding.id] = len(rules)
                rules.append(SARIFReporter._make_rule(finding))
            results.append(
                SARIFReporter._make_result(finding, rule_index_by_id[finding.id], result.target)
            )

        sarif = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": TOOL_NAME,
                            "version": TOOL_VERSION,
                            "informationUri": TOOL_URI,
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "properties": {
                        "target": result.target,
                        "scanTime": result.scan_time.isoformat() + "Z",
                        "scanDuration": round(result.scan_duration, 2),
                    },
                }
            ],
        }

        sarif_str = json.dumps(sarif, indent=2, default=str)

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(sarif_str)

        return sarif_str

    @staticmethod
    def _make_rule(finding: Finding) -> dict:
        rule = {
            "id": finding.id,
            "name": finding.id.replace("-", ""),
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.evidence.description},
            "help": {"text": finding.fix},
            "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL[finding.severity]},
            "properties": {
                "tags": ["security", finding.category.value],
                "security-severity": _SEVERITY_TO_SCORE[finding.severity],
            },
        }
        if finding.references:
            rule["helpUri"] = finding.references[0]
        return rule

    @staticmethod
    def _make_result(finding: Finding, rule_index: int, target: str) -> dict:
        message = finding.evidence.description
        if finding.fix:
            message = f"{message}\n\nFix: {finding.fix}"

        sarif_result = {
            "ruleId": finding.id,
            "ruleIndex": rule_index,
            "level": _SEVERITY_TO_LEVEL[finding.severity],
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": target},
                    }
                }
            ],
            "properties": {
                "severity": finding.severity.value,
                "category": finding.category.value,
                "references": finding.references,
            },
        }
        if finding.evidence.raw_data:
            sarif_result["properties"]["evidence"] = finding.evidence.raw_data
        if finding.cvss_score is not None:
            sarif_result["properties"]["cvssScore"] = finding.cvss_score
        return sarif_result
