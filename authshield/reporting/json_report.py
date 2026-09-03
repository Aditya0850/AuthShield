from __future__ import annotations

from authshield.core.models import ScanResult


class JSONReporter:
    @staticmethod
    def generate(result: ScanResult, output_path: str | None = None) -> str:
        import json
        data = {
            "target": result.target,
            "scan_time": result.scan_time.isoformat() + "Z",
            "scan_duration": round(result.scan_duration, 2),
            "summary": {
                "critical": result.summary.critical,
                "high": result.summary.high,
                "medium": result.summary.medium,
                "low": result.summary.low,
                "info": result.summary.info,
                "total": result.summary.total(),
            },
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "category": f.category.value,
                    "evidence": {
                        "description": f.evidence.description,
                        "raw_data": f.evidence.raw_data,
                        "request": f.evidence.request,
                        "response": f.evidence.response,
                    },
                    "fix": f.fix,
                    "references": f.references,
                    "cvss_score": f.cvss_score,
                    "cvss_vector": f.cvss_vector,
                    "confidence": f.confidence.value,
                    "evidence_type": f.evidence_type.value,
                    "exploitability": f.exploitability.value,
                    "context": f.context,
                }
                for f in result.findings
            ],
        }

        json_str = json.dumps(data, indent=2, default=str)

        if output_path:
            with open(output_path, "w") as f:
                f.write(json_str)

        return json_str