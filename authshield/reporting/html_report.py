from __future__ import annotations

from typing import List, Dict, Any, Optional
from jinja2 import Environment, FileSystemLoader
import os


class HTMLReporter:
    @staticmethod
    def generate(result: ScanResult, output_path: Optional[str] = None, template_dir: Optional[str] = None) -> str:
        if template_dir is None:
            template_dir = os.path.join(os.path.dirname(__file__), "..", "..", "templates")

        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template("report.html.j2")

        # Group findings by severity
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        findings_by_severity = {}
        for severity in severity_order:
            findings_by_severity[severity] = [f for f in result.findings if f.severity.value == severity]

        # Group by category
        categories = {}
        for f in result.findings:
            cat = f.category.value
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(f)

        html = template.render(
            result=result,
            findings_by_severity=findings_by_severity,
            categories=categories,
            severity_order=severity_order,
        )

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)

        return html