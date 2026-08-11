from __future__ import annotations

from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    AUTHENTICATION = "authentication"
    RATE_LIMITING = "rate_limiting"
    USER_ENUMERATION = "user_enumeration"
    SESSION = "session"
    CORS_HEADERS = "cors_headers"
    JWT = "jwt"


class Evidence(BaseModel):
    description: str
    raw_data: Optional[Dict[str, Any]] = None
    request: Optional[str] = None
    response: Optional[str] = None


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    category: Category
    evidence: Evidence
    fix: str
    references: List[str] = Field(default_factory=list)
    cvss_score: Optional[float] = None


class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info

    def increment(self, severity: Severity):
        if severity == Severity.CRITICAL:
            self.critical += 1
        elif severity == Severity.HIGH:
            self.high += 1
        elif severity == Severity.MEDIUM:
            self.medium += 1
        elif severity == Severity.LOW:
            self.low += 1
        elif severity == Severity.INFO:
            self.info += 1


class ScanResult(BaseModel):
    target: str
    scan_time: datetime = Field(default_factory=datetime.utcnow)
    findings: List[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    scan_duration: float = 0.0

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        self.summary.increment(finding.severity)

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_category(self, category: Category) -> List[Finding]:
        return [f for f in self.findings if f.category == category]