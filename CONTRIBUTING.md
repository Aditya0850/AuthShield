# Contributing to AuthShield

Thank you for your interest in contributing to AuthShield! This guide will help you get started.

## Prerequisites

- Python 3.10+
- Git
- Basic understanding of web authentication/security concepts

## Development Setup

```bash
# Clone the repository
git clone https://github.com/Aditya0850/AuthShield
cd AuthShield

# Install in development mode with dev dependencies
pip install -e ".[dev]"
```

## Running Tests

```bash
# All tests with coverage
pytest --cov=authshield --cov-report=term-missing

# Specific test module
pytest tests/test_authshield.py::test_auth_checks -v

# Run a specific test class
pytest tests/test_authshield.py::TestAuthChecks -v
```

## Linting & Type Checking

```bash
# Lint with ruff
ruff check .

# Type check with mypy
mypy authshield/
```

## Project Structure

```
authshield/
├── cli.py                 # Click CLI entry point (scan, checks, quick commands)
├── core/
│   ├── http_client.py     # Conservative HTTP client (budget, retries, pooling)
│   ├── models.py          # Pydantic models (Finding, ScanResult, Severity, Category)
│   └── scanner.py         # Main orchestration (request budget aware)
├── checks/
│   ├── auth.py            # AUTH-001: Weak password policy
│   ├── rate_limit.py      # RATE-001: Login rate limiting
│   ├── enum.py            # ENUM-001: User enumeration via error messages
│   ├── cookies.py         # COOKIE-001/002/003: Session cookie flags
│   ├── cors.py            # CORS-001/002: CORS & security headers
│   └── jwt.py             # JWT-001/003/004: JWT security
├── reporting/
│   ├── html_report.py     # Jinja2 HTML reporter (templates/report.html.j2)
│   └── json_report.py     # JSON reporter
��── __init__.py
```

## How to Add a New Security Check

AuthShield follows a **conservative, passive-first** philosophy. Before implementing a check, ensure it:
- Does NOT perform brute force, credential stuffing, or secret cracking
- Does NOT make destructive requests
- Has a clear, documented methodology in the code
- Includes mocked tests (no external dependencies)

### Step 1: Create the Check Module

Create a new file in `authshield/checks/` (e.g., `new_check.py`):

```python
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from authshield.core.scanner import Scanner

from authshield.core.http_client import make_finding
from authshield.core.models import Category, Severity


class NewChecks:
    """Description of what this check does.
    
    Methodology:
    - Explain exactly what requests are made
    - What responses are analyzed
    - Why this is safe/conservative
    """

    def __init__(self, scanner: Scanner):
        self.scanner = scanner
        self.client = scanner.client

    def run_all(self):
        self.check_my_vulnerability()

    def check_my_vulnerability(self):
        """CHECK-ID: Descriptive title.
        
        Detailed methodology here.
        """
        # Use self.scanner.make_request() for HTTP requests
        # Use self.scanner.add_finding(make_finding(...)) to report findings
        pass
```

### Step 2: Register the Check

In `authshield/core/scanner.py`, import and initialize your check class in `__init__`:

```python
from authshield.checks.new_check import NewChecks
# ...
self.new_checks = NewChecks(self)
```

Then call it in the `scan()` method:

```python
self.log("Running new checks...")
self.new_checks.run_all()
```

### Step 3: Add Tests

Add mocked tests in `tests/test_authshield.py` following existing patterns:

```python
class TestNewChecks:
    def test_check_my_vulnerability_detects_issue(self):
        mock_scanner = Mock()
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = "vulnerable response"
        mock_scanner.make_request.return_value = mock_resp

        checks = NewChecks(mock_scanner)
        checks.check_my_vulnerability()

        mock_scanner.add_finding.assert_called()
        call_args = mock_scanner.add_finding.call_args[0][0]
        assert call_args.id == "CHECK-ID"
        assert call_args.severity == Severity.HIGH  # or appropriate level
```

### Step 4: Document the Check

Update the `checks` command in `cli.py` to include your check in the table.

## Finding Metadata Guidelines

Each finding should include:
- **check_id**: Unique ID (e.g., `AUTH-001`, `NEW-001`)
- **title**: Clear, descriptive title
- **severity**: CRITICAL, HIGH, MEDIUM, LOW, or INFO
- **category**: One of the existing Category enums
- **evidence.description**: Human-readable explanation of what was found
- **evidence.raw_data**: Structured data for programmatic consumption
- **fix**: Actionable remediation guidance
- **references**: OWASP or other authoritative links

## Branch Naming

- Feature: `feat/check-name` or `feat/short-description`
- Bug fix: `fix/short-description`
- Docs: `docs/short-description`
- Refactor: `refactor/short-description`

## Commit & PR Expectations

- **Commits**: Atomic, one logical change per commit
- **Messages**: Conventional commits format (e.g., `feat: add new JWT check for kid header validation`)
- **PRs**: 
  - Clear description of what the check does and why
  - Include methodology in PR description or code comments
  - All tests passing (`pytest`, `ruff check .`, `mypy authshield/`)
  - No reduction in test coverage

## Choosing an Issue

1. Look for issues labeled `good first issue` for beginner-friendly tasks
2. Look for `help wanted` for areas needing community input
3. Comment on the issue before starting work to avoid duplication
4. For new check proposals, open a discussion issue first (`discussion` label)

## Submitting a Pull Request

1. Fork the repository
2. Create a feature branch from `main`
3. Implement your changes with tests
4. Run the full test suite and linting
5. Push to your fork
6. Open a PR against `main` with:
   - Clear title and description
   - Reference to related issue(s)
   - Explanation of check methodology (if adding a check)

---

**Questions?** Open a discussion issue or comment on an existing issue. We're happy to help!