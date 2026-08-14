from __future__ import annotations

import os
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, TextColumn
from rich.table import Table

from authshield.core.models import Severity
from authshield.core.scanner import Scanner
from authshield.reporting.html_report import HTMLReporter
from authshield.reporting.json_report import JSONReporter

# Force UTF-8 encoding on Windows
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    console = Console(force_terminal=True, legacy_windows=False)
else:
    console = Console()


def parse_exclude_checks(raw: str | None) -> tuple[list[str], list[str]]:
    """Parse a comma-separated string of check IDs.

    Returns (valid_ids, unknown_ids), both uppercased and deduplicated,
    preserving input order.
    """
    valid: list[str] = []
    unknown: list[str] = []
    if not raw:
        return valid, unknown
    for part in raw.split(","):
        check_id = part.strip().upper()
        if not check_id or check_id in valid or check_id in unknown:
            continue
        if check_id in Scanner.KNOWN_CHECK_IDS:
            valid.append(check_id)
        else:
            unknown.append(check_id)
    return valid, unknown


@click.group()
@click.version_option(version="0.1.0", prog_name="AuthShield")
def cli():
    """AuthShield - Web Authentication Security Auditor

    Automatically checks web applications for authentication, session,
    CORS, and JWT misconfigurations.
    """


@cli.command()
@click.argument("target", required=True)
@click.option("-e", "--endpoints", help="Comma-separated list of endpoints to scan")
@click.option("-c", "--cookie", "cookies", multiple=True, help="Cookies in format 'name=value'")
@click.option("-H", "--header", "headers", multiple=True, help="Headers in format 'Name: Value'")
@click.option("-t", "--timeout", default=10, help="Request timeout in seconds")
@click.option("--no-ssl-verify", is_flag=True, help="Disable SSL verification")
@click.option("-f", "--format", "output_format", type=click.Choice(["json", "html", "both"]), default="both")
@click.option("-o", "--output", help="Output file path (without extension)")
@click.option("--exclude-checks", "exclude_checks",
              help="Comma-separated check IDs to skip (e.g. 'RATE-001,JWT-004')")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def scan(target: str, endpoints: str, cookies: tuple, headers: tuple,
         timeout: int, no_ssl_verify: bool, output_format: str, output: str,
         exclude_checks: str, verbose: bool):
    """Scan a target web application for authentication security issues."""

    # Parse endpoints
    endpoint_list = None
    if endpoints:
        endpoint_list = [e.strip() for e in endpoints.split(",")]

    # Parse and validate excluded check IDs
    excluded, unknown = parse_exclude_checks(exclude_checks)
    if unknown:
        console.print(
            f"[yellow]WARNING[/yellow] Unknown check ID(s) ignored: {', '.join(unknown)}\n"
            f"  Run 'authshield checks' to list valid check IDs."
        )

    # Parse cookies
    cookie_dict = {}
    for cookie in cookies:
        if "=" in cookie:
            k, v = cookie.split("=", 1)
            cookie_dict[k.strip()] = v.strip()

    # Parse headers
    header_dict = {}
    for header in headers:
        if ":" in header:
            k, v = header.split(":", 1)
            header_dict[k.strip()] = v.strip()

    console.print(Panel.fit(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Endpoints:[/bold] {len(endpoint_list) if endpoint_list else 'default'}\n"
        f"[bold]Cookies:[/bold] {len(cookie_dict)}\n"
        f"[bold]Headers:[/bold] {len(header_dict)}\n"
        f"[bold]Excluded checks:[/bold] {', '.join(excluded) if excluded else 'none'}",
        title="AuthShield Scan",
        border_style="blue"
    ))

    scanner = Scanner(
        target=target,
        endpoints=endpoint_list,
        cookies=cookie_dict if cookie_dict else None,
        headers=header_dict if header_dict else None,
        timeout=timeout,
        verify_ssl=not no_ssl_verify,
        verbose=verbose,
        exclude_checks=excluded,
    )

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=None)
        result = scanner.scan()
        progress.update(task, completed=True)

    # Print summary table
    table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Percentage", justify="right")

    total = result.summary.total()
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = getattr(result.summary, severity.value.lower())
        pct = f"{(count/total*100):.1f}%" if total > 0 else "0%"
        color = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "orange3",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "green",
            Severity.INFO: "blue",
        }[severity]
        table.add_row(f"[{color}]{severity.value}[/{color}]", str(count), pct)

    table.add_row("[bold]Total[/bold]", f"[bold]{total}[/bold]", "100%")
    console.print(table)

    if excluded:
        console.print(f"[dim]Excluded checks (not scanned): {', '.join(excluded)}[/dim]")

    # Print findings
    if result.findings:
        console.print("\n[bold]Findings:[/bold]")
        for finding in result.findings:
            color = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "orange3",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "green",
                Severity.INFO: "blue",
            }[finding.severity]
            console.print(f"  [{color}]{finding.severity.value}[/{color}] {finding.id}: {finding.title}")

    # Generate reports
    if output_format in ("json", "both"):
        json_path = f"{output}.json" if output else "authshield-report.json"
        JSONReporter.generate(result, json_path)
        console.print(f"\n[green]OK[/green] JSON report saved to: {json_path}")

    if output_format in ("html", "both"):
        html_path = f"{output}.html" if output else "authshield-report.html"
        HTMLReporter.generate(result, html_path)
        console.print(f"[green]OK[/green] HTML report saved to: {html_path}")

    if total > 0:
        console.print(f"\n[yellow]WARNING[/yellow] Found {total} security issue(s). Review the reports for remediation guidance.")
    else:
        console.print("\n[green]OK[/green] No security issues found!")


@cli.command()
def checks():
    """List all available security checks."""
    checks_data = [
        ("AUTH-001", "Weak Password Policy Indicator", "Authentication", "MEDIUM"),
        ("RATE-001", "Missing Rate Limiting on Login", "Rate Limiting", "HIGH"),
        ("ENUM-001", "Username Enumeration via Error Messages", "User Enumeration", "MEDIUM"),
        ("COOKIE-001", "Missing Secure Flag on Session Cookie", "Session", "HIGH"),
        ("COOKIE-002", "Missing HttpOnly Flag on Session Cookie", "Session", "HIGH"),
        ("COOKIE-003", "Missing or Insecure SameSite Attribute", "Session", "HIGH"),
        ("CORS-001", "CORS Reflects Arbitrary Origin with Credentials", "CORS/Headers", "HIGH"),
        ("CORS-002", "Missing or Weak Security Headers", "CORS/Headers", "HIGH"),
        ("JWT-001", "JWT Algorithm Confusion Risk (RS256 + Public JWKS)", "JWT", "MEDIUM"),
        ("JWT-003", "Missing or Excessive Expiration Claim", "JWT", "HIGH/MEDIUM"),
        ("JWT-004", "Endpoint Accepts 'none' Algorithm JWT", "JWT", "CRITICAL"),
    ]

    table = Table(title="AuthShield Security Checks", show_header=True, header_style="bold cyan")
    table.add_column("Check ID", style="bold")
    table.add_column("Title")
    table.add_column("Category")
    table.add_column("Severity")

    for check_id, title, category, severity in checks_data:
        # Handle multi-severity values
        base_severity = severity.split("/")[0]
        color = {
            "CRITICAL": "red",
            "HIGH": "orange3",
            "MEDIUM": "yellow",
            "LOW": "green",
            "INFO": "blue",
        }[base_severity]
        table.add_row(check_id, title, category, f"[{color}]{severity}[/{color}]")

    console.print(table)


@cli.command()
@click.argument("target", required=True)
def quick(target: str):
    """Quick scan with minimal output."""
    scanner = Scanner(target=target, verbose=False)
    result = scanner.scan()

    if result.findings:
        for f in result.findings:
            print(f"{f.severity.value}: {f.id} - {f.title}")
    else:
        print("No issues found")


if __name__ == "__main__":
    cli()