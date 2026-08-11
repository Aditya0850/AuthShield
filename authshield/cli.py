from __future__ import annotations

from typing import List, Dict, Any, Optional
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
import json

from authshield.core.scanner import Scanner
from authshield.core.models import Severity, Category, ScanResult
from authshield.reporting.json_report import JSONReporter
from authshield.reporting.html_report import HTMLReporter


console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="AuthShield")
def cli():
    """AuthShield - Web Authentication Security Auditor

    Automatically checks web applications for authentication, session,
    CORS, and JWT misconfigurations.
    """
    pass


@cli.command()
@click.argument("target", required=True)
@click.option("-e", "--endpoints", help="Comma-separated list of endpoints to scan")
@click.option("-c", "--cookie", "cookies", multiple=True, help="Cookies in format 'name=value'")
@click.option("-H", "--header", "headers", multiple=True, help="Headers in format 'Name: Value'")
@click.option("-t", "--timeout", default=10, help="Request timeout in seconds")
@click.option("--no-ssl-verify", is_flag=True, help="Disable SSL verification")
@click.option("-f", "--format", "output_format", type=click.Choice(["json", "html", "both"]), default="both")
@click.option("-o", "--output", help="Output file path (without extension)")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def scan(target: str, endpoints: str, cookies: tuple, headers: tuple,
         timeout: int, no_ssl_verify: bool, output_format: str, output: str, verbose: bool):
    """Scan a target web application for authentication security issues."""

    # Parse endpoints
    endpoint_list = None
    if endpoints:
        endpoint_list = [e.strip() for e in endpoints.split(",")]

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
        f"[bold]Headers:[/bold] {len(header_dict)}",
        title="🛡️ AuthShield Scan",
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
    )

    with Progress(
        SpinnerColumn(),
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
        console.print(f"\n[green]✓[/green] JSON report saved to: {json_path}")

    if output_format in ("html", "both"):
        html_path = f"{output}.html" if output else "authshield-report.html"
        HTMLReporter.generate(result, html_path)
        console.print(f"[green]✓[/green] HTML report saved to: {html_path}")

    if total > 0:
        console.print(f"\n[yellow]⚠[/yellow] Found {total} security issue(s). Review the reports for remediation guidance.")
    else:
        console.print(f"\n[green]✓[/green] No security issues found!")


@cli.command()
def checks():
    """List all available security checks."""
    checks_data = [
        ("AUTH-001", "Weak Password Policy", "Authentication", "HIGH"),
        ("AUTH-002", "Missing Multi-Factor Authentication", "Authentication", "MEDIUM"),
        ("AUTH-003", "Default Credentials", "Authentication", "CRITICAL"),
        ("RATE-001", "Missing Rate Limiting on Login", "Rate Limiting", "HIGH"),
        ("RATE-002", "Weak Rate Limiting Configuration", "Rate Limiting", "MEDIUM"),
        ("ENUM-001", "Username Enumeration via Error Messages", "User Enumeration", "MEDIUM"),
        ("ENUM-002", "Username Enumeration via Timing Attack", "User Enumeration", "MEDIUM"),
        ("COOKIE-001", "Missing Secure Flag on Session Cookie", "Session", "HIGH"),
        ("COOKIE-002", "Missing HttpOnly Flag on Session Cookie", "Session", "HIGH"),
        ("COOKIE-003", "Missing SameSite Attribute", "Session", "MEDIUM"),
        ("CORS-001", "Overly Permissive CORS Policy", "CORS/Headers", "HIGH"),
        ("CORS-002", "Missing Security Headers", "CORS/Headers", "MEDIUM"),
        ("JWT-001", "Algorithm Confusion (RS256/HS256)", "JWT", "HIGH"),
        ("JWT-002", "Weak JWT Secret", "JWT", "CRITICAL"),
        ("JWT-003", "Missing Expiration Claim", "JWT", "HIGH"),
        ("JWT-004", "'none' Algorithm Accepted", "JWT", "CRITICAL"),
    ]

    table = Table(title="AuthShield Security Checks", show_header=True, header_style="bold cyan")
    table.add_column("Check ID", style="bold")
    table.add_column("Title")
    table.add_column("Category")
    table.add_column("Severity")

    for check_id, title, category, severity in checks_data:
        color = {
            "CRITICAL": "red",
            "HIGH": "orange3",
            "MEDIUM": "yellow",
            "LOW": "green",
            "INFO": "blue",
        }[severity]
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