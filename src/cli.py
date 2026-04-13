"""CLI entry point for VN-PQC Readiness Analyzer."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from src.config import ScanConfig
from src.utils.constants import RiskLevel
from src.utils.i18n import set_language, t

app = typer.Typer(
    name="pqc-analyzer",
    help="VN-PQC Readiness Analyzer — Assess your system's readiness for post-quantum cryptography migration.",
    no_args_is_help=True,
)
scan_app = typer.Typer(help="Scan targets for cryptographic algorithms.")
app.add_typer(scan_app, name="scan")

console = Console()

# Common options
VerboseOption = Annotated[int, typer.Option("--verbose", "-v", count=True, help="Increase verbosity")]
OutputOption = Annotated[Optional[str], typer.Option("--output", "-o", help="Output file path")]
LanguageOption = Annotated[str, typer.Option("--language", "-l", help="Language: en or vi")]
RedactOption = Annotated[bool, typer.Option("--redact", help="Redact hostnames/IPs in output")]


def _setup_logging(verbose: int) -> None:
    """Configure logging based on verbosity level."""
    level = logging.WARNING
    if verbose == 1:
        level = logging.INFO
    elif verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _print_disclaimer() -> None:
    """Print the legal disclaimer."""
    console.print()
    console.print(t("disclaimer"), style="bold yellow")
    console.print()


def _risk_style(risk: RiskLevel) -> str:
    """Get rich style for a risk level."""
    return {
        RiskLevel.CRITICAL: "bold red",
        RiskLevel.HIGH: "bold yellow",
        RiskLevel.MEDIUM: "yellow",
        RiskLevel.LOW: "green",
        RiskLevel.SAFE: "bold cyan",
    }.get(risk, "white")


def _risk_icon(risk: RiskLevel) -> str:
    """Get icon for a risk level."""
    return {
        RiskLevel.CRITICAL: "[red]●[/red]",
        RiskLevel.HIGH: "[yellow]●[/yellow]",
        RiskLevel.MEDIUM: "[yellow]○[/yellow]",
        RiskLevel.LOW: "[green]○[/green]",
        RiskLevel.SAFE: "[cyan]✓[/cyan]",
    }.get(risk, " ")


def _print_findings_table(findings: list) -> None:
    """Print findings as a rich table."""
    table = Table(show_header=True, header_style="bold")
    table.add_column("Risk", width=10)
    table.add_column("Component", width=20)
    table.add_column("Algorithm", width=20)
    table.add_column("QV", width=4)  # Quantum Vulnerable
    table.add_column("Location", width=35)
    table.add_column("Replacement", width=25)

    for f in sorted(findings, key=lambda x: x.migration_priority):
        risk = RiskLevel(f.risk_level) if isinstance(f.risk_level, str) else f.risk_level
        qv = "[red]Yes[/red]" if f.quantum_vulnerable else "[green]No[/green]"
        replacement = ", ".join(f.replacement[:2]) if f.replacement else "—"
        table.add_row(
            f"{_risk_icon(risk)} {risk.value}",
            f.component,
            f.algorithm,
            qv,
            f.location[:35],
            replacement,
        )

    console.print(table)


def _print_summary(summary) -> None:
    """Print scan summary."""
    console.print()
    console.print(f"[bold]Total findings:[/bold] {summary.total_findings}")
    if summary.critical > 0:
        console.print(f"  [red]● CRITICAL: {summary.critical}[/red]")
    if summary.high > 0:
        console.print(f"  [yellow]● HIGH: {summary.high}[/yellow]")
    if summary.medium > 0:
        console.print(f"  [yellow]○ MEDIUM: {summary.medium}[/yellow]")
    if summary.low > 0:
        console.print(f"  [green]○ LOW: {summary.low}[/green]")
    if summary.safe > 0:
        console.print(f"  [cyan]✓ SAFE: {summary.safe}[/cyan]")
    console.print(
        f"  [bold]Overall risk: [{_risk_style(summary.overall_risk)}]{summary.overall_risk.value}[/{_risk_style(summary.overall_risk)}][/bold]"
    )


def _save_output(data: dict, output_path: str | None) -> None:
    """Save results to file if output path specified."""
    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        console.print(f"\n{t('results_saved', path=output_path)}", style="green")


@scan_app.command("tls")
def scan_tls(
    targets: Annotated[list[str], typer.Argument(help="Host:port targets to scan")],
    hosts_file: Annotated[Optional[str], typer.Option("--hosts-file", "-f", help="File with targets (one per line)")] = None,
    timeout: Annotated[int, typer.Option("--timeout", "-t", help="Connection timeout in ms")] = 5000,
    delay: Annotated[int, typer.Option("--delay", help="Delay between requests in ms")] = 100,
    max_concurrent: Annotated[int, typer.Option("--max-concurrent", help="Max concurrent connections")] = 10,
    output: OutputOption = None,
    language: LanguageOption = "en",
    redact: RedactOption = False,
    verbose: VerboseOption = 0,
    accept_disclaimer: Annotated[bool, typer.Option("--accept-disclaimer", help="Accept legal disclaimer")] = False,
) -> None:
    """Scan TLS endpoints for cryptographic algorithms."""
    _setup_logging(verbose)
    set_language(language)  # type: ignore[arg-type]

    if not accept_disclaimer:
        _print_disclaimer()

    # Warn about aggressive settings
    if delay == 0 and max_concurrent > 50:
        console.print(
            t("rate_limit_warning", concurrent=max_concurrent),
            style="bold red",
        )

    config = ScanConfig(
        timeout_ms=timeout,
        delay_ms=delay,
        max_concurrent=max_concurrent,
        redact=redact,
        verbose=verbose,
        language=language,
    )

    from src.scanner.tls_scanner import TLSScanner

    scanner = TLSScanner(config=config)

    # Collect all targets
    all_targets = list(targets)
    if hosts_file:
        all_targets.extend(scanner.load_targets_file(hosts_file))

    if not all_targets:
        console.print("[red]No targets specified.[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Scanning {len(all_targets)} target(s)...[/bold]\n")

    from src.scanner.inventory import CryptoInventory

    inventory = CryptoInventory()

    for target_str in all_targets:
        with console.status(f"Scanning {target_str}..."):
            result = scanner.scan_host(*scanner._parse_target(target_str))
        inventory.add_result(result)

        if result.status.value != "success":
            console.print(f"[red]✗ {target_str}: {result.error_message}[/red]")
        else:
            console.print(
                f"[green]✓ {target_str}[/green] — {len(result.findings)} finding(s)"
            )

    # Print results
    if inventory.all_findings:
        console.print()
        _print_findings_table(inventory.all_findings)
        _print_summary(inventory.summary)
    else:
        console.print(f"\n[cyan]{t('no_findings')}[/cyan]")

    _save_output(inventory.to_dict(), output)


@scan_app.command("config")
def scan_config(
    paths: Annotated[list[str], typer.Argument(help="Config file or directory paths")],
    recursive: Annotated[bool, typer.Option("--recursive", "-r", help="Scan directories recursively")] = True,
    output: OutputOption = None,
    language: LanguageOption = "en",
    verbose: VerboseOption = 0,
) -> None:
    """Scan configuration files (nginx, apache, haproxy) for crypto settings."""
    _setup_logging(verbose)
    set_language(language)  # type: ignore[arg-type]

    from src.scanner.config_parser import ConfigParser
    from src.scanner.inventory import CryptoInventory

    parser = ConfigParser()
    inventory = CryptoInventory()

    for path_str in paths:
        path = Path(path_str)
        if path.is_dir():
            results = parser.scan_directory(str(path), recursive=recursive)
            inventory.add_results(results)
            console.print(f"[green]Scanned directory: {path_str}[/green] — {len(results)} file(s) with findings")
        elif path.is_file():
            result = parser.scan_file(str(path))
            inventory.add_result(result)
            if result.findings:
                console.print(f"[green]✓ {path_str}[/green] — {len(result.findings)} finding(s)")
            else:
                console.print(f"[dim]○ {path_str}[/dim] — no findings")
        else:
            console.print(f"[red]✗ {path_str}: not found[/red]")

    if inventory.all_findings:
        console.print()
        _print_findings_table(inventory.all_findings)
        _print_summary(inventory.summary)
    else:
        console.print(f"\n[cyan]{t('no_findings')}[/cyan]")

    _save_output(inventory.to_dict(), output)


@scan_app.command("ssh")
def scan_ssh(
    paths: Annotated[list[str], typer.Argument(help="SSH config file paths")] = None,
    output: OutputOption = None,
    language: LanguageOption = "en",
    verbose: VerboseOption = 0,
) -> None:
    """Scan SSH configuration files for quantum-vulnerable algorithms."""
    _setup_logging(verbose)
    set_language(language)  # type: ignore[arg-type]

    from src.scanner.inventory import CryptoInventory
    from src.scanner.ssh_scanner import SSHScanner

    scanner = SSHScanner()
    inventory = CryptoInventory()

    # Default paths if none specified
    if not paths:
        default_paths = ["/etc/ssh/sshd_config", "/etc/ssh/ssh_config"]
        paths = [p for p in default_paths if Path(p).exists()]
        if not paths:
            console.print("[red]No SSH config files found. Specify paths explicitly.[/red]")
            raise typer.Exit(1)

    for path_str in paths:
        result = scanner.scan_file(path_str)
        inventory.add_result(result)

        if result.status.value != "success":
            console.print(f"[red]✗ {path_str}: {result.error_message}[/red]")
        elif result.findings:
            console.print(f"[green]✓ {path_str}[/green] — {len(result.findings)} finding(s)")
        else:
            console.print(f"[dim]○ {path_str}[/dim] — no findings")

    if inventory.all_findings:
        console.print()
        _print_findings_table(inventory.all_findings)
        _print_summary(inventory.summary)
    else:
        console.print(f"\n[cyan]{t('no_findings')}[/cyan]")

    _save_output(inventory.to_dict(), output)


@app.command("version")
def version() -> None:
    """Show version information."""
    console.print("[bold]VN-PQC Readiness Analyzer[/bold] v0.1.0")
    console.print("https://github.com/nguyendong/vn-pqc-analyzer")


@app.command("db")
def db_info(
    action: Annotated[str, typer.Argument(help="Action: version, list, stats")] = "version",
) -> None:
    """Show algorithm database information."""
    from src.utils.crypto_db import get_algorithm_db

    db = get_algorithm_db()

    if action == "version":
        console.print(f"Algorithm database version: [bold]{db.version}[/bold]")
    elif action == "list":
        table = Table(show_header=True, header_style="bold")
        table.add_column("Algorithm", width=20)
        table.add_column("Type", width=15)
        table.add_column("Risk", width=10)
        table.add_column("Quantum Vuln.", width=12)
        table.add_column("Replacement", width=30)

        for name, info in sorted(db.all_algorithms().items()):
            risk = info.risk_level
            qv = "[red]Yes[/red]" if info.quantum_vulnerable else "[green]No[/green]"
            replacement = ", ".join(info.replacement[:2]) if info.replacement else "—"
            table.add_row(
                info.name,
                info.type,
                f"[{_risk_style(risk)}]{risk.value}[/{_risk_style(risk)}]",
                qv,
                replacement,
            )
        console.print(table)
    elif action == "stats":
        all_algos = db.all_algorithms()
        vuln = db.quantum_vulnerable()
        safe = db.quantum_safe()
        console.print(f"Total algorithms: [bold]{len(all_algos)}[/bold]")
        console.print(f"Quantum vulnerable: [red]{len(vuln)}[/red]")
        console.print(f"Quantum safe: [green]{len(safe)}[/green]")


if __name__ == "__main__":
    app()
