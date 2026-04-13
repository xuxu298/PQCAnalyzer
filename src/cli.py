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


@scan_app.command("vpn")
def scan_vpn(
    paths: Annotated[list[str], typer.Argument(help="VPN config file paths")],
    output: OutputOption = None,
    language: LanguageOption = "en",
    verbose: VerboseOption = 0,
) -> None:
    """Scan VPN configuration files (OpenVPN, WireGuard, IPSec) for quantum-vulnerable algorithms."""
    _setup_logging(verbose)
    set_language(language)  # type: ignore[arg-type]

    from src.scanner.inventory import CryptoInventory
    from src.scanner.vpn_scanner import VPNScanner

    scanner = VPNScanner()
    inventory = CryptoInventory()

    for path_str in paths:
        path = Path(path_str)
        if path.is_dir():
            # Scan all config files in directory
            for f in sorted(path.rglob("*")):
                if f.is_file() and f.suffix in (".conf", ".ovpn", ".cfg"):
                    result = scanner.scan_file(str(f))
                    inventory.add_result(result)
                    if result.findings:
                        console.print(f"[green]✓ {f}[/green] — {len(result.findings)} finding(s) [{result.metadata.get('vpn_type', '?')}]")
                    elif result.status.value == "skipped":
                        console.print(f"[dim]○ {f}[/dim] — skipped (not a VPN config)")
        elif path.is_file():
            result = scanner.scan_file(path_str)
            inventory.add_result(result)
            if result.status.value != "success":
                console.print(f"[red]✗ {path_str}: {result.error_message}[/red]")
            elif result.findings:
                console.print(f"[green]✓ {path_str}[/green] — {len(result.findings)} finding(s) [{result.metadata.get('vpn_type', '?')}]")
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


@scan_app.command("code")
def scan_code(
    paths: Annotated[list[str], typer.Argument(help="Source file or directory paths")],
    recursive: Annotated[bool, typer.Option("--recursive", "-r", help="Scan directories recursively")] = True,
    output: OutputOption = None,
    language: LanguageOption = "en",
    verbose: VerboseOption = 0,
) -> None:
    """Scan source code for cryptographic usage patterns."""
    _setup_logging(verbose)
    set_language(language)  # type: ignore[arg-type]

    from src.scanner.code_scanner import CodeScanner
    from src.scanner.inventory import CryptoInventory

    scanner = CodeScanner()
    inventory = CryptoInventory()

    for path_str in paths:
        path = Path(path_str)
        if path.is_dir():
            results = scanner.scan_directory(str(path), recursive=recursive)
            inventory.add_results(results)
            total_findings = sum(len(r.findings) for r in results)
            console.print(f"[green]Scanned directory: {path_str}[/green] — {len(results)} file(s) with {total_findings} finding(s)")
        elif path.is_file():
            result = scanner.scan_file(path_str)
            inventory.add_result(result)
            if result.status.value == "skipped":
                console.print(f"[dim]○ {path_str}[/dim] — {result.error_message}")
            elif result.findings:
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


# --- Benchmark commands ---

bench_app = typer.Typer(help="Benchmark PQC vs classical cryptographic algorithms.")
app.add_typer(bench_app, name="benchmark")


@bench_app.command("kem")
def bench_kem(
    iterations: Annotated[int, typer.Option("--iterations", "-n", help="Number of iterations")] = 1000,
    warmup: Annotated[int, typer.Option("--warmup", help="Warmup iterations")] = 10,
    output: OutputOption = None,
    verbose: VerboseOption = 0,
) -> None:
    """Benchmark KEM algorithms (key generation, encapsulation, decapsulation)."""
    _setup_logging(verbose)

    from src.benchmarker.comparator import compare_kem_results
    from src.benchmarker.encaps_bench import bench_kem_encaps_classical, bench_kem_encaps_pqc
    from src.benchmarker.hardware_profile import detect_hardware
    from src.benchmarker.keygen_bench import bench_kem_keygen_classical, bench_kem_keygen_pqc
    from src.benchmarker.models import BenchmarkReport

    hw = detect_hardware()
    console.print(f"[bold]Hardware:[/bold] {hw.cpu_model} ({hw.cpu_cores} cores, {hw.ram_total_gb:.1f} GB RAM)")
    console.print(f"[bold]Iterations:[/bold] {iterations}\n")

    # Keygen benchmarks
    with console.status("Benchmarking classical KEM keygen..."):
        classical_keygen = bench_kem_keygen_classical(iterations, warmup)
    with console.status("Benchmarking PQC KEM keygen..."):
        pqc_keygen = bench_kem_keygen_pqc(iterations, warmup)

    # Encaps benchmarks
    with console.status("Benchmarking classical KEM encaps/decaps..."):
        classical_encaps = bench_kem_encaps_classical(iterations, warmup)
    with console.status("Benchmarking PQC KEM encaps/decaps..."):
        pqc_encaps = bench_kem_encaps_pqc(iterations, warmup)

    # Merge keygen + encaps results
    all_results = _merge_kem_results(classical_keygen + pqc_keygen, classical_encaps + pqc_encaps)

    # Display results table
    table = Table(title="KEM Benchmark Results", show_header=True, header_style="bold")
    table.add_column("Algorithm", width=15)
    table.add_column("Keygen (ms)", width=12, justify="right")
    table.add_column("Encaps (ms)", width=12, justify="right")
    table.add_column("Decaps (ms)", width=12, justify="right")
    table.add_column("PubKey (B)", width=10, justify="right")
    table.add_column("CT (B)", width=10, justify="right")

    for r in all_results:
        table.add_row(
            r.algorithm,
            f"{r.keygen.mean:.3f}" if r.keygen.mean > 0 else "—",
            f"{r.encaps.mean:.3f}" if r.encaps.mean > 0 else "—",
            f"{r.decaps.mean:.3f}" if r.decaps.mean > 0 else "—",
            str(r.pubkey_bytes) if r.pubkey_bytes > 0 else "—",
            str(r.ciphertext_bytes) if r.ciphertext_bytes > 0 else "—",
        )
    console.print(table)

    # Comparisons
    comparisons = compare_kem_results(all_results)
    if comparisons:
        console.print("\n[bold]Comparisons:[/bold]")
        for c in comparisons:
            console.print(f"  {c.summary}")

    report = BenchmarkReport(hardware=hw, kem_results=all_results, comparisons=comparisons)
    _save_output(report.to_dict(), output)


@bench_app.command("sign")
def bench_sign(
    iterations: Annotated[int, typer.Option("--iterations", "-n", help="Number of iterations")] = 1000,
    warmup: Annotated[int, typer.Option("--warmup", help="Warmup iterations")] = 10,
    output: OutputOption = None,
    verbose: VerboseOption = 0,
) -> None:
    """Benchmark digital signature algorithms (keygen, sign, verify)."""
    _setup_logging(verbose)

    from src.benchmarker.comparator import compare_sign_results
    from src.benchmarker.hardware_profile import detect_hardware
    from src.benchmarker.keygen_bench import bench_sign_keygen_classical, bench_sign_keygen_pqc
    from src.benchmarker.models import BenchmarkReport
    from src.benchmarker.sign_bench import bench_sign_classical, bench_sign_pqc

    hw = detect_hardware()
    console.print(f"[bold]Hardware:[/bold] {hw.cpu_model} ({hw.cpu_cores} cores, {hw.ram_total_gb:.1f} GB RAM)")
    console.print(f"[bold]Iterations:[/bold] {iterations}\n")

    # Sign/verify benchmarks (include keygen)
    with console.status("Benchmarking classical signatures..."):
        classical_results = bench_sign_classical(iterations, warmup)
    with console.status("Benchmarking PQC signatures..."):
        pqc_results = bench_sign_pqc(iterations, warmup)

    # Merge keygen data
    with console.status("Benchmarking classical sign keygen..."):
        classical_keygen = bench_sign_keygen_classical(iterations, warmup)
    with console.status("Benchmarking PQC sign keygen..."):
        pqc_keygen = bench_sign_keygen_pqc(iterations, warmup)

    all_results = _merge_sign_results(classical_results + pqc_results, classical_keygen + pqc_keygen)

    # Display results table
    table = Table(title="Signature Benchmark Results", show_header=True, header_style="bold")
    table.add_column("Algorithm", width=18)
    table.add_column("Keygen (ms)", width=12, justify="right")
    table.add_column("Sign (ms)", width=12, justify="right")
    table.add_column("Verify (ms)", width=12, justify="right")
    table.add_column("PubKey (B)", width=10, justify="right")
    table.add_column("Sig (B)", width=10, justify="right")

    for r in all_results:
        table.add_row(
            r.algorithm,
            f"{r.keygen.mean:.3f}" if r.keygen.mean > 0 else "—",
            f"{r.sign.mean:.3f}" if r.sign.mean > 0 else "—",
            f"{r.verify.mean:.3f}" if r.verify.mean > 0 else "—",
            str(r.pubkey_bytes) if r.pubkey_bytes > 0 else "—",
            str(r.signature_bytes) if r.signature_bytes > 0 else "—",
        )
    console.print(table)

    # Comparisons
    comparisons = compare_sign_results(all_results)
    if comparisons:
        console.print("\n[bold]Comparisons:[/bold]")
        for c in comparisons:
            console.print(f"  {c.summary}")

    report = BenchmarkReport(hardware=hw, sign_results=all_results, comparisons=comparisons)
    _save_output(report.to_dict(), output)


@bench_app.command("all")
def bench_all(
    iterations: Annotated[int, typer.Option("--iterations", "-n", help="Number of iterations")] = 1000,
    warmup: Annotated[int, typer.Option("--warmup", help="Warmup iterations")] = 10,
    output: OutputOption = None,
    verbose: VerboseOption = 0,
) -> None:
    """Run all benchmarks (KEM + signatures)."""
    _setup_logging(verbose)
    console.print("[bold]Running full benchmark suite...[/bold]\n")
    bench_kem(iterations=iterations, warmup=warmup, output=None, verbose=verbose)
    console.print()
    bench_sign(iterations=iterations, warmup=warmup, output=None, verbose=verbose)

    if output:
        console.print(f"\n[green]Note: Use 'benchmark kem -o' or 'benchmark sign -o' to save individual results.[/green]")


@bench_app.command("hardware")
def bench_hardware() -> None:
    """Show detected hardware profile."""
    from src.benchmarker.hardware_profile import detect_hardware

    hw = detect_hardware()
    table = Table(title="Hardware Profile", show_header=False)
    table.add_column("Property", style="bold", width=20)
    table.add_column("Value", width=50)

    table.add_row("CPU", hw.cpu_model)
    table.add_row("Architecture", hw.cpu_arch)
    table.add_row("Cores/Threads", f"{hw.cpu_cores}/{hw.cpu_threads}")
    table.add_row("Frequency", f"{hw.cpu_frequency_mhz:.0f} MHz")
    table.add_row("RAM", f"{hw.ram_total_gb:.1f} GB")
    table.add_row("OS", f"{hw.os_name} {hw.os_version}")
    table.add_row("Python", hw.python_version)
    table.add_row("OpenSSL", hw.openssl_version)
    table.add_row("liboqs", hw.liboqs_version)
    table.add_row("AES-NI", "[green]Yes[/green]" if hw.has_aesni else "[red]No[/red]")
    table.add_row("AVX2", "[green]Yes[/green]" if hw.has_avx2 else "[red]No[/red]")
    table.add_row("AVX-512", "[green]Yes[/green]" if hw.has_avx512 else "[red]No[/red]")
    table.add_row("SHA Extensions", "[green]Yes[/green]" if hw.has_sha_ext else "[red]No[/red]")

    console.print(table)


def _merge_kem_results(
    keygen_results: list, encaps_results: list,
) -> list:
    """Merge keygen and encaps results for the same algorithm."""
    from src.benchmarker.models import KEMBenchmarkResult
    merged: dict[str, KEMBenchmarkResult] = {}

    for r in keygen_results:
        merged[r.algorithm] = KEMBenchmarkResult(
            algorithm=r.algorithm,
            iterations=r.iterations,
            keygen=r.keygen,
            pubkey_bytes=r.pubkey_bytes,
            seckey_bytes=r.seckey_bytes,
        )

    for r in encaps_results:
        if r.algorithm in merged:
            merged[r.algorithm].encaps = r.encaps
            merged[r.algorithm].decaps = r.decaps
            merged[r.algorithm].ciphertext_bytes = r.ciphertext_bytes
        else:
            merged[r.algorithm] = r

    return list(merged.values())


def _merge_sign_results(sign_results: list, keygen_results: list) -> list:
    """Merge sign/verify and keygen results for the same algorithm."""
    merged: dict[str, object] = {}

    for r in sign_results:
        merged[r.algorithm] = r

    for r in keygen_results:
        name = r.algorithm.replace("-Sign", "")
        if name in merged:
            merged[name].keygen = r.keygen
            if not merged[name].pubkey_bytes and r.pubkey_bytes:
                merged[name].pubkey_bytes = r.pubkey_bytes
                merged[name].seckey_bytes = r.seckey_bytes
        elif r.algorithm in merged:
            merged[r.algorithm].keygen = r.keygen

    return list(merged.values())


@app.command("roadmap")
def generate_roadmap(
    scan_results: Annotated[str, typer.Argument(help="Path to scan results JSON file")],
    organization: Annotated[str, typer.Option("--org", help="Organization name")] = "",
    exposure: Annotated[Optional[int], typer.Option("--exposure", help="Exposure factor (1-3)")] = None,
    sensitivity: Annotated[Optional[int], typer.Option("--sensitivity", help="Data sensitivity (1-5)")] = None,
    output: OutputOption = None,
    language: LanguageOption = "en",
    verbose: VerboseOption = 0,
) -> None:
    """Generate migration roadmap from scan results."""
    _setup_logging(verbose)
    set_language(language)  # type: ignore[arg-type]

    from src.roadmap.compliance_checker import check_compliance
    from src.roadmap.cost_estimator import estimate_cost, format_vnd
    from src.roadmap.models import MigrationRoadmap
    from src.roadmap.priority_engine import build_migration_tasks, build_phases
    from src.roadmap.recommendation import recommend_all
    from src.roadmap.risk_scorer import score_findings
    from src.roadmap.timeline_generator import generate_timeline
    from src.scanner.models import Finding

    # Load scan results
    results_path = Path(scan_results)
    if not results_path.exists():
        console.print(f"[red]File not found: {scan_results}[/red]")
        raise typer.Exit(1)

    import json as json_mod
    data = json_mod.loads(results_path.read_text())

    findings: list[Finding] = []
    # Support both "results" and "scan_results" keys
    scan_data = data.get("results", data.get("scan_results", []))
    for r in scan_data:
        for f_data in r.get("findings", []):
            findings.append(Finding(
                component=f_data["component"],
                algorithm=f_data["algorithm"],
                risk_level=RiskLevel(f_data["risk_level"]),
                quantum_vulnerable=f_data["quantum_vulnerable"],
                location=f_data.get("location", ""),
                replacement=f_data.get("replacement", []),
                migration_priority=f_data.get("migration_priority", 5),
                note=f_data.get("note", ""),
            ))

    if not findings:
        console.print("[red]No findings in scan results.[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Loaded {len(findings)} findings from {scan_results}[/bold]\n")

    # Build roadmap
    with console.status("Computing risk scores..."):
        risk_scores = score_findings(findings, exposure, sensitivity)
    with console.status("Generating recommendations..."):
        recommendations = recommend_all(findings)
    with console.status("Building migration plan..."):
        tasks = build_migration_tasks(findings, risk_scores, recommendations)
        phases = build_phases(tasks)
    with console.status("Estimating costs..."):
        cost = estimate_cost(phases)
    with console.status("Checking compliance..."):
        compliance = check_compliance(findings)

    timeline = generate_timeline(phases)

    # Overall risk
    critical_count = sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL)
    high_count = sum(1 for f in findings if f.risk_level == RiskLevel.HIGH)
    if critical_count > 0:
        overall = RiskLevel.CRITICAL
    elif high_count > 0:
        overall = RiskLevel.HIGH
    else:
        overall = RiskLevel.MEDIUM

    roadmap = MigrationRoadmap(
        organization=organization,
        overall_risk=overall,
        phases=phases,
        risk_scores=risk_scores,
        cost_estimate=cost,
        compliance=compliance,
        total_findings=len(findings),
        critical_findings=critical_count,
        quantum_vulnerable_count=sum(1 for f in findings if f.quantum_vulnerable),
    )

    # Display roadmap
    console.print(f"[bold]Overall Risk: [{_risk_style(overall)}]{overall.value}[/{_risk_style(overall)}][/bold]")
    console.print(f"Total findings: {len(findings)} | Critical: {critical_count} | QV: {roadmap.quantum_vulnerable_count}\n")

    for phase in phases:
        if not phase.tasks:
            continue
        console.print(f"[bold cyan]Phase {phase.phase_number} — {phase.name}[/bold cyan] ({phase.timeline})")
        for task in phase.tasks[:5]:
            console.print(f"  [{_risk_icon_for_priority(task.priority)}] {task.title} ({task.effort_hours}h)")
        if len(phase.tasks) > 5:
            console.print(f"  ... and {len(phase.tasks) - 5} more tasks")
        console.print(f"  Total effort: {phase.total_effort_hours} person-hours\n")

    # Cost summary
    console.print("[bold]Cost Estimation:[/bold]")
    console.print(f"  Total effort: {cost.total_person_hours} person-hours")
    console.print(f"  Timeline: {cost.timeline_months} months")
    console.print(f"  Cost range: {format_vnd(cost.cost_range_low_vnd)} — {format_vnd(cost.cost_range_high_vnd)}")

    # Compliance
    console.print("\n[bold]Compliance:[/bold]")
    for c in compliance:
        status_style = {"compliant": "green", "non_compliant": "red", "partial": "yellow"}.get(c.status, "white")
        console.print(f"  [{status_style}]{c.status.upper()}[/{status_style}] {c.standard}")

    _save_output(roadmap.to_dict(), output)


@app.command("report")
def generate_report(
    scan_results: Annotated[str, typer.Argument(help="Path to scan results JSON file")],
    format: Annotated[str, typer.Option("--format", "-f", help="Report format: html, json, sarif")] = "html",
    organization: Annotated[str, typer.Option("--org", help="Organization name")] = "",
    prepared_by: Annotated[str, typer.Option("--prepared-by", help="Report author")] = "",
    output: Annotated[str, typer.Option("--output", "-o", help="Output file path")] = "report.html",
    language: LanguageOption = "en",
    verbose: VerboseOption = 0,
) -> None:
    """Generate assessment report from scan results."""
    _setup_logging(verbose)
    set_language(language)  # type: ignore[arg-type]

    from src.roadmap.compliance_checker import check_compliance
    from src.roadmap.cost_estimator import estimate_cost
    from src.roadmap.models import MigrationRoadmap
    from src.roadmap.priority_engine import build_migration_tasks, build_phases
    from src.roadmap.recommendation import recommend_all
    from src.roadmap.risk_scorer import score_findings
    from src.scanner.models import Finding

    # Load scan results
    results_path = Path(scan_results)
    if not results_path.exists():
        console.print(f"[red]File not found: {scan_results}[/red]")
        raise typer.Exit(1)

    import json as json_mod
    data = json_mod.loads(results_path.read_text())

    findings: list[Finding] = []
    scan_data = data.get("results", data.get("scan_results", []))
    for r in scan_data:
        for f_data in r.get("findings", []):
            findings.append(Finding(
                component=f_data["component"],
                algorithm=f_data["algorithm"],
                risk_level=RiskLevel(f_data["risk_level"]),
                quantum_vulnerable=f_data["quantum_vulnerable"],
                location=f_data.get("location", ""),
                replacement=f_data.get("replacement", []),
                migration_priority=f_data.get("migration_priority", 5),
                note=f_data.get("note", ""),
            ))

    if not findings:
        console.print("[red]No findings in scan results.[/red]")
        raise typer.Exit(1)

    # Build roadmap
    with console.status("Building roadmap..."):
        risk_scores = score_findings(findings)
        recommendations = recommend_all(findings)
        tasks = build_migration_tasks(findings, risk_scores, recommendations)
        phases = build_phases(tasks)
        cost = estimate_cost(phases)
        compliance = check_compliance(findings)

    critical_count = sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL)
    overall = RiskLevel.CRITICAL if critical_count > 0 else RiskLevel.HIGH

    roadmap = MigrationRoadmap(
        organization=organization,
        overall_risk=overall,
        phases=phases,
        risk_scores=risk_scores,
        cost_estimate=cost,
        compliance=compliance,
        total_findings=len(findings),
        critical_findings=critical_count,
        quantum_vulnerable_count=sum(1 for f in findings if f.quantum_vulnerable),
    )

    # Generate report
    try:
        if format == "html":
            from src.reporter.html_report import generate_html_report, save_html_report
            html = generate_html_report(
                roadmap=roadmap,
                findings=findings,
                language=language,
                organization=organization,
                prepared_by=prepared_by,
            )
            save_html_report(html, output)
            console.print(f"[green]HTML report saved to: {output}[/green]")
        elif format == "json":
            from src.reporter.json_export import export_json
            export_json(roadmap, output)
            console.print(f"[green]JSON report saved to: {output}[/green]")
        elif format == "sarif":
            from src.reporter.json_export import export_sarif
            export_sarif(roadmap, output)
            console.print(f"[green]SARIF report saved to: {output}[/green]")
        else:
            console.print(f"[red]Unknown format: {format}. Use html, json, or sarif.[/red]")
            raise typer.Exit(1)
    except ImportError:
        console.print("[red]Reporter module not available in this deployment.[/red]")
        console.print("Install with: pip install -e '.[report]' or contact your administrator.")
        raise typer.Exit(1)


def _risk_icon_for_priority(priority: int) -> str:
    return {1: "red", 2: "yellow", 3: "yellow", 4: "green", 5: "cyan"}.get(priority, "white")


@app.command("version")
def version() -> None:
    """Show version information."""
    console.print("[bold]VN-PQC Readiness Analyzer[/bold] v0.3.0")
    console.print("https://github.com/xuxu298/PQCAnalyzer")


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
