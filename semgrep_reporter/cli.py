"""
Command-line interface for the Semgrep Reporter tool.
"""

import logging
import sys
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, BarColumn, TimeRemainingColumn, SpinnerColumn, TextColumn, TaskProgressColumn, track

from . import __version__
from .api import SemgrepClient
from .config import APIConfig, FilterConfig, ReportConfig, Settings
from .reports import ReportGenerator

# Create console for output
console = Console()

# Set up logging based on debug flag
class RichConsoleHandler(logging.Handler):
    def emit(self, record):
        try:
            msg = self.format(record)
            level = record.levelname
            
            # Force a new line before each log message
            console.print()
            
            if level == 'DEBUG':
                console.print(f"[dim]{msg}[/dim]")
            elif level == 'INFO':
                console.print(msg)
            elif level == 'WARNING':
                console.print(f"[yellow]{msg}[/yellow]")
            elif level == 'ERROR':
                console.print(f"[red]{msg}[/red]")
            elif level == 'CRITICAL':
                console.print(f"[red bold]{msg}[/red bold]")
        except Exception:
            self.handleError(record)

# Configure root logger
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichConsoleHandler()]
)

logger = logging.getLogger("semgrep_reporter")


@click.group()
@click.version_option(version=__version__)
def cli():
    """Semgrep Reporter - Generate customizable security reports from Semgrep findings."""
    pass


def common_options(function):
    """Common CLI options for both SAST and SCA commands."""
    function = click.option(
        "--api-token",
        envvar="SEMGREP_API_TOKEN",
        help="Semgrep API token (can also be set via SEMGREP_API_TOKEN env var)",
        required=True,
    )(function)
    function = click.option(
        "--deployment-slug",
        envvar="SEMGREP_DEPLOYMENT_SLUG",
        help="Semgrep deployment slug (can also be set via SEMGREP_DEPLOYMENT_SLUG env var)",
        required=True,
    )(function)
    function = click.option(
        "--output-dir",
        type=click.Path(path_type=Path),
        default="./reports",
        help="Directory to store generated reports",
    )(function)
    function = click.option(
        "--format",
        "output_formats",
        multiple=True,
        type=click.Choice(["pdf", "csv", "xlsx"]),
        default=["pdf", "csv"],
        help="Output format(s) for the report",
    )(function)
    function = click.option(
        "--repository",
        "repositories",
        multiple=True,
        help="Filter by repository name (can be specified multiple times)",
    )(function)
    function = click.option(
        "--tag",
        "tags",
        multiple=True,
        help="Filter by repository tag (can be specified multiple times)",
    )(function)
    function = click.option(
        "--severity",
        "severity_levels",
        multiple=True,
        type=click.Choice(["INFO", "WARNING", "ERROR"]),
        help="Filter by severity level (can be specified multiple times)",
    )(function)
    function = click.option(
        "--include-charts/--no-charts",
        default=True,
        help="Include visualization charts in the reports",
    )(function)
    function = click.option(
        "--company-logo",
        type=click.Path(exists=True, path_type=Path),
        help="Path to company logo to include in reports",
    )(function)
    function = click.option(
        "--debug/--no-debug",
        default=False,
        help="Enable debug mode for more verbose output",
    )(function)
    function = click.option(
        "--api-url",
        default="https://semgrep.dev/api/v1",
        help="Semgrep API base URL (only change if using a custom Semgrep deployment)",
    )(function)
    return function


def generate_report(
    issue_type: str = "sast",
    repositories: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    severity_levels: Optional[List[str]] = None,
    output_formats: Optional[List[str]] = None,
    output_dir: str = "reports",
    config_file: Optional[str] = None,
    api_token: Optional[str] = None,
    deployment_slug: Optional[str] = None,
    api_url: Optional[str] = None,
    include_charts: bool = True,
    company_logo: Optional[Path] = None,
    report_title: Optional[str] = None,
    debug: bool = False,
) -> None:
    """
    Generate reports for Semgrep findings.
    
    Args:
        issue_type: Type of findings to fetch ("sast" or "sca")
        repositories: Optional list of repository names to filter by
        tags: Optional list of repository tags to filter by
        severity_levels: Optional list of severity levels to filter by
        output_formats: Optional list of report formats to generate
        output_dir: Directory to store generated reports
        config_file: Path to configuration file
        api_token: Semgrep API token
        deployment_slug: Semgrep deployment slug
        api_url: Semgrep API base URL
        include_charts: Whether to include charts in reports
        company_logo: Path to company logo for reports
        report_title: Custom title for the report
        debug: Enable debug mode
    """
    # Set up logging based on debug flag
    log_level = logging.DEBUG if debug else logging.INFO
    logger.setLevel(log_level)

    # Create progress display with refresh_per_second=1 to reduce flicker
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False,
        refresh_per_second=1,
        expand=True
    ) as progress:
        # Create overall task
        overall_task = progress.add_task("[cyan]Processing findings...", total=100)
        progress.update(overall_task, completed=10)
        
        # Create API config
        api_config = APIConfig(
            token=api_token,
            deployment_slug=deployment_slug,
            api_url=api_url
        )
        
        # Initialize Semgrep client
        client = SemgrepClient(api_config)
        
        # Create task for fetching findings
        fetch_task = progress.add_task("[yellow]Fetching findings...", total=100)
        
        def update_fetch_progress(current: int, total: int):
            if total > 0:
                progress.update(fetch_task, completed=(current / total) * 100)
                # Update overall progress (10-50%)
                overall_progress = 10 + (current / total) * 40
                progress.update(overall_task, completed=overall_progress)
        
        # Fetch findings with progress callback
        findings = client.get_findings(
            issue_type=issue_type,
            repositories=repositories,
            tags=tags,
            severity_levels=severity_levels,
            progress_callback=update_fetch_progress,
            console=console
        )
        
        # Complete fetch task
        progress.update(fetch_task, completed=100)
        progress.update(overall_task, completed=50)
        
        # Create reports task
        if not output_formats:
            output_formats = ["pdf", "xlsx"]
            
        reports_task = progress.add_task("[green]Generating reports...", total=len(output_formats))
        
        # Create report config
        report_config = ReportConfig(
            output_formats=output_formats,
            include_charts=include_charts,
            company_logo=company_logo,
            report_title=report_title or f"Semgrep {issue_type.upper()} Findings Report",
            deployment_slug=deployment_slug
        )
        
        # Initialize report generator
        generator = ReportGenerator(report_config, Path(output_dir))
        
        # Generate all reports at once
        generator.generate_reports(findings)
        
        # Update progress for each format
        for i, report_format in enumerate(output_formats, 1):
            progress.update(reports_task, description=f"[green]Generated {report_format} report...")
            progress.update(reports_task, advance=1)
            # Update overall progress (50-100%)
            overall_progress = 50 + (i / len(output_formats)) * 50
            progress.update(overall_task, completed=overall_progress)
            
        # Complete all tasks
        progress.update(overall_task, completed=100)
        
        # Show completion message
        console.print("\n[bold green]Successfully generated reports in:[/bold green]")
        for format_type in output_formats:
            if format_type == "pdf":
                console.print(f"  • {output_dir}/semgrep_report.pdf")
            elif format_type == "xlsx":
                console.print(f"  • {output_dir}/semgrep_findings.xlsx")


@cli.command()
@common_options
@click.option(
    "--report-title",
    default="Semgrep SAST Findings Report",
    help="Title for the generated reports",
)
def sast(**kwargs):
    """Generate security reports for SAST (Static Application Security Testing) findings."""
    generate_report("sast", **kwargs)


@cli.command()
@common_options
@click.option(
    "--report-title",
    default="Semgrep SCA Findings Report",
    help="Title for the generated reports",
)
def sca(**kwargs):
    """Generate security reports for SCA (Software Composition Analysis) findings."""
    generate_report("sca", **kwargs)


def main():
    """Entry point for the CLI."""
    try:
        cli()
    except Exception as e:
        logger.exception("Unhandled exception")
        console.print(f"[red]Unhandled error: {str(e)}[/red]")
        sys.exit(1) 