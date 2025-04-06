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
from rich.progress import Progress

from . import __version__
from .api import SemgrepClient
from .config import APIConfig, FilterConfig, ReportConfig, Settings
from .reports import ReportGenerator

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("semgrep_reporter")

console = Console()


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
    finding_type: str,
    api_token: str,
    deployment_slug: str,
    output_dir: Path,
    output_formats: List[str],
    repositories: Optional[List[str]],
    tags: Optional[List[str]],
    severity_levels: Optional[List[str]],
    include_charts: bool,
    company_logo: Optional[Path],
    report_title: str,
    debug: bool,
    api_url: str,
):
    """Common function to generate reports for both SAST and SCA findings."""
    
    # Set logging level based on debug flag
    if debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled")
    
    try:
        # Create configuration
        logger.debug(f"Setting up with deployment_slug: {deployment_slug}")
        logger.debug(f"API URL: {api_url}")
        
        settings = Settings(
            api=APIConfig(
                api_token=api_token,
                deployment_slug=deployment_slug,
                api_url=api_url
            ),
            report=ReportConfig(
                output_formats=list(output_formats),
                include_charts=include_charts,
                company_logo=company_logo,
                report_title=report_title,
            ),
            filters=FilterConfig(
                repositories=list(repositories) if repositories else None,
                tags=list(tags) if tags else None,
                severity_levels=list(severity_levels) if severity_levels else None,
            ),
            output_dir=output_dir,
        )

        # Initialize components
        client = SemgrepClient(settings.api)
        
        with Progress() as progress:
            # Create a progress task for findings fetching
            fetch_task = progress.add_task(f"Fetching {finding_type.upper()} findings...", total=None)
            
            # Fetch findings with specific type
            logger.debug(f"Calling Semgrep API to fetch {finding_type} findings...")
            findings = client.get_findings(
                repositories=settings.filters.repositories,
                tags=settings.filters.tags,
                severity_levels=settings.filters.severity_levels,
                finding_types=[finding_type],
                progress=progress,
                progress_task=fetch_task
            )
            
            if not findings:
                console.print(f"[yellow]Warning: No {finding_type.upper()} findings were returned from the Semgrep API.[/yellow]")
                console.print("This could be because:")
                console.print("  • There are no security issues in the repositories")
                console.print("  • The API token doesn't have access to the specified deployment")
                console.print("  • The deployment slug is incorrect")
                console.print("  • The filters you specified returned no results")
                
                if click.confirm("Do you want to continue and generate empty reports?", default=False):
                    console.print("[yellow]Continuing with empty reports...[/yellow]")
                else:
                    console.print("[yellow]Aborting.[/yellow]")
                    sys.exit(0)

            # Generate reports
            progress.update(fetch_task, description="Generating reports...")
            
            # Update report title based on finding type
            settings.report.report_title = f"Semgrep {finding_type.upper()} Findings Report"
            
            # Create output directory with finding type
            type_output_dir = output_dir / finding_type
            type_output_dir.mkdir(parents=True, exist_ok=True)
            
            generator = ReportGenerator(settings.report, type_output_dir)
            generator.generate_reports(findings)
            progress.update(fetch_task, completed=100)

        console.print(f"\n[green]Successfully generated {finding_type.upper()} reports in {type_output_dir}[/green]")
        console.print("\nGenerated files:")
        for format_type in output_formats:
            if format_type == "pdf":
                console.print(f"  • {type_output_dir}/semgrep_report.pdf")
            elif format_type == "csv":
                console.print(f"  • {type_output_dir}/semgrep_findings.csv")
            elif format_type == "xlsx":
                console.print(f"  • {type_output_dir}/semgrep_findings.xlsx")

    except Exception as e:
        logger.exception("Error occurred during report generation")
        console.print(f"\n[red]Error: {str(e)}[/red]")
        if debug:
            console.print_exception()
        raise click.Abort()


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