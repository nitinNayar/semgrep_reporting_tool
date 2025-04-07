"""
PDF report generation functionality.
"""

import datetime
import logging
import os
from pathlib import Path
from typing import List, Dict, Any

from fpdf import FPDF
from jinja2 import Environment, PackageLoader, select_autoescape

from ..api import Finding
from ..config import ReportConfig
from .charts import ChartGenerator
from .utils import FindingFormatter, TextSanitizer

logger = logging.getLogger("semgrep_reporter")

class PDFReportGenerator:
    """Generates PDF reports from Semgrep findings."""
    
    def __init__(self, config: ReportConfig, output_dir: Path):
        """
        Initialize PDF report generator.
        
        Args:
            config: Report configuration settings
            output_dir: Directory to store generated reports
        """
        self.config = config
        self.output_dir = output_dir
        self.chart_generator = ChartGenerator(config, output_dir)
        
        # Initialize Jinja2 environment for any templating needs
        self.jinja_env = Environment(
            loader=PackageLoader("semgrep_reporter", "templates"),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
    def _setup_pdf(self) -> FPDF:
        """Set up PDF document with fonts and basic configuration."""
        pdf = FPDF()
        
        # Set up font handling for Unicode text
        font_family = 'DejaVu'
        use_unicode_font = False
        
        try:
            # Path to embedded fonts
            fonts_dir = os.path.join(os.path.dirname(__file__), '..', 'fonts')
            
            dejavu_regular = os.path.join(fonts_dir, 'DejaVuSans.ttf')
            dejavu_bold = os.path.join(fonts_dir, 'DejaVuSans-Bold.ttf')
            dejavu_italic = os.path.join(fonts_dir, 'DejaVuSans-Oblique.ttf')
            
            # Check if font files exist
            if all(os.path.exists(f) for f in [dejavu_regular, dejavu_bold, dejavu_italic]):
                pdf.add_font(font_family, '', dejavu_regular, uni=True)
                pdf.add_font(font_family, 'B', dejavu_bold, uni=True)
                pdf.add_font(font_family, 'I', dejavu_italic, uni=True)
                use_unicode_font = True
                logger.debug(f"Using embedded DejaVu Sans fonts from {fonts_dir}")
            else:
                logger.warning(f"Embedded DejaVu fonts not found in {fonts_dir}")
        except Exception as font_error:
            logger.warning(f"Error adding embedded DejaVu fonts: {font_error}")
        
        # Try built-in Unicode font as fallback
        if not use_unicode_font:
            try:
                pdf.set_font('helvetica', '')
                font_family = 'helvetica'
                use_unicode_font = True
                logger.debug("Using built-in Unicode font 'helvetica'")
            except Exception as e:
                logger.debug(f"Built-in Unicode font not available: {e}")
                font_family = 'Arial'
                logger.info("Using standard fonts with text sanitization")
        
        return pdf, font_family

    def _add_severity_summary_table(self, pdf: FPDF, findings: List[Finding], font_family: str) -> None:
        """Add a table showing severity counts per repository."""
        # Group findings by repository and count severities
        repo_severity_counts = {}
        for finding in findings:
            repo = finding.get_repository_name() or "Unknown Repository"
            severity = finding.get_severity().upper() if finding.get_severity() else 'INFO'
            
            if repo not in repo_severity_counts:
                repo_severity_counts[repo] = {
                    'CRITICAL': 0,
                    'HIGH': 0,
                    'MEDIUM': 0,
                    'LOW': 0
                }
            
            if severity in repo_severity_counts[repo]:
                repo_severity_counts[repo][severity] += 1

        # Add table header
        pdf.ln(10)
        pdf.set_font(font_family, 'B', 12)
        pdf.cell(0, 10, TextSanitizer.sanitize_for_pdf("Open Findings by Repository and Severity"), ln=True)
        pdf.ln(5)

        # Define column widths (total = 190)
        col_widths = {
            'repo': 70,
            'critical': 30,
            'high': 30,
            'medium': 30,
            'low': 30
        }

        # Add table headers
        pdf.set_font(font_family, 'B', 9)
        pdf.set_fill_color(240, 240, 240)  # Light gray background
        
        pdf.cell(col_widths['repo'], 8, "Repository", 1, 0, 'L', True)
        pdf.cell(col_widths['critical'], 8, "Critical", 1, 0, 'C', True)
        pdf.cell(col_widths['high'], 8, "High", 1, 0, 'C', True)
        pdf.cell(col_widths['medium'], 8, "Medium", 1, 0, 'C', True)
        pdf.cell(col_widths['low'], 8, "Low", 1, 1, 'C', True)

        # Add data rows
        pdf.set_font(font_family, '', 9)
        for repo, counts in repo_severity_counts.items():
            # Repository name might be long, so truncate if needed
            repo_name = repo
            if len(repo_name) > 40:
                repo_name = repo_name[:37] + "..."
            
            pdf.cell(col_widths['repo'], 8, TextSanitizer.sanitize_for_pdf(repo_name), 1, 0, 'L')
            pdf.cell(col_widths['critical'], 8, str(counts['CRITICAL']), 1, 0, 'C')
            pdf.cell(col_widths['high'], 8, str(counts['HIGH']), 1, 0, 'C')
            pdf.cell(col_widths['medium'], 8, str(counts['MEDIUM']), 1, 0, 'C')
            pdf.cell(col_widths['low'], 8, str(counts['LOW']), 1, 1, 'C')

        pdf.ln(10)

    def _add_finding_details(self, pdf: FPDF, finding: Finding, font_family: str) -> None:
        """Add detailed information for a single finding."""
        finding_dict = FindingFormatter.to_dict(finding, deployment_slug=self.config.deployment_slug)
        
        # Basic finding information
        pdf.set_font(font_family, 'B', 10)
        pdf.cell(0, 10, TextSanitizer.sanitize_for_pdf(f"Finding: {finding_dict['check_id']}"), ln=True)
        
        pdf.set_font(font_family, '', 9)
        pdf.multi_cell(0, 5, TextSanitizer.sanitize_for_pdf(
            f"Severity: {finding_dict['severity'].upper() if finding_dict['severity'] else 'Unknown'}\n"
            f"Status: {finding_dict['status'] or 'N/A'}\n"
            f"State: {finding_dict['state'] or 'N/A'}\n"
            f"Triage State: {finding_dict['triage_state'] or 'N/A'}\n"
            f"File: {finding_dict['path']}:{finding_dict['line']}\n"
        ))
        
        # Add SCA information if this is a dependency finding
        if finding_dict['is_dependency']:
            pdf.ln(2)
            pdf.set_font(font_family, 'B', 9)
            pdf.cell(0, 5, "Dependency Information:", ln=True)
            pdf.set_font(font_family, '', 9)
            
            sca_info = []
            if finding_dict['dependency_name']:
                sca_info.append(f"Package: {finding_dict['dependency_name']}")
            if finding_dict['dependency_version']:
                sca_info.append(f"Version: {finding_dict['dependency_version']}")
            if finding_dict['fixed_version']:
                sca_info.append(f"Fixed in Version: {finding_dict['fixed_version']}")
            if finding_dict['ecosystem']:
                sca_info.append(f"Ecosystem: {finding_dict['ecosystem']}")
            if finding_dict['cve_ids']:
                sca_info.append(f"CVE IDs: {', '.join(finding_dict['cve_ids'])}")
            if finding_dict['reachable'] is not None:
                sca_info.append(f"Reachable: {'Yes' if finding_dict['reachable'] else 'No'}")
            
            pdf.multi_cell(0, 5, TextSanitizer.sanitize_for_pdf('\n'.join(sca_info)))
        
        # Add links
        if finding_dict['line_of_code_url'] or finding_dict['semgrep_ui_url']:
            pdf.ln(2)
            pdf.set_text_color(0, 0, 255)  # Blue for links
            pdf.set_font(font_family, 'U', 9)
            
            if finding_dict['line_of_code_url']:
                pdf.cell(0, 5, "View in repository", link=finding_dict['line_of_code_url'])
                pdf.ln()
            
            if finding_dict['semgrep_ui_url']:
                pdf.cell(0, 5, "View in Semgrep UI", link=finding_dict['semgrep_ui_url'])
                pdf.ln()
            
            pdf.set_font(font_family, '', 9)
            pdf.set_text_color(0, 0, 0)
        
        # Message/Description
        pdf.ln(2)
        pdf.set_font(font_family, 'B', 9)
        pdf.cell(0, 5, "Description:", ln=True)
        pdf.set_font(font_family, '', 9)
        pdf.multi_cell(0, 5, TextSanitizer.sanitize_for_pdf(finding_dict['message'] or "No description available"))
        
        # Add separator between findings
        pdf.ln(5)
        pdf.cell(0, 0, "", ln=True, border="T")
        pdf.ln(5)

    def generate(self, findings: List[Finding]) -> None:
        """
        Generate PDF report with charts and formatted findings.
        
        Args:
            findings: List of findings to include in the report
        """
        logger.debug("Generating PDF report")
        
        try:
            # Initialize PDF with appropriate font setup
            pdf, font_family = self._setup_pdf()
            
            # Add title page
            pdf.add_page()
            pdf.set_font(font_family, 'B', 16)
            pdf.cell(0, 10, TextSanitizer.sanitize_for_pdf(self.config.report_title), ln=True, align="C")

            # Add company logo if configured
            if self.config.company_logo and self.config.company_logo.exists():
                logger.debug(f"Adding company logo from {self.config.company_logo}")
                pdf.image(str(self.config.company_logo), x=10, y=10, w=30)

            # Add summary statistics
            pdf.set_font(font_family, 'B', 12)
            pdf.cell(0, 10, TextSanitizer.sanitize_for_pdf(f"Total Findings: {len(findings)}"), ln=True)
            generation_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
            pdf.cell(0, 10, TextSanitizer.sanitize_for_pdf(f"Generated on: {generation_date}"), ln=True)

            # Add severity summary table
            if findings:
                self._add_severity_summary_table(pdf, findings, font_family)

            # Add charts if enabled
            if self.config.include_charts and findings:
                logger.debug("Adding charts to PDF")
                pdf.add_page()  # Start charts on a new page
                
                # Generate and add severity chart
                severity_chart = self.chart_generator.create_severity_chart(findings)
                if severity_chart:
                    # Center the chart on the page
                    page_width = pdf.w
                    chart_width = 190  # Width in mm
                    x_position = (page_width - chart_width) / 2
                    pdf.image(str(severity_chart), x=x_position, y=30, w=chart_width)
                
                # Clean up temporary chart files
                self.chart_generator.cleanup_charts()

            # Group findings by repository
            findings_by_repo = {}
            for finding in findings:
                repo = finding.get_repository_name() or "Unknown Repository"
                if repo not in findings_by_repo:
                    findings_by_repo[repo] = []
                findings_by_repo[repo].append(finding)

            # Add findings for each repository
            for repo_name, repo_findings in findings_by_repo.items():
                pdf.add_page()
                
                # Repository header
                pdf.set_font(font_family, 'B', 14)
                pdf.cell(0, 10, TextSanitizer.sanitize_for_pdf(f"Repository: {repo_name}"), ln=True)
                
                # Add each finding's details
                for finding in repo_findings:
                    self._add_finding_details(pdf, finding, font_family)

            # Save the PDF
            output_path = self.output_dir / "semgrep_report.pdf"
            pdf.output(str(output_path))
            logger.info(f"PDF report saved to {output_path}")
            
        except Exception as e:
            logger.error(f"Error in PDF generation: {e}")
            logger.exception("PDF generation error details")
            raise
