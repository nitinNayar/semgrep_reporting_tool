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
        self.font_family = 'DejaVu'  # Default font family
        
        # Initialize Jinja2 environment for any templating needs
        self.jinja_env = Environment(
            loader=PackageLoader("semgrep_reporter", "templates"),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
    def _setup_pdf(self) -> FPDF:
        """Set up PDF document with fonts and basic configuration."""
        pdf = FPDF()
        
        # Set up font handling for Unicode text
        use_unicode_font = False
        
        try:
            # Path to embedded fonts
            fonts_dir = os.path.join(os.path.dirname(__file__), '..', 'fonts')
            
            dejavu_regular = os.path.join(fonts_dir, 'DejaVuSans.ttf')
            dejavu_bold = os.path.join(fonts_dir, 'DejaVuSans-Bold.ttf')
            dejavu_italic = os.path.join(fonts_dir, 'DejaVuSans-Oblique.ttf')
            dejavu_mono = os.path.join(fonts_dir, 'DejaVuSansMono.ttf')  # Add monospace font
            
            # Check if font files exist
            if all(os.path.exists(f) for f in [dejavu_regular, dejavu_bold, dejavu_italic]):
                pdf.add_font(self.font_family, '', dejavu_regular, uni=True)
                pdf.add_font(self.font_family, 'B', dejavu_bold, uni=True)
                pdf.add_font(self.font_family, 'I', dejavu_italic, uni=True)
                if os.path.exists(dejavu_mono):
                    pdf.add_font(f"{self.font_family}-Mono", '', dejavu_mono, uni=True)
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
                self.font_family = 'helvetica'
                use_unicode_font = True
                logger.debug("Using built-in Unicode font 'helvetica'")
            except Exception as e:
                logger.debug(f"Built-in Unicode font not available: {e}")
                self.font_family = 'Arial'
                logger.info("Using standard fonts with text sanitization")
        
        return pdf

    def _get_code_font(self, pdf: FPDF) -> tuple:
        """
        Get the appropriate monospace font for code sections.
        
        Args:
            pdf: The FPDF instance
            
        Returns:
            Tuple of (font_family, style) to use for code
        """
        try:
            # Try DejaVu Mono if available
            pdf.set_font(f"{self.font_family}-Mono", '', 9)
            return f"{self.font_family}-Mono", ''
        except RuntimeError:
            try:
                # Try Courier as fallback
                pdf.set_font('Courier', '', 9)
                return 'Courier', ''
            except RuntimeError:
                # Fall back to regular font if no monospace available
                return self.font_family, ''

    def _add_severity_summary_table(self, pdf: FPDF, findings: List[Finding], font_family: str) -> None:
        """Add a table showing severity counts per repository."""
        # Group findings by repository and count severities
        repo_stats = {}
        for finding in findings:
            repo = finding.get_repository_name() or "Unknown Repository"
            severity = finding.get_severity() or "Unknown"
            
            if repo not in repo_stats:
                repo_stats[repo] = {
                    'Critical': 0,
                    'High': 0,
                    'Medium': 0,
                    'Low': 0
                }
            
            # Only count Critical, High, Medium, and Low severities
            if severity.capitalize() in repo_stats[repo]:
                repo_stats[repo][severity.capitalize()] += 1
        
        if not repo_stats:
            return
            
        # Add table header
        pdf.ln(10)
        pdf.set_font(font_family, 'B', 12)
        pdf.cell(0, 10, TextSanitizer.sanitize_for_pdf("Findings by Severity"), ln=True)
        
        # Calculate column widths
        repo_width = 80  # Increased width for repository names
        severity_width = 25  # Increased width for each severity column
        total_width = repo_width + (severity_width * 4)  # 4 severity levels
        
        # Add column headers
        pdf.set_font(font_family, 'B', 10)
        x_start = pdf.get_x()
        y_start = pdf.get_y()
        
        # Repository column
        pdf.cell(repo_width, 8, TextSanitizer.sanitize_for_pdf("Repository"), border=1)
        
        # Severity columns
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            pdf.set_text_color(*self._get_severity_color(severity.upper()))
            pdf.cell(severity_width, 8, TextSanitizer.sanitize_for_pdf(severity), border=1, align='C')
        pdf.ln()
        
        # Reset text color to black
        pdf.set_text_color(0, 0, 0)
        
        # Add data rows
        pdf.set_font(font_family, '', 10)
        for repo, stats in repo_stats.items():
            # Repository name
            pdf.cell(repo_width, 8, TextSanitizer.sanitize_for_pdf(repo), border=1)
            
            # Severity counts
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                count = stats.get(severity, 0)
                pdf.cell(severity_width, 8, TextSanitizer.sanitize_for_pdf(str(count)), border=1, align='C')
            pdf.ln()
        
        # Add totals row
        pdf.set_font(font_family, 'B', 10)
        pdf.cell(repo_width, 8, TextSanitizer.sanitize_for_pdf("Total"), border=1)
        
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            total = sum(stats.get(severity, 0) for stats in repo_stats.values())
            pdf.cell(severity_width, 8, TextSanitizer.sanitize_for_pdf(str(total)), border=1, align='C')
        pdf.ln(10)

    def _add_finding_details(self, pdf: FPDF, findings: List[Finding]) -> None:
        """Add detailed findings information to the PDF."""
        pdf.add_page()
        pdf.set_font(self.font_family, 'B', 14)
        pdf.cell(0, 10, 'Finding Details', ln=True)
        
        # Define table properties
        col_width = {
            'label': 50,  # Width for label column
            'value': 140  # Width for value column
        }
        row_height = 8
        
        for i, finding in enumerate(findings, 1):
            finding_dict = FindingFormatter.to_dict(finding, deployment_slug=self.config.deployment_slug)
            
            # Add some spacing between findings
            pdf.ln(10)
            
            # Finding header with severity
            pdf.set_font(self.font_family, 'B', 12)
            severity = finding_dict.get('severity', 'Unknown').upper()
            pdf.set_text_color(*self._get_severity_color(severity))
            pdf.cell(0, 8, TextSanitizer.sanitize_for_pdf(f"Finding #{i}"), ln=True)
            pdf.set_text_color(0, 0, 0)  # Reset to black
            
            # Basic Information Table
            pdf.set_font(self.font_family, 'B', 10)
            pdf.set_fill_color(245, 245, 245)  # Light gray background
            
            # Function to add a table row
            def add_table_row(label: str, value: str, fill: bool = True, link: str = None):
                pdf.set_font(self.font_family, 'B', 10)
                pdf.cell(col_width['label'], row_height, TextSanitizer.sanitize_for_pdf(label), 1, 0, fill=fill)
                pdf.set_font(self.font_family, '', 10)
                
                # If this is a link, make it blue and underlined
                if link:
                    pdf.set_text_color(0, 0, 255)  # Blue for links
                    pdf.set_font(self.font_family, 'U', 10)  # Underline for links
                
                # Use multi_cell for value to handle long text, but need to track position
                current_x = pdf.get_x()
                current_y = pdf.get_y()
                
                if link:
                    # For links, we need to use cell instead of multi_cell to make it clickable
                    pdf.cell(col_width['value'], row_height, TextSanitizer.sanitize_for_pdf(value), 1, 0, fill=fill, link=link)
                    pdf.ln()
                else:
                    pdf.multi_cell(col_width['value'], row_height, TextSanitizer.sanitize_for_pdf(value), 1, fill=fill)
                    pdf.set_xy(current_x - col_width['label'], current_y + (pdf.get_y() - current_y))
                
                # Reset text color and font
                if link:
                    pdf.set_text_color(0, 0, 0)
                    pdf.set_font(self.font_family, '', 10)
            
            # Basic Information Section
            add_table_row("Check Id", finding_dict.get('check_id', 'N/A'))
            add_table_row("Summary", finding_dict.get('message', 'N/A'))
            add_table_row("Severity", severity)
            
            # Create the finding location string
            repo = finding_dict.get('repository', '')
            file_path = finding_dict.get('path', '')
            line_num = finding_dict.get('line', '')
            location = f"{repo}/{file_path}:{line_num}" if all([repo, file_path, line_num]) else 'N/A'
            
            # Add finding location with link
            add_table_row(
                "Finding Location",
                location,
                link=finding_dict.get('line_of_code_url') if location != 'N/A' else None
            )
            
            # Add vulnerability classification information
            vulnerability_classes = finding_dict.get('vulnerability_classes', [])
            if vulnerability_classes:
                add_table_row("Vulnerability Class", ", ".join(vulnerability_classes))
            else:
                add_table_row("Vulnerability Class", "N/A")
            
            # Format CWE information with links if available
            cwe_names = finding_dict.get('cwe_names', [])
            if cwe_names:
                # Extract CWE IDs and create links
                current_x = pdf.get_x()
                current_y = pdf.get_y()
                
                # Add the label
                pdf.set_font(self.font_family, 'B', 10)
                pdf.cell(col_width['label'], row_height, TextSanitizer.sanitize_for_pdf("CWE"), 1, 0, fill=True)
                
                # Add each CWE with its link
                pdf.set_font(self.font_family, 'U', 10)  # Underline for links
                pdf.set_text_color(0, 0, 255)  # Blue for links
                
                x_pos = pdf.get_x()
                y_pos = pdf.get_y()
                remaining_width = col_width['value']
                
                for i, cwe_name in enumerate(cwe_names):
                    if cwe_name.startswith('CWE-'):
                        cwe_id = cwe_name.split('-')[1].split(':')[0]  # Extract just the number
                        cwe_link = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
                        
                        # Add comma and space if not the first item
                        if i > 0:
                            pdf.set_font(self.font_family, '', 10)
                            pdf.set_text_color(0, 0, 0)
                            pdf.cell(2, row_height, ", ", 0, 0)
                            pdf.set_font(self.font_family, 'U', 10)
                            pdf.set_text_color(0, 0, 255)
                        
                        # Add the clickable CWE text
                        pdf.cell(0, row_height, TextSanitizer.sanitize_for_pdf(cwe_name), 1, 0, link=cwe_link)
                
                pdf.ln()
                
                # Reset text color and font
                pdf.set_text_color(0, 0, 0)
                pdf.set_font(self.font_family, '', 10)
            else:
                add_table_row("CWE", "N/A")
            
            # Add OWASP Top 10 mapping
            owasp_categories = finding_dict.get('owasp_names', [])
            if owasp_categories:
                add_table_row("OWASP Top 10", ", ".join(owasp_categories))
            else:
                add_table_row("OWASP Top 10", "N/A")
            
            # AI Analysis Section
            pdf.ln(5)
            add_table_row("Triage Status", finding_dict.get('triage_state', 'N/A'))
            add_table_row("AI Triage Verdict", finding_dict.get('autotriage_verdict', 'N/A'))
            add_table_row("AI Component", finding_dict.get('component_tag', 'N/A'))
            add_table_row("AI Risk Level", finding_dict.get('component_risk', 'N/A'))
            add_table_row(
                "View in Semgrep",
                "Click to view in Semgrep Dashboard",
                link=finding_dict.get('semgrep_ui_url')
            )
            
            # Remediation Section
            pdf.ln(5)
            pdf.set_font(self.font_family, 'B', 10)
            pdf.cell(0, row_height, "Remediation Instructions", 1, 1, fill=True)
            pdf.set_font(self.font_family, '', 10)
            pdf.multi_cell(0, row_height, TextSanitizer.sanitize_for_pdf(finding_dict.get('guidance_instructions', 'N/A')), 1)
            
            pdf.ln(2)
            pdf.set_font(self.font_family, 'B', 10)
            pdf.cell(0, row_height, "Suggested Fix", 1, 1, fill=True)
            
            # Use monospace font for code
            code_font, code_style = self._get_code_font(pdf)
            pdf.set_font(code_font, code_style, 9)
            pdf.multi_cell(0, row_height, TextSanitizer.sanitize_for_pdf(finding_dict.get('autofix_code', 'N/A')), 1)
            
            # Add a separator line between findings
            if i < len(findings):
                pdf.ln(5)
                pdf.set_draw_color(200, 200, 200)  # Light gray
                pdf.line(20, pdf.get_y(), 190, pdf.get_y())

    def _get_severity_color(self, severity: str) -> tuple:
        """
        Get RGB color values for a severity level.
        
        Args:
            severity: The severity level (CRITICAL, HIGH, MEDIUM, LOW, or INFO)
            
        Returns:
            Tuple of (R, G, B) values for the severity color
        """
        severity_colors = {
            'CRITICAL': (153, 0, 0),    # Dark red
            'HIGH': (204, 0, 0),        # Red
            'MEDIUM': (255, 153, 0),    # Orange
            'LOW': (255, 204, 0),       # Yellow
            'INFO': (0, 102, 204),      # Blue
        }
        return severity_colors.get(severity.upper(), (0, 0, 0))  # Default to black if severity not found

    def _get_heatmap_color(self, count: int) -> tuple:
        """
        Get RGB color values for the heatmap based on count.
        
        Args:
            count: The number of findings
            
        Returns:
            Tuple of (R, G, B) values for the heatmap color
        """
        if count < 5:
            return (0, 153, 0)  # Green
        elif count < 15:
            return (255, 204, 0)  # Yellow
        else:
            return (255, 0, 0)  # Red

    def _add_vulnerability_classes_heatmap(self, pdf: FPDF, findings: List[Finding]) -> None:
        """Add a heatmap showing vulnerability classes distribution across repositories."""
        if not findings:
            return
            
        # Create a dictionary to store counts per repository and vulnerability class
        repo_vuln_counts = {}
        
        # Count Critical and High severity findings for each vulnerability class per repository
        for finding in findings:
            finding_dict = FindingFormatter.to_dict(finding)
            severity = finding_dict.get('severity', '').upper()
            repo = finding_dict.get('repository', 'Unknown')
            vuln_classes = finding_dict.get('vulnerability_classes', [])
            
            if severity in ['CRITICAL', 'HIGH'] and vuln_classes:
                if repo not in repo_vuln_counts:
                    repo_vuln_counts[repo] = {}
                    
                for vuln_class in vuln_classes:
                    if vuln_class not in repo_vuln_counts[repo]:
                        repo_vuln_counts[repo][vuln_class] = 0
                    repo_vuln_counts[repo][vuln_class] += 1
        
        if not repo_vuln_counts:
            return
            
        # Get unique vulnerability classes across all findings
        all_vuln_classes = set()
        for repo_data in repo_vuln_counts.values():
            all_vuln_classes.update(repo_data.keys())
        all_vuln_classes = sorted(list(all_vuln_classes))
        
        # Add title
        pdf.add_page()
        pdf.set_font(self.font_family, 'B', 14)
        pdf.cell(0, 10, 'Vulnerability Classes for Critical & High Severity Findings', ln=True)
        pdf.ln(5)
        
        # Calculate column widths and heights
        repo_col_width = 60  # Width for repository names
        class_col_width = 20  # Width for vulnerability class columns
        header_height = 80  # Height for vertical headers
        row_height = 8
        
        # Calculate total width needed and adjust page margins if necessary
        total_width = repo_col_width + (class_col_width * len(all_vuln_classes))
        if total_width > pdf.w - 20:  # If wider than page width minus margins
            # Reduce column widths to fit
            available_width = pdf.w - 20 - repo_col_width
            class_col_width = min(20, available_width / len(all_vuln_classes))
        
        # Start position for the table
        start_x = pdf.get_x()
        start_y = pdf.get_y()
        
        # Add header row with repository label
        pdf.set_font(self.font_family, 'B', 8)
        pdf.cell(repo_col_width, header_height, 'Repository', 1, 0, 'C')
        
        # Add vertical headers for vulnerability classes
        for vuln_class in all_vuln_classes:
            # Save current position
            current_x = pdf.get_x()
            current_y = pdf.get_y()
            
            # Draw the border for the header cell
            pdf.rect(current_x, current_y, class_col_width, header_height)
            
            # Calculate center position for text
            x_center = current_x + (class_col_width / 2)
            y_center = current_y + (header_height / 2)
            
            # Get text dimensions
            text = TextSanitizer.sanitize_for_pdf(vuln_class)
            text_width = pdf.get_string_width(text)
            
            # Save state and set up rotation
            pdf.rotate(90, x_center, y_center)
            
            # Position and write the text
            text_x = x_center - (text_width / 2)
            text_y = y_center + 3  # Small offset for better centering
            pdf.text(text_x, text_y, text)
            
            # Reset rotation
            pdf.rotate(0)
            
            # Move to next column position
            pdf.set_xy(current_x + class_col_width, current_y)
        
        pdf.ln(header_height)
        
        # Add data rows
        pdf.set_font(self.font_family, '', 8)
        for repo in sorted(repo_vuln_counts.keys()):
            # Repository name
            pdf.cell(repo_col_width, row_height, TextSanitizer.sanitize_for_pdf(repo), 1, 0)
            
            # Counts for each vulnerability class
            for vuln_class in all_vuln_classes:
                count = repo_vuln_counts[repo].get(vuln_class, 0)
                
                # Set cell background color based on count
                if count > 0:
                    pdf.set_fill_color(*self._get_heatmap_color(count))
                    pdf.set_text_color(255, 255, 255)  # White text for better visibility
                else:
                    pdf.set_fill_color(255, 255, 255)  # White background
                    pdf.set_text_color(0, 0, 0)  # Black text
                
                pdf.cell(class_col_width, row_height, str(count), 1, 0, 'C', True)
            
            # Reset colors and move to next line
            pdf.set_fill_color(255, 255, 255)
            pdf.set_text_color(0, 0, 0)
            pdf.ln()
        
        # Add legend
        pdf.ln(5)
        pdf.set_font(self.font_family, 'B', 8)
        pdf.cell(0, 5, 'Heatmap Legend:', ln=True)
        pdf.set_font(self.font_family, '', 8)
        
        legend_items = [
            ('< 5 findings', (0, 153, 0)),
            ('5-14 findings', (255, 204, 0)),
            ('>= 15 findings', (255, 0, 0))
        ]
        
        for text, color in legend_items:
            pdf.set_fill_color(*color)
            pdf.set_text_color(255, 255, 255) if color[0] == 255 else pdf.set_text_color(0, 0, 0)
            pdf.cell(30, 5, text, 1, 0, 'C', True)
            pdf.cell(5, 5, '', 0, 0)  # Space between legend items
        
        # Reset colors
        pdf.set_fill_color(255, 255, 255)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(10)

    def generate(self, findings: List[Finding]) -> None:
        """
        Generate PDF report with charts and formatted findings.
        
        Args:
            findings: List of findings to include in the report
        """
        logger.debug("Generating PDF report")
        
        try:
            # Initialize PDF with appropriate font setup
            pdf = self._setup_pdf()
            
            # Add title page
            pdf.add_page()
            pdf.set_font(self.font_family, 'B', 16)
            pdf.cell(0, 10, TextSanitizer.sanitize_for_pdf(self.config.report_title), ln=True, align="C")

            # Add company logo if configured
            if self.config.company_logo and self.config.company_logo.exists():
                logger.debug(f"Adding company logo from {self.config.company_logo}")
                pdf.image(str(self.config.company_logo), x=10, y=10, w=30)

            # Add summary statistics
            pdf.set_font(self.font_family, 'B', 12)
            pdf.cell(0, 10, TextSanitizer.sanitize_for_pdf(f"Total Findings: {len(findings)}"), ln=True)
            generation_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
            pdf.cell(0, 10, TextSanitizer.sanitize_for_pdf(f"Generated on: {generation_date}"), ln=True)

            # Add severity summary table
            if findings:
                self._add_severity_summary_table(pdf, findings, self.font_family)
                
                # Add vulnerability classes heatmap
                self._add_vulnerability_classes_heatmap(pdf, findings)
                
                # Add detailed findings
                self._add_finding_details(pdf, findings)

            # Save the PDF
            output_path = self.output_dir / "semgrep_report.pdf"
            pdf.output(str(output_path))
            logger.info(f"PDF report saved to {output_path}")
            
        except Exception as e:
            logger.error(f"Error in PDF generation: {e}")
            logger.exception("PDF generation error details")
            raise
