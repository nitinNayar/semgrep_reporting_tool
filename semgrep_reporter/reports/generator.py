"""
Main report generator coordination module.
"""

import json
import logging
from pathlib import Path
from typing import List, Optional

from ..api import Finding
from ..config import ReportConfig
from .csv_report import CSVReportGenerator
from .excel_report import ExcelReportGenerator
from .pdf_report import PDFReportGenerator

logger = logging.getLogger("semgrep_reporter")

class ReportGenerator:
    """Main class for coordinating report generation in various formats."""
    
    def __init__(self, config: ReportConfig, output_dir: Path):
        """
        Initialize the report generator.
        
        Args:
            config: Report configuration settings
            output_dir: Directory to store generated reports
        """
        self.config = config
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.debug(f"ReportGenerator initialized with output directory: {output_dir}")
        
    def generate_reports(self, findings: List[Finding]) -> None:
        """
        Generate reports in all configured formats.
        
        Args:
            findings: List of findings to include in the reports
        """
        logger.info(f"Generating reports for {len(findings)} findings in formats: {self.config.output_formats}")
        
        # First save the raw findings data
        try:
            raw_findings = [
                finding.raw_response 
                for finding in findings 
                if hasattr(finding, 'raw_response')
            ]
            if raw_findings:
                raw_output_path = self.output_dir / "semgrep_raw_findings.json"
                with open(raw_output_path, 'w') as f:
                    json.dump(raw_findings, f, indent=2)
                logger.info(f"Raw API response saved to {raw_output_path}")
        except Exception as e:
            logger.error(f"Error saving raw API response: {e}")
            logger.exception("Raw data save error details")

        # Generate configured report formats
        for format_type in self.config.output_formats:
            try:
                if format_type == "pdf":
                    generator = PDFReportGenerator(
                        self.config,
                        self.output_dir
                    )
                    generator.generate(findings)
                    
                elif format_type == "csv":
                    generator = CSVReportGenerator(
                        self.config,
                        self.output_dir
                    )
                    generator.generate(findings)
                    
                elif format_type == "xlsx":
                    generator = ExcelReportGenerator(
                        self.config,
                        self.output_dir
                    )
                    generator.generate(findings)
                    
                logger.debug(f"Successfully generated {format_type} report")
                
            except Exception as e:
                logger.error(f"Error generating {format_type} report: {e}")
                logger.exception("Report generation error details")
