"""
CSV report generation functionality.
"""

import csv
import logging
from pathlib import Path
from typing import List

from ..api import Finding
from ..config import ReportConfig
from .utils import FindingFormatter, ReportFields

logger = logging.getLogger("semgrep_reporter")

class CSVReportGenerator:
    """Generates CSV reports from Semgrep findings."""
    
    def __init__(self, config: ReportConfig, output_dir: Path):
        """
        Initialize CSV report generator.
        
        Args:
            config: Report configuration settings
            output_dir: Directory to store generated reports
        """
        self.config = config
        self.output_dir = output_dir
        
    def generate(self, findings: List[Finding]) -> None:
        """
        Generate CSV report with all findings.
        
        Args:
            findings: List of findings to include in the report
        """
        logger.debug("Generating CSV report")
        output_path = self.output_dir / "semgrep_findings.csv"
        
        try:
            # Get all fields for the CSV
            fieldnames = ReportFields.get_all_fields()
            
            with open(output_path, "w", newline="") as csvfile:
                writer = csv.DictWriter(
                    csvfile,
                    fieldnames=fieldnames
                )
                writer.writeheader()
                
                if not findings:
                    logger.debug("No findings to write to CSV")
                else:
                    for finding in findings:
                        writer.writerow(FindingFormatter.to_dict(
                            finding,
                            deployment_slug=self.config.deployment_slug
                        ))
            
            logger.info(f"CSV report saved to {output_path}")
            
        except Exception as e:
            logger.error(f"Error in CSV generation: {e}")
            logger.exception("CSV generation error details")
            raise
