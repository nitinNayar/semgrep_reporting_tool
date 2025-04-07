"""
Excel report generation functionality.
"""

import logging
from pathlib import Path
from typing import List, Dict

import pandas as pd
from openpyxl.utils import get_column_letter

from ..api import Finding
from ..config import ReportConfig
from .utils import FindingFormatter, ReportFields

logger = logging.getLogger("semgrep_reporter")

class ExcelReportGenerator:
    """Generates Excel reports from Semgrep findings."""
    
    def __init__(self, config: ReportConfig, output_dir: Path):
        """
        Initialize Excel report generator.
        
        Args:
            config: Report configuration settings
            output_dir: Directory to store generated reports
        """
        self.config = config
        self.output_dir = output_dir
        
    def _create_severity_summary(self, findings: List[Finding]) -> pd.DataFrame:
        """Create severity summary by repository DataFrame."""
        if not findings:
            return pd.DataFrame(columns=['Repository', 'Critical', 'High', 'Medium', 'Low'])
            
        summary_data = []
        df = pd.DataFrame([
            FindingFormatter.to_dict(f, deployment_slug=self.config.deployment_slug)
            for f in findings
        ])
        
        for repo in df['repository'].unique():
            repo_findings = df[df['repository'] == repo]
            severity_counts = {
                'Repository': repo,
                'Critical': len(repo_findings[repo_findings['severity'].str.upper() == 'CRITICAL']),
                'High': len(repo_findings[repo_findings['severity'].str.upper() == 'HIGH']),
                'Medium': len(repo_findings[repo_findings['severity'].str.upper() == 'MEDIUM']),
                'Low': len(repo_findings[repo_findings['severity'].str.upper() == 'LOW'])
            }
            summary_data.append(severity_counts)
            
        return pd.DataFrame(summary_data)
        
    def _format_summary_sheet(self, writer: pd.ExcelWriter, summary_df: pd.DataFrame) -> None:
        """Format the summary sheet with appropriate column widths."""
        summary_sheet = writer.sheets["Open Findings by Repository"]
        
        # Apply formatting to the summary sheet
        for column in range(len(summary_df.columns)):
            max_length = 0
            column_letter = get_column_letter(column + 1)
            
            # Find the maximum length in the column
            for row in range(len(summary_df) + 1):  # +1 for header
                cell = summary_sheet[f"{column_letter}{row + 1}"]
                max_length = max(max_length, len(str(cell.value)))
            
            # Set the column width
            adjusted_width = (max_length + 2)
            summary_sheet.column_dimensions[column_letter].width = adjusted_width
            
    def generate(self, findings: List[Finding]) -> None:
        """
        Generate Excel report with findings and charts.
        
        Args:
            findings: List of findings to include in the report
        """
        logger.debug("Generating Excel report")
        output_path = self.output_dir / "semgrep_findings.xlsx"
        
        try:
            # Convert findings to DataFrame
            data = [
                FindingFormatter.to_dict(f, deployment_slug=self.config.deployment_slug)
                for f in findings
            ]
            df = pd.DataFrame(data)
            
            # Create severity summary
            summary_df = self._create_severity_summary(findings)
            
            with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
                # Write the summary sheet first
                summary_df.to_excel(writer, sheet_name="Open Findings by Repository", index=False)
                self._format_summary_sheet(writer, summary_df)
                
                # Write the detailed findings
                if df.empty:
                    pd.DataFrame(columns=ReportFields.get_all_fields()).to_excel(
                        writer,
                        sheet_name="Findings",
                        index=False
                    )
                else:
                    # Only include fields that exist in the DataFrame
                    columns_to_include = [
                        col for col in ReportFields.get_all_fields()
                        if col in df.columns
                    ]
                    df[columns_to_include].to_excel(
                        writer,
                        sheet_name="Findings",
                        index=False
                    )
                    
                    # Add charts if enabled
                    if self.config.include_charts:
                        pivot = pd.pivot_table(
                            df,
                            values="severity",
                            index="severity",
                            aggfunc="count"
                        )
                        pivot.to_excel(writer, sheet_name="Charts")
            
            logger.info(f"Excel report saved to {output_path}")
            
        except Exception as e:
            logger.error(f"Error in Excel generation: {e}")
            logger.exception("Excel generation error details")
            raise
