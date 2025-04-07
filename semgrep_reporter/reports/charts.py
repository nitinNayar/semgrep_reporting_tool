"""
Chart generation functionality for reports.
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

import pandas as pd
import plotly.express as px

from ..api import Finding
from ..config import ReportConfig
from .utils import FindingFormatter

logger = logging.getLogger("semgrep_reporter")

class ChartGenerator:
    """Generates charts and visualizations for reports."""
    
    def __init__(self, config: ReportConfig, output_dir: Path):
        """
        Initialize chart generator.
        
        Args:
            config: Report configuration settings
            output_dir: Directory to store generated charts
        """
        self.config = config
        self.output_dir = output_dir
        
    def create_severity_chart(self, findings: List[Finding]) -> Optional[Path]:
        """
        Create a pie chart showing the distribution of findings by severity.
        
        Args:
            findings: List of findings to visualize
            
        Returns:
            Path to the generated chart image, or None if chart couldn't be generated
        """
        try:
            # Convert findings to DataFrame
            data = [
                FindingFormatter.to_dict(f, deployment_slug=self.config.deployment_slug)
                for f in findings
            ]
            df = pd.DataFrame(data)
            
            if df.empty:
                logger.debug("No data available for severity chart")
                return None
                
            # Count severity levels
            severity_counts = df["severity"].value_counts().reset_index()
            severity_counts.columns = ["severity", "count"]
            
            if len(severity_counts) == 0:
                logger.debug("No severity data for chart")
                return None
            
            # Create pie chart
            fig = px.pie(
                severity_counts,
                values="count",
                names="severity",
                title="Findings by Severity",
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            
            # Save chart
            chart_path = self.output_dir / "severity_chart.png"
            fig.write_image(str(chart_path))
            logger.debug(f"Severity chart saved to {chart_path}")
            
            return chart_path
            
        except Exception as e:
            logger.error(f"Error generating severity chart: {e}")
            logger.exception("Chart generation error details")
            return None
            
    def create_repository_chart(self, findings: List[Finding]) -> Optional[Path]:
        """
        Create a bar chart showing findings by repository.
        
        Args:
            findings: List of findings to visualize
            
        Returns:
            Path to the generated chart image, or None if chart couldn't be generated
        """
        try:
            # Convert findings to DataFrame
            data = [
                FindingFormatter.to_dict(f, deployment_slug=self.config.deployment_slug)
                for f in findings
            ]
            df = pd.DataFrame(data)
            
            if df.empty:
                logger.debug("No data available for repository chart")
                return None
                
            # Count findings by repository
            repo_counts = df["repository"].value_counts().reset_index()
            repo_counts.columns = ["repository", "count"]
            
            if len(repo_counts) == 0:
                logger.debug("No repository data for chart")
                return None
            
            # Create bar chart
            fig = px.bar(
                repo_counts,
                x="repository",
                y="count",
                title="Findings by Repository",
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            
            # Rotate x-axis labels for better readability
            fig.update_layout(xaxis_tickangle=-45)
            
            # Save chart
            chart_path = self.output_dir / "repository_chart.png"
            fig.write_image(str(chart_path))
            logger.debug(f"Repository chart saved to {chart_path}")
            
            return chart_path
            
        except Exception as e:
            logger.error(f"Error generating repository chart: {e}")
            logger.exception("Chart generation error details")
            return None
            
    def cleanup_charts(self):
        """Remove temporary chart files."""
        try:
            for chart_file in self.output_dir.glob("*_chart.png"):
                chart_file.unlink(missing_ok=True)
                logger.debug(f"Removed temporary chart file: {chart_file}")
        except Exception as e:
            logger.error(f"Error cleaning up chart files: {e}")
