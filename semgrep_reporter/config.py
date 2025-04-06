"""
Configuration management for Semgrep Reporter.
"""

from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class APIConfig(BaseModel):
    """Semgrep API configuration."""
    api_token: str = Field(..., description="Semgrep API token")
    deployment_slug: str = Field(..., description="Semgrep deployment slug")
    api_url: str = Field(
        "https://semgrep.dev/api/v1",
        description="Semgrep API base URL"
    )


class ReportConfig(BaseModel):
    """Report generation configuration."""
    output_formats: List[str] = Field(
        default=["pdf", "csv"],
        description="List of output formats to generate"
    )
    include_charts: bool = Field(
        default=True,
        description="Whether to include charts in the reports"
    )
    company_logo: Optional[Path] = Field(
        None,
        description="Path to company logo for reports"
    )
    report_title: str = Field(
        "Semgrep Security Findings Report",
        description="Title for the generated reports"
    )


class FilterConfig(BaseModel):
    """Filtering configuration for findings."""
    repositories: Optional[List[str]] = Field(
        None,
        description="List of repositories to include"
    )
    tags: Optional[List[str]] = Field(
        None,
        description="List of repository tags to filter by"
    )
    severity_levels: Optional[List[str]] = Field(
        None,
        description="List of severity levels to include"
    )


class Settings(BaseSettings):
    """Main configuration settings."""
    api: APIConfig
    report: ReportConfig = ReportConfig()
    filters: FilterConfig = FilterConfig()
    output_dir: Path = Field(
        Path("./reports"),
        description="Directory for generated reports"
    )

    class Config:
        env_prefix = "SEMGREP_REPORTER_"
        env_nested_delimiter = "__" 