"""
Tests for the report generation functionality.
"""

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from semgrep_reporter.api import Finding
from semgrep_reporter.config import ReportConfig
from semgrep_reporter.reports import ReportGenerator


@pytest.fixture
def sample_findings():
    """Fixture providing sample findings for testing."""
    return [
        Finding(
            check_id="test-check-1",
            path="src/file1.py",
            line=10,
            message="Security issue 1",
            severity="ERROR",
            repository="repo1",
            commit="abc123",
        ),
        Finding(
            check_id="test-check-2",
            path="src/file2.py",
            line=20,
            message="Security issue 2",
            severity="WARNING",
            repository="repo1",
            commit="def456",
        ),
    ]


@pytest.fixture
def report_config(tmp_path):
    """Fixture providing report configuration."""
    return ReportConfig(
        output_formats=["pdf", "csv", "xlsx"],
        include_charts=True,
        report_title="Test Report",
    )


def test_report_generator_initialization(tmp_path, report_config):
    """Test ReportGenerator initialization."""
    generator = ReportGenerator(report_config, tmp_path)
    assert generator.config == report_config
    assert generator.output_dir == tmp_path
    assert generator.output_dir.exists()


@patch("semgrep_reporter.reports.FPDF")
def test_pdf_report_generation(mock_fpdf, tmp_path, report_config, sample_findings):
    """Test PDF report generation."""
    mock_pdf = Mock()
    mock_fpdf.return_value = mock_pdf

    generator = ReportGenerator(report_config, tmp_path)
    generator._generate_pdf_report(sample_findings)

    # Verify PDF methods were called
    mock_pdf.add_page.assert_called()
    mock_pdf.set_font.assert_called()
    mock_pdf.cell.assert_called()
    mock_pdf.output.assert_called_with(str(tmp_path / "semgrep_report.pdf"))


def test_csv_report_generation(tmp_path, report_config, sample_findings):
    """Test CSV report generation."""
    generator = ReportGenerator(report_config, tmp_path)
    generator._generate_csv_report(sample_findings)

    csv_file = tmp_path / "semgrep_findings.csv"
    assert csv_file.exists()
    
    # Verify CSV content
    content = csv_file.read_text()
    assert "check_id,severity,path,line,message,repository,commit" in content
    assert "test-check-1,ERROR,src/file1.py,10" in content
    assert "test-check-2,WARNING,src/file2.py,20" in content


def test_excel_report_generation(tmp_path, report_config, sample_findings):
    """Test Excel report generation."""
    generator = ReportGenerator(report_config, tmp_path)
    generator._generate_excel_report(sample_findings)

    excel_file = tmp_path / "semgrep_findings.xlsx"
    assert excel_file.exists()


def test_report_generation_with_no_findings(tmp_path, report_config):
    """Test report generation with no findings."""
    generator = ReportGenerator(report_config, tmp_path)
    generator.generate_reports([])

    # Verify files are created even with no findings
    assert (tmp_path / "semgrep_report.pdf").exists()
    assert (tmp_path / "semgrep_findings.csv").exists()
    assert (tmp_path / "semgrep_findings.xlsx").exists()


@patch("plotly.express.pie")
def test_chart_generation(mock_pie, tmp_path, report_config, sample_findings):
    """Test chart generation for PDF reports."""
    mock_fig = Mock()
    mock_pie.return_value = mock_fig

    generator = ReportGenerator(report_config, tmp_path)
    with patch("semgrep_reporter.reports.FPDF") as mock_fpdf:
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        generator._generate_pdf_report(sample_findings)

    # Verify chart generation
    mock_pie.assert_called_once()
    mock_fig.write_image.assert_called_once() 