"""
Tests for the command-line interface.
"""

from pathlib import Path
from unittest.mock import Mock, patch

import click
import pytest
from click.testing import CliRunner

from semgrep_reporter.cli import cli, generate


@pytest.fixture
def cli_runner():
    """Fixture providing a Click CLI runner."""
    return CliRunner()


@pytest.fixture
def mock_findings():
    """Fixture providing mock findings data."""
    return [
        {
            "check_id": "test-check",
            "path": "test/file.py",
            "line": 42,
            "message": "Test finding",
            "severity": "ERROR",
            "repository": "test/repo",
            "commit": "abc123",
        }
    ]


def test_cli_version(cli_runner):
    """Test CLI version command."""
    result = cli_runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "version" in result.output.lower()


def test_generate_command_requires_api_token(cli_runner):
    """Test that generate command requires API token."""
    result = cli_runner.invoke(cli, ["generate"])
    assert result.exit_code != 0
    assert "api-token" in result.output.lower()


@patch("semgrep_reporter.cli.SemgrepClient")
@patch("semgrep_reporter.cli.ReportGenerator")
def test_generate_command_basic(
    mock_generator_class, mock_client_class, cli_runner, mock_findings, tmp_path
):
    """Test basic generate command functionality."""
    # Setup mocks
    mock_client = Mock()
    mock_client.get_findings.return_value = mock_findings
    mock_client_class.return_value = mock_client

    mock_generator = Mock()
    mock_generator_class.return_value = mock_generator

    # Run command
    with cli_runner.isolated_filesystem():
        result = cli_runner.invoke(
            cli,
            [
                "generate",
                "--api-token", "test-token",
                "--output-dir", str(tmp_path),
            ]
        )

    assert result.exit_code == 0
    mock_client.get_findings.assert_called_once()
    mock_generator.generate_reports.assert_called_once()


@patch("semgrep_reporter.cli.SemgrepClient")
@patch("semgrep_reporter.cli.ReportGenerator")
def test_generate_command_with_filters(
    mock_generator_class, mock_client_class, cli_runner, mock_findings, tmp_path
):
    """Test generate command with filtering options."""
    # Setup mocks
    mock_client = Mock()
    mock_client.get_findings.return_value = mock_findings
    mock_client_class.return_value = mock_client

    mock_generator = Mock()
    mock_generator_class.return_value = mock_generator

    # Run command with filters
    with cli_runner.isolated_filesystem():
        result = cli_runner.invoke(
            cli,
            [
                "generate",
                "--api-token", "test-token",
                "--output-dir", str(tmp_path),
                "--repository", "repo1",
                "--repository", "repo2",
                "--tag", "production",
                "--severity", "ERROR",
            ]
        )

    assert result.exit_code == 0
    mock_client.get_findings.assert_called_once_with(
        repositories=["repo1", "repo2"],
        tags=["production"],
        severity_levels=["ERROR"],
    )


@patch("semgrep_reporter.cli.SemgrepClient")
def test_generate_command_handles_api_error(
    mock_client_class, cli_runner, tmp_path
):
    """Test error handling in generate command."""
    # Setup mock to raise an exception
    mock_client = Mock()
    mock_client.get_findings.side_effect = Exception("API Error")
    mock_client_class.return_value = mock_client

    # Run command
    with cli_runner.isolated_filesystem():
        result = cli_runner.invoke(
            cli,
            [
                "generate",
                "--api-token", "test-token",
                "--output-dir", str(tmp_path),
            ]
        )

    assert result.exit_code != 0
    assert "error" in result.output.lower()


def test_generate_command_output_formats(cli_runner, tmp_path):
    """Test generate command with different output formats."""
    with patch("semgrep_reporter.cli.SemgrepClient") as mock_client_class:
        mock_client = Mock()
        mock_client.get_findings.return_value = []
        mock_client_class.return_value = mock_client

        result = cli_runner.invoke(
            cli,
            [
                "generate",
                "--api-token", "test-token",
                "--output-dir", str(tmp_path),
                "--format", "pdf",
                "--format", "csv",
                "--format", "xlsx",
            ]
        )

    assert result.exit_code == 0 