"""
Tests for the Semgrep API client.
"""

from unittest.mock import Mock, patch

import pytest
import requests

from semgrep_reporter.api import Finding, SemgrepClient
from semgrep_reporter.config import APIConfig


@pytest.fixture
def api_config():
    """Fixture for API configuration."""
    return APIConfig(api_token="test-token")


@pytest.fixture
def mock_response():
    """Fixture for mocked API response."""
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


def test_client_initialization(api_config):
    """Test client initialization with API token."""
    client = SemgrepClient(api_config)
    assert client.config.api_token == "test-token"
    assert "Bearer test-token" in client.session.headers["Authorization"]


@patch("requests.Session.get")
def test_get_findings(mock_get, api_config, mock_response):
    """Test getting findings from the API."""
    mock_get.return_value.json.return_value = mock_response
    mock_get.return_value.raise_for_status = Mock()

    client = SemgrepClient(api_config)
    findings = client.get_findings()

    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, Finding)
    assert finding.check_id == "test-check"
    assert finding.severity == "ERROR"


@patch("requests.Session.get")
def test_get_findings_with_filters(mock_get, api_config):
    """Test getting findings with filters."""
    mock_get.return_value.json.return_value = []
    mock_get.return_value.raise_for_status = Mock()

    client = SemgrepClient(api_config)
    client.get_findings(
        repositories=["repo1", "repo2"],
        tags=["prod"],
        severity_levels=["ERROR"],
    )

    # Verify the correct parameters were passed
    call_args = mock_get.call_args[1]["params"]
    assert call_args["repos"] == "repo1,repo2"
    assert call_args["tags"] == "prod"
    assert call_args["severity"] == "ERROR"


@patch("requests.Session.get")
def test_api_error_handling(mock_get, api_config):
    """Test API error handling."""
    mock_get.side_effect = requests.exceptions.RequestException("API Error")

    client = SemgrepClient(api_config)
    with pytest.raises(requests.exceptions.RequestException):
        client.get_findings() 