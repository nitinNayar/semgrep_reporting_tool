"""
Semgrep API client for fetching security findings.
"""

import json
import logging
import time
from typing import Dict, List, Optional, Any, Callable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from rich.console import Console
from rich.progress import Progress

from .config import APIConfig
from .models import Finding

logger = logging.getLogger("semgrep_reporter")


class SemgrepClient:
    """Client for interacting with the Semgrep API."""

    def __init__(self, config: APIConfig):
        """Initialize the Semgrep API client."""
        self.config = config
        self.base_url = config.api_url
        
        # Set up session with retries
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        
        self.session = requests.Session()
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set headers
        self.session.headers.update({
            "Authorization": f"Bearer {config.token}",
            "Accept": "application/json",
            "User-Agent": "semgrep-reporter/0.1.0"
        })

    def get_findings(
        self,
        issue_type: str = "sast",
        repositories: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        severity_levels: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        console: Optional[Console] = None
    ) -> List[Finding]:
        """
        Get list of findings from Semgrep.
        
        Args:
            issue_type: Type of findings to fetch ("sast" or "sca")
            repositories: Optional list of repository names to filter by
            tags: Optional list of repository tags to filter by
            severity_levels: Optional list of severity levels to filter by
            progress_callback: Optional callback function to report progress
            console: Optional console for output logging
            
        Returns:
            List of Finding objects
        """
        # Use provided console or create a new one
        output_console = console or Console()
        
        # Build the API URL
        api_url = f"{self.base_url}/findings"
        if self.config.deployment_slug:
            api_url = f"{self.base_url}/deployments/{self.config.deployment_slug}/findings"
        
        # Log initial API request details
        output_console.print("\n[bold blue]API Request Details:[/bold blue]")
        output_console.print(f"[yellow]Endpoint:[/yellow] {api_url}")
        
        # Build query parameters
        params = {
            "issue_type": issue_type
        }
        
        if repositories:
            params["repos"] = repositories
        if tags:
            params["tags"] = tags
        if severity_levels:
            params["severity"] = severity_levels
            
        # Log base parameters
        output_console.print("[yellow]Base Parameters:[/yellow]")
        for key, value in params.items():
            output_console.print(f"  • {key}: {value}")
            
        # Initialize pagination parameters
        page = 0
        page_size = 100
        total_findings = []
        total_count = None
        
        while True:
            # Add pagination parameters
            params.update({
                "page": page,
                "page_size": page_size
            })
            
            # Make the API request
            response = self.session.get(api_url, params=params)
            response.raise_for_status()
            data = response.json()
            
            # Get the findings from this page
            findings = data.get("findings", [])
            total_findings.extend(findings)
            
            # Get total count if not already set
            if total_count is None:
                total_count = data.get("total_count", len(findings))
                output_console.print(f"\n[blue]Total findings available: {total_count}[/blue]")
            
            # Log progress
            output_console.print(f"[green]Retrieved {len(findings)} findings from page {page}[/green]")
            
            # Update progress if callback provided
            if progress_callback:
                progress_callback(len(total_findings), total_count)
            
            # Check if we need to fetch more pages
            if len(findings) < page_size:
                break
            
            # Add a small delay between requests to avoid rate limiting
            time.sleep(0.5)
            page += 1
        
        output_console.print(f"\n[bold green]Successfully retrieved {len(total_findings)} total findings across {page + 1} pages[/bold green]")
        
        # Convert raw findings to Finding objects
        return [Finding(**finding) for finding in total_findings]

    def get_repositories(self) -> List[str]:
        """Get list of available repositories."""
        # Build the API URL
        api_url = f"{self.base_url}/repos"
        if self.config.deployment_slug:
            api_url = f"{self.base_url}/deployments/{self.config.deployment_slug}/repos"
        
        logger.debug(f"Fetching repositories from: {api_url}")
        
        # Retry settings
        max_retries = 3
        retry_delay = 2  # seconds
        current_url = api_url
        success = False
        
        for attempt in range(max_retries):
            try:
                logger.debug(f"Attempting API call (attempt {attempt+1}/{max_retries})...")
                logger.debug(f"API URL: {current_url}")
                
                response = self.session.get(
                    current_url,
                    timeout=(5, 15)  # 5s connect, 15s read
                )
                response.raise_for_status()
                success = True
                break
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching repositories: {e}")
                logger.error(f"Request URL: {e.response.url if hasattr(e, 'response') and e.response else 'Unknown'}")
                logger.error(f"Response status: {e.response.status_code if hasattr(e, 'response') and e.response else 'Unknown'}")
                
                # If we get a 400 error and deployment_slug is in the URL, try falling back to base URL
                if (hasattr(e, 'response') and e.response and e.response.status_code == 400 and 
                    self.config.deployment_slug and current_url == api_url):
                    logger.warning("Got 400 error with deployment slug URL. Trying fallback to base API URL")
                    current_url = f"{self.base_url}/repos"
                    # Reset retry count for the new URL
                    attempt = -1  # Will become 0 after increment
                    retry_delay = 2
                    continue
                
                if attempt < max_retries - 1:
                    logger.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2
                else:
                    logger.error("Max retries exceeded.")
        
        if not success:
            logger.error("Failed to retrieve repositories after all retries")
            return []
            
        try:
            return response.json()
        except Exception as e:
            logger.error(f"Error parsing repository response: {e}")
            return []

    def get_repository_tags(self) -> List[str]:
        """Get list of available repository tags."""
        # Build the API URL
        api_url = f"{self.base_url}/tags"
        if self.config.deployment_slug:
            api_url = f"{self.base_url}/deployments/{self.config.deployment_slug}/tags"
        
        logger.debug(f"Fetching repository tags from: {api_url}")
        
        # Retry settings
        max_retries = 3
        retry_delay = 2  # seconds
        current_url = api_url
        success = False
        
        for attempt in range(max_retries):
            try:
                logger.debug(f"Attempting API call (attempt {attempt+1}/{max_retries})...")
                logger.debug(f"API URL: {current_url}")
                
                response = self.session.get(
                    current_url,
                    timeout=(5, 15)  # 5s connect, 15s read
                )
                response.raise_for_status()
                success = True
                break
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching repository tags: {e}")
                logger.error(f"Request URL: {e.response.url if hasattr(e, 'response') and e.response else 'Unknown'}")
                logger.error(f"Response status: {e.response.status_code if hasattr(e, 'response') and e.response else 'Unknown'}")
                
                # If we get a 400 error and deployment_slug is in the URL, try falling back to base URL
                if (hasattr(e, 'response') and e.response and e.response.status_code == 400 and 
                    self.config.deployment_slug and current_url == api_url):
                    logger.warning("Got 400 error with deployment slug URL. Trying fallback to base API URL")
                    current_url = f"{self.base_url}/tags"
                    current_url = f"{self.config.api_url}/tags"
                    # Reset retry count for the new URL
                    attempt = -1  # Will become 0 after increment
                    retry_delay = 2
                    continue
                
                if attempt < max_retries - 1:
                    logger.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2
                else:
                    logger.error("Max retries exceeded.")
        
        if not success:
            logger.error("Failed to retrieve repository tags after all retries")
            return []
            
        try:
            return response.json()
        except Exception as e:
            logger.error(f"Error parsing repository tags response: {e}")
            return [] 