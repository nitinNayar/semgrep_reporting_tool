"""
Semgrep API client for fetching security findings.
"""

import json
import logging
import time
from typing import Dict, List, Optional, Any

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
        self.config = config
        
        # Configure session with retries and timeouts
        self.session = requests.Session()
        
        # Configure retries for connection errors
        retry_strategy = Retry(
            total=3,  # Maximum number of retries
            backoff_factor=1,  # Time factor between retries
            status_forcelist=[429, 500, 502, 503, 504],  # Retry on these HTTP status codes
            allowed_methods=["GET"]  # Only retry on GET requests
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set headers
        self.session.headers.update({
            "Authorization": f"Bearer {config.api_token}",
            "Accept": "application/json",
            "User-Agent": "semgrep-reporter/0.1.0"
        })

    def get_findings(
        self,
        repositories: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        severity_levels: Optional[List[str]] = None,
        finding_types: Optional[List[str]] = None,
        progress: Optional[Progress] = None,
        progress_task: Optional[Any] = None
    ) -> List[Finding]:
        """
        Fetch findings from Semgrep API with optional filtering.

        Args:
            repositories: Optional list of repository names to filter by
            tags: Optional list of repository tags to filter by
            severity_levels: Optional list of severity levels to filter by
            finding_types: Optional list of finding types to filter by ('sast', 'sca')
            progress: Optional Progress instance for progress tracking
            progress_task: Optional task ID for the progress bar

        Returns:
            List of Finding objects
        """
        # Base parameters for filtering
        params: Dict[str, Any] = {}
        if repositories:
            params["repos"] = ",".join(repositories)
        if tags:
            params["tags"] = ",".join(tags)
        if severity_levels:
            params["severity"] = ",".join(severity_levels)
        if finding_types:
            params["issue_type"] = ",".join(finding_types)
        else:
            params["issue_type"] = "sast"  # Default to SAST if not specified
            
        # Build the API URL - make sure deployment_slug is correctly formatted
        api_url = f"{self.config.api_url}/findings"
        if self.config.deployment_slug:
            api_url = f"{self.config.api_url}/deployments/{self.config.deployment_slug}/findings"
            
        # Log initial API request details
        console = Console()
        console.print("\n[bold blue]API Request Details:[/bold blue]")
        console.print(f"[yellow]Endpoint:[/yellow] {api_url}")
        console.print("[yellow]Base Parameters:[/yellow]")
        for key, value in params.items():
            console.print(f"  • {key}: {value}")

        # Initialize findings list and pagination variables
        all_findings: List[Finding] = []
        current_page = 0
        page_size = 100  # Default page size per Semgrep API docs
        total_findings = 0
        has_more = True

        while has_more:
            # Add pagination parameters
            pagination_params = params.copy()
            pagination_params["page"] = current_page
            pagination_params["page_size"] = page_size
            
            # Log pagination details
            logger.debug(f"Fetching page {current_page} with page_size {page_size}")
            logger.debug(f"Full parameters: {pagination_params}")
            
            try:
                # Make API request with parameters
                response = self.session.get(
                    api_url,
                    params=pagination_params,
                    timeout=30,
                )
                response.raise_for_status()
                
                # Parse response
                data = response.json()
                
                # Get findings from this page
                page_findings = data.get("findings", [])
                finding_count = len(page_findings)
                
                # Update progress
                if current_page == 0:
                    # Get total count if available
                    if "total" in data:
                        total_findings = data["total"]
                        if progress and progress_task:
                            progress.update(progress_task, total=total_findings)
                        console.print(f"\n[blue]Total findings available: {total_findings}[/blue]")
                
                # Create Finding objects
                for finding_data in page_findings:
                    try:
                        finding = Finding(**finding_data)
                        all_findings.append(finding)
                    except ValidationError as e:
                        logger.warning(f"Failed to parse finding: {e}")
                        continue
                
                # Update progress
                if progress and progress_task:
                    progress.update(progress_task, completed=len(all_findings))
                
                # Log progress
                console.print(f"[green]Retrieved {finding_count} findings from page {current_page}[/green]")
                
                # Check if we should continue pagination
                # We have a full page of results, so there might be more
                has_more = finding_count >= page_size
                
                # If we have a total count, use it to determine if we should continue
                if "total" in data:
                    has_more = len(all_findings) < data["total"]
                
                # Increment page counter if we need to continue
                if has_more:
                    current_page += 1
                    # Add a small delay between requests to avoid rate limiting
                    time.sleep(0.5)
                
            except requests.exceptions.RequestException as e:
                logger.error(f"API request failed on page {current_page}: {e}")
                if hasattr(e.response, 'text'):
                    logger.error(f"Response text: {e.response.text}")
                raise
        
        # Final summary
        console.print(f"\n[bold green]Successfully retrieved {len(all_findings)} total findings across {current_page + 1} pages[/bold green]")
        
        return all_findings

    def get_repositories(self) -> List[str]:
        """Get list of available repositories."""
        # Build the API URL
        api_url = f"{self.config.api_url}/repos"
        if self.config.deployment_slug:
            api_url = f"{self.config.api_url}/deployments/{self.config.deployment_slug}/repos"
        
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
                    current_url = f"{self.config.api_url}/repos"
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
        api_url = f"{self.config.api_url}/tags"
        if self.config.deployment_slug:
            api_url = f"{self.config.api_url}/deployments/{self.config.deployment_slug}/tags"
        
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