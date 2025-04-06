"""
Semgrep API client for fetching security findings.
"""

import json
import logging
import time
from typing import Dict, List, Optional, Any, Union

import requests
from pydantic import BaseModel, Field, ValidationError, field_validator
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from rich.console import Console
from rich.progress import Progress

from .config import APIConfig

logger = logging.getLogger("semgrep_reporter")


class ExternalTicket(BaseModel):
    """Model for external ticket information."""
    external_slug: Optional[str] = None
    url: Optional[str] = None
    
    model_config = {
        "extra": "ignore",
        "arbitrary_types_allowed": True
    }


class ReviewComment(BaseModel):
    """Model for review comments."""
    external_discussion_id: Optional[str] = None
    external_note_id: Optional[int] = None
    
    model_config = {
        "extra": "ignore",
        "arbitrary_types_allowed": True
    }


class Repository(BaseModel):
    """Model for repository information."""
    name: Optional[str] = None
    url: Optional[str] = None
    
    model_config = {
        "extra": "ignore",
        "arbitrary_types_allowed": True
    }


class Location(BaseModel):
    """Model for finding location."""
    file_path: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    
    model_config = {
        "extra": "ignore",
        "arbitrary_types_allowed": True
    }


class SourcingPolicy(BaseModel):
    """Model for sourcing policy."""
    id: Optional[int] = None
    name: Optional[str] = None
    slug: Optional[str] = None
    
    model_config = {
        "extra": "ignore",
        "arbitrary_types_allowed": True
    }


class Rule(BaseModel):
    """Model for rule information."""
    name: Optional[str] = None
    message: Optional[str] = None
    confidence: Optional[str] = None
    category: Optional[str] = None
    subcategories: Optional[List[str]] = None
    vulnerability_classes: Optional[List[str]] = None
    cwe_names: Optional[List[str]] = None
    owasp_names: Optional[List[str]] = None
    
    model_config = {
        "extra": "ignore",
        "arbitrary_types_allowed": True
    }


class Autofix(BaseModel):
    """Model for autofix information."""
    fix_code: Optional[str] = None
    explanation: Optional[str] = None
    
    model_config = {
        "extra": "ignore",
        "arbitrary_types_allowed": True
    }


class Guidance(BaseModel):
    """Model for guidance information."""
    summary: Optional[str] = None
    instructions: Optional[str] = None
    
    model_config = {
        "extra": "ignore",
        "arbitrary_types_allowed": True
    }


class Autotriage(BaseModel):
    """Model for autotriage information."""
    verdict: Optional[str] = None
    reason: Optional[str] = None
    
    model_config = {
        "extra": "ignore",
        "arbitrary_types_allowed": True
    }


class Component(BaseModel):
    """Model for component information."""
    tag: Optional[str] = None
    risk: Optional[str] = None
    
    model_config = {
        "extra": "ignore",
        "arbitrary_types_allowed": True
    }


class Assistant(BaseModel):
    """Model for assistant information."""
    autofix: Optional[Autofix] = None
    guidance: Optional[Guidance] = None
    autotriage: Optional[Autotriage] = None
    component: Optional[Component] = None
    
    model_config = {
        "extra": "ignore",
        "arbitrary_types_allowed": True
    }


class Finding(BaseModel):
    """
    Model representing a Semgrep finding based on the API docs.
    
    According to Semgrep API documentation:
    https://semgrep.dev/api/v1/docs/#tag/Finding
    """
    # Finding identification
    id: Optional[Any] = None
    ref: Optional[str] = None
    first_seen_scan_id: Optional[int] = None
    syntactic_id: Optional[str] = None
    match_based_id: Optional[str] = None
    
    # Finding type
    finding_type: Optional[str] = None  # 'sast' or 'sca'
    
    # SCA-specific fields
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    fixed_version: Optional[str] = None
    ecosystem: Optional[str] = None
    cve_ids: Optional[List[str]] = None
    reachable: Optional[bool] = None
    reachability_details: Optional[Dict] = None
    references: Optional[List[str]] = None
    
    # External integrations
    external_ticket: Optional[ExternalTicket] = None
    review_comments: Optional[List[ReviewComment]] = None
    
    # Repository information
    repository: Optional[Any] = None
    line_of_code_url: Optional[str] = None
    
    # Triage and state information
    triage_state: Optional[str] = None
    state: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[str] = None
    categories: Optional[List[str]] = None
    
    # Timestamps
    created_at: Optional[str] = None
    relevant_since: Optional[str] = None
    triaged_at: Optional[str] = None
    state_updated_at: Optional[str] = None
    
    # Rule information
    rule_name: Optional[str] = None
    rule_message: Optional[str] = None
    rule: Optional[Rule] = None
    
    # Location information
    location: Optional[Location] = None
    
    # Policy information
    sourcing_policy: Optional[SourcingPolicy] = None
    
    # Triage metadata
    triage_comment: Optional[str] = None
    triage_reason: Optional[str] = None
    
    # Assistant information
    assistant: Optional[Assistant] = None
    
    # Backward compatibility fields
    check_id: Optional[str] = None
    path: Optional[str] = None
    start: Optional[Dict] = None
    end: Optional[Dict] = None
    line: Optional[int] = None
    message: Optional[str] = None
    commit: Optional[str] = None
    commit_date: Optional[str] = None
    scan_id: Optional[str] = None
    scan_date: Optional[str] = None
    
    # Store raw API response
    raw_response: Optional[Dict] = None
    
    # Update Config class to use Pydantic v2 syntax
    model_config = {
        "extra": "ignore",
        "arbitrary_types_allowed": True,
        "populate_by_name": True
    }
    
    def __init__(self, **data):
        """Initialize with special handling for nested fields."""
        # Store the raw API response
        raw_response = data.copy()
        
        # Determine finding type
        if data.get('package_name') or data.get('ecosystem'):
            data['finding_type'] = 'sca'
        else:
            data['finding_type'] = 'sast'
        
        # Extract SCA-specific fields if available
        if data.get('package'):
            package_data = data['package']
            if isinstance(package_data, dict):
                data['package_name'] = package_data.get('name')
                data['package_version'] = package_data.get('version')
                data['ecosystem'] = package_data.get('ecosystem')
                
        if data.get('vulnerability'):
            vuln_data = data['vulnerability']
            if isinstance(vuln_data, dict):
                data['fixed_version'] = vuln_data.get('fixed_version')
                data['cve_ids'] = vuln_data.get('cve_ids', [])
                data['references'] = vuln_data.get('references', [])
                
        if data.get('reachability'):
            reach_data = data['reachability']
            if isinstance(reach_data, dict):
                data['reachable'] = reach_data.get('reachable')
                data['reachability_details'] = reach_data.get('details')
        
        # Extract rule info from rule object if available
        if 'rule' in data and isinstance(data['rule'], dict):
            if 'name' in data['rule'] and not data.get('rule_name'):
                data['rule_name'] = data['rule']['name']
            if 'message' in data['rule'] and not data.get('rule_message'):
                data['rule_message'] = data['rule']['message']
        
        # For backward compatibility, set check_id from rule_name if available
        if 'rule_name' in data and not data.get('check_id'):
            data['check_id'] = data['rule_name']
        
        # Extract location information if available
        if 'location' in data and isinstance(data['location'], dict):
            location = data['location']
            if 'file_path' in location and not data.get('path'):
                data['path'] = location['file_path']
            if 'line' in location and not data.get('line'):
                data['line'] = location['line']
            
            # Map location to start/end for backward compatibility
            if not data.get('start') and 'line' in location and 'column' in location:
                data['start'] = {
                    'line': location['line'],
                    'col': location['column']
                }
            if not data.get('end') and 'end_line' in location and 'end_column' in location:
                data['end'] = {
                    'line': location['end_line'],
                    'col': location['end_column']
                }
        
        # Extract message from rule_message if available
        if 'rule_message' in data and not data.get('message'):
            data['message'] = data['rule_message']
        
        # Convert id to string if it's an integer
        if 'id' in data and isinstance(data['id'], int):
            data['id'] = str(data['id'])
            
        # Ensure created_at is mapped to scan_date for backward compatibility
        if 'created_at' in data and not data.get('scan_date'):
            data['scan_date'] = data['created_at']
            
        # Set raw_response after all transformations
        data['raw_response'] = raw_response
            
        super().__init__(**data)
    
    @field_validator('id')
    def validate_id(cls, v):
        """Convert id to string if it's not already."""
        if v is None:
            return v
        return str(v)
    
    @field_validator('repository')
    def validate_repository(cls, v):
        """Extract repository name if it's a dictionary."""
        if v is None:
            return ""
        if isinstance(v, dict):
            return v.get('name', str(v))
        return v
    
    def get_path(self) -> str:
        """Get file path from location or path field."""
        if self.location and self.location.file_path:
            return self.location.file_path
        return self.path or ""
    
    def get_line(self) -> int:
        """Get line number from location or line field."""
        if self.location and self.location.line:
            return self.location.line
        if self.start and isinstance(self.start, dict) and 'line' in self.start:
            return self.start['line']
        return self.line or 0
    
    def get_rule_id(self) -> str:
        """Get rule ID from rule_name or check_id."""
        return self.rule_name or self.check_id or "unknown"
    
    def get_message(self) -> str:
        """Get message from rule_message or message."""
        return self.rule_message or self.message or ""
    
    def get_severity(self) -> str:
        """Get severity."""
        return self.severity or "unknown"
    
    def get_confidence(self) -> str:
        """Get confidence."""
        return self.confidence or "unknown"
    
    def get_repository_name(self) -> str:
        """Get repository name."""
        if isinstance(self.repository, dict):
            return self.repository.get('name', "")
        return self.repository or ""


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