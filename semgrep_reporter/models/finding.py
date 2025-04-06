"""
Model for Semgrep findings.
"""

from typing import Dict, List, Optional, Any
from pydantic import BaseModel, field_validator

from .external import ExternalTicket, ReviewComment
from .location import Location
from .policy import SourcingPolicy
from .rule import Rule
from .assistant import Assistant


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