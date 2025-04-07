"""
Utility functions and classes for report generation.
"""

import logging
from typing import Dict, Any, Optional

from ..api import Finding

logger = logging.getLogger("semgrep_reporter")

class FindingFormatter:
    """Converts Finding objects to dictionary format for reports."""
    
    @staticmethod
    def to_dict(finding: Finding, deployment_slug: Optional[str] = None) -> Dict[str, Any]:
        """
        Convert a Finding object to a dictionary with consistent field access.
        
        Args:
            finding: Finding object to convert
            deployment_slug: Optional deployment slug for Semgrep UI URLs
        """
        finding_dict = {
            # Core fields
            "check_id": finding.check_id,
            "path": finding.get_path(),
            "line": finding.get_line(),
            "message": finding.get_message(),
            "severity": finding.get_severity(),
            "repository": finding.get_repository_name(),
            
            # Status and triage fields
            "state": getattr(finding, 'state', None),
            "status": getattr(finding, 'status', None),
            "triage_state": getattr(finding, 'triage_state', None),
            "triaged_at": getattr(finding, 'triaged_at', None),
            "triage_comment": getattr(finding, 'triage_comment', None),
            "triage_reason": getattr(finding, 'triage_reason', None),
            "state_updated_at": getattr(finding, 'state_updated_at', None),
            
            # Optional fields
            "commit": finding.commit,
            "scan_date": finding.scan_date,
            "line_of_code_url": finding.line_of_code_url,
            
            # Initialize Semgrep UI fields
            "finding_id": None,
            "semgrep_ui_url": None
        }

        # Add Semgrep UI link if raw_response is available
        if hasattr(finding, 'raw_response') and isinstance(finding.raw_response, dict):
            finding_id = finding.raw_response.get('id')
            finding_dict["finding_id"] = finding_id
            if finding_id and deployment_slug:
                finding_dict["semgrep_ui_url"] = f"https://semgrep.dev/orgs/{deployment_slug}/findings/{finding_id}"
            
        # Add SCA-specific fields
        finding_dict.update({
            "is_dependency": getattr(finding, 'is_dependency', False),
            "dependency_name": getattr(finding, 'dependency_name', None),
            "dependency_version": getattr(finding, 'dependency_version', None),
            "fixed_version": getattr(finding, 'fixed_version', None),
            "ecosystem": getattr(finding, 'ecosystem', None),
            "cve_ids": getattr(finding, 'cve_ids', []),
            "references": getattr(finding, 'references', []),
            "reachable": getattr(finding, 'reachable', None),
            "reachability_details": getattr(finding, 'reachability_details', None),
            
            # Rule fields
            "rule_category": "",
            "rule_subcategories": [],
            "vulnerability_classes": [],
            "cwe_names": [],
            "owasp_names": []
        })
        
        # Add rule information if available
        if finding.rule:
            finding_dict.update({
                "rule_category": finding.rule.category,
                "rule_subcategories": finding.rule.subcategories,
                "vulnerability_classes": finding.rule.vulnerability_classes,
                "cwe_names": finding.rule.cwe_names,
                "owasp_names": finding.rule.owasp_names
            })
            
        # Add assistant information if available
        if finding.assistant:
            if finding.assistant.guidance:
                finding_dict["guidance_summary"] = finding.assistant.guidance.summary
                finding_dict["guidance_instructions"] = finding.assistant.guidance.instructions
                
            if finding.assistant.autofix:
                finding_dict["autofix_code"] = finding.assistant.autofix.fix_code
                finding_dict["autofix_explanation"] = finding.assistant.autofix.explanation
                
            if finding.assistant.autotriage:
                finding_dict["autotriage_verdict"] = finding.assistant.autotriage.verdict
                finding_dict["autotriage_reason"] = finding.assistant.autotriage.reason
                
            if finding.assistant.component:
                finding_dict["component_tag"] = finding.assistant.component.tag
                finding_dict["component_risk"] = finding.assistant.component.risk
                
        return finding_dict

class TextSanitizer:
    """Handles text sanitization for different report formats."""
    
    @staticmethod
    def sanitize_for_pdf(text: Optional[str]) -> str:
        """Sanitize text for PDF output, handling Unicode characters."""
        if not text:
            return ""
            
        # Replace smart quotes and other problematic characters
        replacements = {
            '\u2018': "'",  # Left single quote
            '\u2019': "'",  # Right single quote
            '\u201c': '"',  # Left double quote
            '\u201d': '"',  # Right double quote
            '\u2013': '-',  # En dash
            '\u2014': '--', # Em dash
            '\u00a0': ' ',  # Non-breaking space
            '\u2022': '*',  # Bullet
            '\u2026': '...', # Ellipsis
            '\u2032': "'",  # Prime
            '\u2033': '"',  # Double prime
        }
        
        for char, replacement in replacements.items():
            text = text.replace(char, replacement)
        
        # Remove other non-Latin1 characters
        result = ""
        for char in text:
            if ord(char) < 256:  # Latin-1 range
                result += char
            else:
                result += '?'
                
        return result

class ReportFields:
    """Constants for report field names."""
    
    COMMON_FIELDS = [
        "check_id", "path", "line", "message", "severity", "repository",
        "finding_id", "line_of_code_url", "semgrep_ui_url",
        "state", "status", "triage_state", "triaged_at", "triage_comment", "triage_reason",
        "state_updated_at", "commit", "scan_date"
    ]
    
    SCA_FIELDS = [
        "is_dependency", "dependency_name", "dependency_version", "fixed_version",
        "ecosystem", "cve_ids", "references", "reachable", "reachability_details"
    ]
    
    RULE_FIELDS = [
        "rule_category", "rule_subcategories", "vulnerability_classes",
        "cwe_names", "owasp_names"
    ]
    
    ASSISTANT_FIELDS = [
        "guidance_summary", "guidance_instructions",
        "autofix_code", "autofix_explanation",
        "autotriage_verdict", "autotriage_reason",
        "component_tag", "component_risk"
    ]
    
    @classmethod
    def get_all_fields(cls) -> list:
        """Get all available report fields."""
        return (
            cls.COMMON_FIELDS +
            cls.SCA_FIELDS +
            cls.RULE_FIELDS +
            cls.ASSISTANT_FIELDS
        )
