"""
Model for rule information.
"""

from typing import Optional, List
from pydantic import BaseModel


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