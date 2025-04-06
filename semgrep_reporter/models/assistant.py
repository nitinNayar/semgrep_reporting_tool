"""
Models for assistant-related information including autofix, guidance, and triage.
"""

from typing import Optional
from pydantic import BaseModel


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