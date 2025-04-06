"""
Models for external integrations like tickets and review comments.
"""

from typing import Optional
from pydantic import BaseModel


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