"""
Model for repository information.
"""

from typing import Optional
from pydantic import BaseModel


class Repository(BaseModel):
    """Model for repository information."""
    name: Optional[str] = None
    url: Optional[str] = None
    
    model_config = {
        "extra": "ignore",
        "arbitrary_types_allowed": True
    } 