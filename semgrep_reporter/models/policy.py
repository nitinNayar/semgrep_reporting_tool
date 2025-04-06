"""
Model for sourcing policy information.
"""

from typing import Optional
from pydantic import BaseModel


class SourcingPolicy(BaseModel):
    """Model for sourcing policy."""
    id: Optional[int] = None
    name: Optional[str] = None
    slug: Optional[str] = None
    
    model_config = {
        "extra": "ignore",
        "arbitrary_types_allowed": True
    } 