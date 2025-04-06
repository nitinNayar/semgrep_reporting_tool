"""
Model for finding location information.
"""

from typing import Optional
from pydantic import BaseModel


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