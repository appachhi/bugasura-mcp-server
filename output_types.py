"""Structured output TypedDicts used across tools."""
from typing import Any, List, Literal, Optional, TypedDict, Union


class PaginatedResponse(TypedDict, total=False):
    """Standard pagination envelope returned by list_*/find_* tools."""
    status: Literal["OK"]
    total: int
    count: int
    offset: int
    items: List[Any]
    has_more: bool
    next_offset: Optional[int]

class SelectionRequired(TypedDict, total=False):
    """Interactive prompt when team/project/etc. context is missing."""
    status: Literal["selection_required"]
    step: str
    message: str
    options: List[Any]
    instruction: str

class ErrorResponse(TypedDict, total=False):
    """Generic failure envelope."""
    status: Literal["failed"]
    error: str
    error_type: str
    message: str

class ApiKeyRequired(TypedDict, total=False):
    """Signals a valid Bugasura API key is missing or invalid."""
    status: Literal["api_key_required"]
    error: str
    error_type: str
    action: str
    help: str


ToolResponse = Union[PaginatedResponse, SelectionRequired, ErrorResponse,
                     ApiKeyRequired, dict, str]
