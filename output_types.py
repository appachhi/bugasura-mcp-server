"""Structured output TypedDicts used across tools."""
from typing import Any, List, Literal, Optional, Union

from pydantic import ConfigDict, with_config
from typing_extensions import Required, TypedDict


@with_config(ConfigDict(extra="allow"))
class PaginatedResponse(TypedDict, total=False):
    """Standard pagination envelope returned by list_*/find_* tools."""
    status: Required[Literal["OK"]]
    total: int
    count: int
    offset: int
    items: List[Any]
    has_more: bool
    next_offset: Optional[int]

@with_config(ConfigDict(extra="allow"))
class SelectionRequired(TypedDict, total=False):
    """Interactive prompt when team/project/etc. context is missing."""
    status: Required[Literal["selection_required"]]
    step: str
    message: str
    options: List[Any]
    instruction: str

@with_config(ConfigDict(extra="allow"))
class ErrorResponse(TypedDict, total=False):
    """Generic failure envelope."""
    status: Required[Literal["failed"]]
    error: str
    error_type: str
    message: str

@with_config(ConfigDict(extra="allow"))
class ApiKeyRequired(TypedDict, total=False):
    """Signals a valid Bugasura API key is missing or invalid."""
    status: Required[Literal["api_key_required"]]
    error: str
    error_type: str
    action: str
    help: str


@with_config(ConfigDict(extra="allow"))
class OkResponse(TypedDict, total=False):
    """Any other tool result: a record or action outcome, always with a status."""
    status: Required[str]


ToolResponse = Union[PaginatedResponse, SelectionRequired, ErrorResponse,
                     ApiKeyRequired, OkResponse]
