"""Pagination schemas for list endpoints."""

from typing import Generic, TypeVar

from pydantic import BaseModel, Field, computed_field

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response for list endpoints.

    Provides consistent pagination structure with metadata.
    """

    items: list[T] = Field(description="List of items in current page")
    total: int = Field(ge=0, description="Total number of items")
    page: int = Field(ge=1, description="Current page number (1-indexed)")
    page_size: int = Field(ge=1, le=1000, description="Number of items per page")

    @computed_field
    @property
    def total_pages(self) -> int:
        """Calculate total number of pages."""
        if self.page_size == 0:
            return 0
        return (self.total + self.page_size - 1) // self.page_size

    @computed_field
    @property
    def has_next(self) -> bool:
        """Check if there is a next page."""
        return self.page < self.total_pages

    @computed_field
    @property
    def has_prev(self) -> bool:
        """Check if there is a previous page."""
        return self.page > 1

    model_config = {
        "json_schema_extra": {
            "example": {
                "items": [],
                "total": 100,
                "page": 1,
                "page_size": 20,
                "total_pages": 5,
                "has_next": True,
                "has_prev": False,
            }
        }
    }
