"""
Type Safety Utilities

Type checking and validation utilities for improved type safety.

Author: AI-SOAR Platform Team
Created: 2025-09-11
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Type, TypeVar, Union
from uuid import UUID

T = TypeVar("T")


def safe_cast(
    value: Any, target_type: Type[T], default: Optional[T] = None
) -> Optional[T]:
    """Safely cast value to target type with default fallback"""
    try:
        if value is None:
            return default

        if isinstance(value, target_type):
            return value

        if target_type == str:
            return str(value)
        elif target_type == int:
            return int(value)
        elif target_type == float:
            return float(value)
        elif target_type == bool:
            if isinstance(value, str):
                return value.lower() in ("true", "1", "yes", "on")
            return bool(value)
        elif target_type == UUID:
            return UUID(str(value))
        elif target_type == datetime:
            if isinstance(value, str):
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            return value
        else:
            return target_type(value)

    except (ValueError, TypeError, AttributeError):
        return default


def validate_uuid(value: Any) -> Optional[str]:
    """Validate and return UUID string"""
    try:
        if isinstance(value, UUID):
            return str(value)
        uuid_obj = UUID(str(value))
        return str(uuid_obj)
    except (ValueError, TypeError):
        return None


def validate_dict_keys(data: Dict[str, Any], required_keys: List[str]) -> bool:
    """Validate that dictionary contains required keys"""
    return all(key in data for key in required_keys)


def safe_dict_get(
    data: Dict[str, Any], key: str, target_type: Type[T], default: Optional[T] = None
) -> Optional[T]:
    """Safely get value from dict with type casting"""
    value = data.get(key)
    return safe_cast(value, target_type, default)
