"""
Date and time utility functions
"""

import sys
from datetime import datetime, timedelta
from typing import Tuple, Optional

# Colors for output
class Colors:
    RED = '\033[0;31m'
    NC = '\033[0m'  # No Color

def validate_date(date_str: str) -> None:
    """Validate date format (supports YYYY-MM-DD or YYYY-MM-DDTHH)."""
    # Try date format first
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
        return
    except ValueError:
        pass
    
    # Try datetime format with hour
    try:
        datetime.strptime(date_str, "%Y-%m-%dT%H")
        return
    except ValueError:
        pass
    
    print(f"{Colors.RED}Error: Invalid date format: {date_str}{Colors.NC}", file=sys.stderr)
    print("Date must be in YYYY-MM-DD or YYYY-MM-DDTHH format (e.g., 2025-11-25 or 2025-11-25T00)", file=sys.stderr)
    sys.exit(1)

def parse_datetime(date_str: str) -> datetime:
    """Parse date string to datetime object, supporting both date and datetime formats."""
    # Try datetime format with hour first
    try:
        return datetime.strptime(date_str, "%Y-%m-%dT%H")
    except ValueError:
        pass
    
    # Try date format
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        raise ValueError(f"Invalid date format: {date_str}")


def parse_date_range(start_date: Optional[str] = None,
                     end_date: Optional[str] = None,
                     single_date: Optional[str] = None) -> Tuple[str, str]:
    """
    Parse date range from arguments.

    Args:
        start_date: Start date in YYYY-MM-DD or YYYY-MM-DDTHH format
        end_date: End date in YYYY-MM-DD or YYYY-MM-DDTHH format
        single_date: Single date (will sync from this date to today)

    Returns:
        Tuple of (start_date, end_date) as strings
    """
    if single_date:
        start_date = single_date
        # Set end date to today in UTC
        # If start_date has hour precision, end_date should also have hour precision
        has_hour_precision = 'T' in single_date
        try:
            from datetime import timezone
            now = datetime.now(timezone.utc)
        except ImportError:
            now = datetime.utcnow()
        
        if has_hour_precision:
            # Use current hour for end date
            end_date = now.strftime("%Y-%m-%dT%H")
        else:
            # Use just the date for end date
            end_date = now.strftime("%Y-%m-%d")

    if not start_date or not end_date:
        raise ValueError("Start date and end date are required")

    # Validate dates
    validate_date(start_date)
    validate_date(end_date)

    # Parse to datetime for comparison
    start_dt = parse_datetime(start_date)
    end_dt = parse_datetime(end_date)
    
    if start_dt > end_dt:
        print(f"{Colors.RED}Error: Start date must be before or equal to end date{Colors.NC}", file=sys.stderr)
        sys.exit(1)

    return (start_date, end_date)

