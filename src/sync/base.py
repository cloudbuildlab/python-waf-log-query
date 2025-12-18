"""
Base sync class/interface
"""

from abc import ABC, abstractmethod
from typing import Tuple, Dict
from pathlib import Path

class BaseSync(ABC):
    """Base class for log synchronization."""

    def __init__(self, source_name: str, source_config: Dict):
        """
        Initialize sync instance.

        Args:
            source_name: Name of the log source
            source_config: Configuration dictionary for this source
        """
        self.source_name = source_name
        self.config = source_config
        self.local_dir = Path(source_config.get('local_dir', f"logs/{source_name}/raw"))

    @abstractmethod
    def sync(self, start_date: str, end_date: str, max_workers: int = 10) -> Tuple[int, int, int]:
        """
        Sync logs for the specified date range.

        Args:
            start_date: Start date in YYYY-MM-DD format
            end_date: End date in YYYY-MM-DD format
            max_workers: Number of concurrent workers

        Returns:
            Tuple of (downloads, skips, errors)
        """
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test connection to the log source.

        Returns:
            True if connection is successful
        """
        pass

