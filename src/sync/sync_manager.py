"""
Sync manager - orchestrates multiple log sources
"""

from typing import Dict, Tuple
from .base import BaseSync
from .s3_sync import S3Sync

def create_sync_instance(source_name: str, source_config: Dict) -> BaseSync:
    """
    Create appropriate sync instance based on source type.

    Args:
        source_name: Name of the log source
        source_config: Configuration dictionary for this source

    Returns:
        BaseSync instance
    """
    source_type = source_config.get('type', '').lower()

    if source_type == 's3':
        return S3Sync(source_name, source_config)
    else:
        raise ValueError(f"Unsupported source type: {source_type}")

class SyncManager:
    """Manages synchronization of multiple log sources."""

    def __init__(self, sources: Dict):
        """
        Initialize sync manager.

        Args:
            sources: Dictionary of source configurations
        """
        self.sources = sources
        self.sync_instances = {}

    def get_sync_instance(self, source_name: str) -> BaseSync:
        """Get or create sync instance for a source."""
        if source_name not in self.sync_instances:
            if source_name not in self.sources:
                raise ValueError(f"Source '{source_name}' not found in configuration")
            self.sync_instances[source_name] = create_sync_instance(
                source_name, self.sources[source_name]
            )
        return self.sync_instances[source_name]

    def sync_source(self, source_name: str, start_date: str, end_date: str,
                   max_workers: int = 10) -> Tuple[int, int, int]:
        """Sync a specific source."""
        sync_instance = self.get_sync_instance(source_name)
        return sync_instance.sync(start_date, end_date, max_workers)

    def sync_all(self, start_date: str, end_date: str,
                max_workers: int = 10) -> Dict[str, Tuple[int, int, int]]:
        """
        Sync all enabled sources.

        Returns:
            Dictionary mapping source names to (downloads, skips, errors) tuples
        """
        results = {}
        for source_name in self.sources:
            if self.sources[source_name].get('enabled', False):
                results[source_name] = self.sync_source(
                    source_name, start_date, end_date, max_workers
                )
        return results

