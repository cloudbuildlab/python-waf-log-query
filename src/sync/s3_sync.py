"""
S3-specific sync implementation
"""

import os
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional
import boto3
from botocore.exceptions import ClientError, BotoCoreError

from .base import BaseSync

# Colors for output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color

class S3Sync(BaseSync):
    """S3 log synchronization implementation."""

    def __init__(self, source_name: str, source_config: dict):
        super().__init__(source_name, source_config)
        self.s3_bucket = source_config.get('s3_bucket')
        self.bucket_name, self.bucket_path = self._parse_s3_uri(self.s3_bucket)
        self.s3_client = None

    def _parse_s3_uri(self, s3_uri: str) -> Tuple[str, str]:
        """Parse S3 URI into bucket name and path."""
        s3_uri = s3_uri.replace("s3://", "")
        parts = s3_uri.split("/", 1)
        bucket_name = parts[0]
        bucket_path = parts[1] if len(parts) > 1 else ""
        if bucket_path and not bucket_path.endswith("/"):
            bucket_path += "/"
        return bucket_name, bucket_path

    def _create_s3_client(self):
        """Create S3 client with optional profile."""
        profile = self.config.get('credentials', {}).get('profile')

        if profile:
            session = boto3.Session(profile_name=profile)
            return session.client('s3')
        else:
            return boto3.client('s3')

    def test_connection(self) -> bool:
        """Test connection to S3 bucket."""
        try:
            if self.s3_client is None:
                self.s3_client = self._create_s3_client()
            self.s3_client.head_bucket(Bucket=self.bucket_name)
            return True
        except (ClientError, BotoCoreError):
            return False

    def _list_s3_files(self, prefix: str) -> List[str]:
        """List all files in S3 matching the prefix pattern."""
        files = []
        paginator = self.s3_client.get_paginator('list_objects_v2')

        try:
            for page in paginator.paginate(Bucket=self.bucket_name, Prefix=prefix):
                if 'Contents' in page:
                    for obj in page['Contents']:
                        key = obj['Key']
                        # Filter for log files
                        if key.endswith('.log.gz') or key.endswith('.log'):
                            files.append(key)
        except ClientError as e:
            print(f"{Colors.RED}Error listing files: {e}{Colors.NC}")
            return []

        return files

    def _get_s3_object_size(self, key: str) -> Optional[int]:
        """Get the size of an S3 object."""
        try:
            response = self.s3_client.head_object(Bucket=self.bucket_name, Key=key)
            return response.get('ContentLength', 0)
        except ClientError:
            return None

    def _download_file(self, s3_key: str, local_file: Path,
                      file_num: int, total_files: int) -> Tuple[bool, str]:
        """Download a single file from S3."""
        filename = local_file.name

        # Check if file exists and compare size
        needs_download = True
        if local_file.exists():
            s3_size = self._get_s3_object_size(s3_key)
            if s3_size is not None:
                local_size = local_file.stat().st_size
                if s3_size == local_size and s3_size > 0:
                    needs_download = False

        if not needs_download:
            return (False, f"{Colors.YELLOW}  ⊘ [{file_num}/{total_files}] Skipped (up to date): {filename}{Colors.NC}")

        # Download the file
        try:
            self.s3_client.download_file(self.bucket_name, s3_key, str(local_file))
            return (True, f"{Colors.GREEN}  ✓ [{file_num}/{total_files}] Downloaded: {filename}{Colors.NC}")
        except ClientError as e:
            return (False, f"{Colors.RED}  ✗ [{file_num}/{total_files}] Failed: {filename} - {e}{Colors.NC}")

    def _date_to_prefix(self, date_str: str) -> str:
        """
        Convert a date string (YYYY-MM-DD or YYYY-MM-DDTHH) to the WAF Firehose prefix
        layout: YYYY/MM/DD/ or YYYY/MM/DD/HH/
        """
        try:
            if "T" in date_str:
                dt = datetime.strptime(date_str, "%Y-%m-%dT%H")
                return dt.strftime("%Y/%m/%d/%H/")
            dt = datetime.strptime(date_str, "%Y-%m-%d")
            return dt.strftime("%Y/%m/%d/")
        except ValueError:
            # Fallback: return raw to avoid breaking sync
            return date_str

    def _sync_date(self, date_str: str, max_workers: int = 10) -> Tuple[int, int, int]:
        """Sync all files for a specific date."""
        prefix = f"{self.bucket_path}{self._date_to_prefix(date_str)}"

        print(f"{Colors.YELLOW}Syncing logs for date: {date_str}{Colors.NC}")
        print(f"{Colors.BLUE}  Listing files for {date_str} (prefix: {prefix})...{Colors.NC}")

        # List all files for this date
        files = self._list_s3_files(prefix)
        file_count = len(files)

        if file_count == 0:
            print(f"{Colors.YELLOW}  ⊘ No files found for this date{Colors.NC}")
            return (0, 0, 0)

        print(f"{Colors.BLUE}  Found {file_count} file(s) - syncing with {max_workers} concurrent workers...{Colors.NC}")

        # Directory should already exist from sync() method, but ensure it exists
        self.local_dir.mkdir(parents=True, exist_ok=True)

        downloads = 0
        skips = 0
        errors = 0

        # Download files concurrently
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all download tasks
            future_to_file = {}
            for idx, s3_key in enumerate(files, 1):
                filename = os.path.basename(s3_key)
                local_file = self.local_dir / filename
                future = executor.submit(self._download_file, s3_key, local_file, idx, file_count)
                future_to_file[future] = (idx, filename)

            # Process completed downloads and show progress
            completed = 0
            for future in as_completed(future_to_file):
                completed += 1
                file_num, filename = future_to_file[future]
                try:
                    is_download, message = future.result()
                    print(f"\r{message}", end="", flush=True)

                    if is_download:
                        downloads += 1
                    else:
                        if "Skipped" in message:
                            skips += 1
                        else:
                            errors += 1

                    # Show overall progress
                    print(f"\r{Colors.BLUE}  Progress: {completed}/{file_count} files processed...{Colors.NC}",
                          end="", flush=True)
                except Exception as e:
                    print(f"\r{Colors.RED}  ✗ [{file_num}/{file_count}] Error: {filename} - {e}{Colors.NC}")
                    errors += 1

        print()  # New line after progress

        # Show summary
        if downloads > 0:
            print(f"{Colors.GREEN}  ✓ Downloaded/updated {downloads} file(s){Colors.NC}")
        if skips > 0:
            print(f"{Colors.YELLOW}  ⊘ Skipped {skips} file(s) (up to date){Colors.NC}")

        return (downloads, skips, errors)

    def sync(self, start_date: str, end_date: str, max_workers: int = 10) -> Tuple[int, int, int]:
        """Sync logs for the specified date range."""
        # Create local directory if it doesn't exist (do this early)
        self.local_dir.mkdir(parents=True, exist_ok=True)

        # Initialize S3 client
        if self.s3_client is None:
            try:
                self.s3_client = self._create_s3_client()
                # Test credentials
                self.s3_client.head_bucket(Bucket=self.bucket_name)
            except (ClientError, BotoCoreError) as e:
                print(f"{Colors.RED}Error: AWS credentials not configured or invalid for source '{self.source_name}'{Colors.NC}")
                print(f"Please configure AWS credentials: {e}")
                return (0, 0, 1)

        print(f"\n{Colors.GREEN}{'='*60}{Colors.NC}")
        print(f"{Colors.GREEN}Syncing source: {self.source_name}{Colors.NC}")
        print(f"{Colors.BLUE}Description: {self.config.get('description', 'N/A')}{Colors.NC}")
        print(f"{Colors.BLUE}S3 Bucket: {self.s3_bucket}{Colors.NC}")
        print(f"{Colors.BLUE}Local Directory: {self.local_dir}{Colors.NC}")
        print(f"{Colors.GREEN}{'='*60}{Colors.NC}\n")

        # Parse dates - support both date and datetime formats
        from src.utils.date_utils import parse_datetime

        start_dt = parse_datetime(start_date)
        end_dt = parse_datetime(end_date)

        # Check if hour-level precision is used
        has_hour_precision = 'T' in start_date or 'T' in end_date

        # Generate date/hour range
        current_dt = start_dt
        total_downloads = 0
        total_skips = 0
        total_errors = 0

        if has_hour_precision:
            # Iterate hour by hour
            while current_dt <= end_dt:
                date_str = current_dt.strftime("%Y-%m-%dT%H")
                downloads, skips, errors = self._sync_date(date_str, max_workers)

                total_downloads += downloads
                total_skips += skips
                total_errors += errors

                # Move to next hour
                current_dt += timedelta(hours=1)
        else:
            # Iterate day by day (original behavior)
            while current_dt <= end_dt:
                date_str = current_dt.strftime("%Y-%m-%d")
                downloads, skips, errors = self._sync_date(date_str, max_workers)

                total_downloads += downloads
                total_skips += skips
                total_errors += errors

                # Move to next date
                current_dt += timedelta(days=1)

        print(f"\n{Colors.GREEN}Source '{self.source_name}' sync completed!{Colors.NC}")
        print(f"  New files downloaded: {total_downloads}")
        print(f"  Files skipped (already exist): {total_skips}")
        if total_errors > 0:
            print(f"  {Colors.RED}Errors encountered: {total_errors}{Colors.NC}")

        return (total_downloads, total_skips, total_errors)

