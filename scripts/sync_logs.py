#!/usr/bin/env python3

"""
AWS WAF Log Sync Script
CLI entry point for syncing logs from multiple sources
"""

import argparse
import sys
from pathlib import Path

# Add src to path for imports (go up one level from scripts/ to root)
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.config_loader import load_config, get_enabled_sources
from src.utils.date_utils import parse_date_range
from src.sync.sync_manager import SyncManager

# Colors for output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color

def main():
    parser = argparse.ArgumentParser(
        description="Sync logs from S3 (supports multiple sources via config)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sync default (first enabled) WAF source
  %(prog)s --date 2025-12-16T22

  # Sync specific source
  %(prog)s --source your-source --date 2025-12-16

  # Sync all enabled sources
  %(prog)s --all-sources --start-date 2025-12-16 --end-date 2025-12-17

  # Sync with custom config file
  %(prog)s --config custom_config.yaml --source your-source --date 2025-12-16
        """
    )
    parser.add_argument("--start-date", type=str, help="Start date in YYYY-MM-DD or YYYY-MM-DDTHH format (e.g., 2025-11-25 or 2025-11-25T00)")
    parser.add_argument("--end-date", type=str, help="End date in YYYY-MM-DD or YYYY-MM-DDTHH format (e.g., 2025-11-25 or 2025-11-25T23)")
    parser.add_argument("--date", type=str, help="Start date in YYYY-MM-DD or YYYY-MM-DDTHH format (syncs from this date to today)")
    parser.add_argument("--source", type=str, help="Specific log source to sync (from config)")
    parser.add_argument("--all-sources", action="store_true", help="Sync all enabled sources")
    parser.add_argument("--list-sources", action="store_true", help="List all available log sources")
    parser.add_argument("--config", type=str, help="Path to configuration file (default: config/log_sources.yaml)")
    parser.add_argument("--workers", type=int, default=10, help="Number of concurrent workers (default: 10)")

    args = parser.parse_args()

    # Load configuration
    config_path = Path(args.config) if args.config else None
    sources = load_config(config_path)
    enabled_sources = get_enabled_sources(sources)

    # List sources if requested
    if args.list_sources:
        print(f"{Colors.BLUE}Available log sources:{Colors.NC}\n")
        for name, config in sources.items():
            status = f"{Colors.GREEN}ENABLED{Colors.NC}" if config.get('enabled', False) else f"{Colors.YELLOW}DISABLED{Colors.NC}"
            print(f"  {name}: {status}")
            print(f"    Description: {config.get('description', 'N/A')}")
            print(f"    Type: {config.get('type', 'N/A')}")
            if config.get('type') == 's3':
                print(f"    S3 Bucket: {config.get('s3_bucket', 'N/A')}")
            print()
        sys.exit(0)

    # Parse date range
    try:
        start_date, end_date = parse_date_range(
            args.start_date, args.end_date, args.date
        )
    except ValueError as e:
        print(f"{Colors.RED}Error: {e}{Colors.NC}", file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    if args.date:
        print(f"{Colors.YELLOW}Note: --date specified, syncing from {start_date} to {end_date} (today UTC){Colors.NC}")

    # Determine which sources to sync
    sources_to_sync = {}

    if args.all_sources:
        sources_to_sync = enabled_sources
        if not sources_to_sync:
            print(f"{Colors.RED}Error: No enabled sources found in configuration{Colors.NC}", file=sys.stderr)
            sys.exit(1)
    elif args.source:
        if args.source not in sources:
            print(f"{Colors.RED}Error: Source '{args.source}' not found in configuration{Colors.NC}", file=sys.stderr)
            print(f"Available sources: {', '.join(sources.keys())}", file=sys.stderr)
            sys.exit(1)
        if not sources[args.source].get('enabled', False):
            print(f"{Colors.YELLOW}Warning: Source '{args.source}' is disabled{Colors.NC}", file=sys.stderr)
        sources_to_sync = {args.source: sources[args.source]}
    else:
        # Default: sync all enabled sources automatically
        if not enabled_sources:
            print(f"{Colors.RED}Error: No enabled sources found in configuration{Colors.NC}", file=sys.stderr)
            sys.exit(1)
        sources_to_sync = enabled_sources
        print(f"{Colors.YELLOW}Note: No source specified, syncing all enabled sources: {', '.join(sources_to_sync.keys())}{Colors.NC}")

    print(f"{Colors.GREEN}Starting log sync...{Colors.NC}")
    print(f"Date Range: {start_date} to {end_date}")
    print(f"Sources to sync: {', '.join(sources_to_sync.keys())}")
    print(f"Concurrent Workers: {args.workers}")
    print()

    # Create sync manager and sync sources
    sync_manager = SyncManager(sources_to_sync)

    total_downloads = 0
    total_skips = 0
    total_errors = 0

    for source_name in sources_to_sync:
        downloads, skips, errors = sync_manager.sync_source(
            source_name, start_date, end_date, args.workers
        )
        total_downloads += downloads
        total_skips += skips
        total_errors += errors

    print()
    print(f"{Colors.GREEN}{'='*60}{Colors.NC}")
    print(f"{Colors.GREEN}All syncs completed!{Colors.NC}")
    print(f"  Total files downloaded: {total_downloads}")
    print(f"  Total files skipped: {total_skips}")
    if total_errors > 0:
        print(f"  {Colors.RED}Total errors: {total_errors}{Colors.NC}")
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
