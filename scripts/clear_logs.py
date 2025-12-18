#!/usr/bin/env python3
"""
Clear all log files (raw and parsed) from the logs directory.
"""

import argparse
import sys
from pathlib import Path

# Colors for output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color


def clear_logs(logs_dir: Path = None, confirm: bool = True):
    """
    Clear all log files from the logs directory.
    
    Args:
        logs_dir: Path to logs directory (default: ./logs)
        confirm: Whether to ask for confirmation (default: True)
    """
    if logs_dir is None:
        logs_dir = Path(__file__).parent.parent / "logs"
    
    if not logs_dir.exists():
        print(f"{Colors.YELLOW}Logs directory does not exist: {logs_dir}{Colors.NC}")
        return 0
    
    # Find all log files
    log_files = []
    for pattern in ["*.log*", "*.json", "*.csv"]:
        log_files.extend(logs_dir.rglob(pattern))
    
    if not log_files:
        print(f"{Colors.BLUE}No log files found to clear{Colors.NC}")
        return 0
    
    # Count files
    file_count = len(log_files)
    total_size = sum(f.stat().st_size for f in log_files if f.is_file())
    size_mb = total_size / (1024 * 1024)
    
    print(f"{Colors.BLUE}Found {file_count:,} log file(s) ({size_mb:.2f} MB){Colors.NC}")
    
    if confirm:
        response = input(f"{Colors.YELLOW}Are you sure you want to delete all log files? (yes/no): {Colors.NC}")
        if response.lower() not in ['yes', 'y']:
            print(f"{Colors.BLUE}Cancelled{Colors.NC}")
            return 0
    
    # Delete files
    deleted = 0
    for log_file in log_files:
        try:
            if log_file.is_file():
                log_file.unlink()
                deleted += 1
        except Exception as e:
            print(f"{Colors.RED}Error deleting {log_file}: {e}{Colors.NC}", file=sys.stderr)
    
    # Remove empty directories
    try:
        for dir_path in sorted(logs_dir.rglob("*"), reverse=True):
            if dir_path.is_dir():
                try:
                    dir_path.rmdir()
                except OSError:
                    pass  # Directory not empty, skip
    except Exception:
        pass  # Ignore errors when removing directories
    
    print(f"{Colors.GREEN}Cleared {deleted:,} log file(s){Colors.NC}")
    
    # Try to remove logs directory if empty
    try:
        if logs_dir.exists() and not any(logs_dir.iterdir()):
            logs_dir.rmdir()
            print(f"{Colors.GREEN}Removed empty logs directory{Colors.NC}")
    except Exception:
        pass
    
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Clear all log files (raw and parsed) from the logs directory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Clear logs with confirmation
  %(prog)s --yes              # Clear logs without confirmation
  %(prog)s --logs-dir ./logs  # Clear logs from custom directory
        """
    )
    parser.add_argument(
        "--logs-dir",
        type=str,
        help="Path to logs directory (default: ./logs)"
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Skip confirmation prompt"
    )
    
    args = parser.parse_args()
    
    logs_dir = Path(args.logs_dir) if args.logs_dir else None
    
    return clear_logs(logs_dir, confirm=not args.yes)


if __name__ == "__main__":
    sys.exit(main())

