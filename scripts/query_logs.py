#!/usr/bin/env python3
"""
AWS WAF Log Query Orchestration Script
Orchestrates the full pipeline: sync → parse → analyze
"""

import argparse
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.config_loader import load_config, get_enabled_sources
from src.utils.date_utils import parse_date_range

# Colors for output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color


def check_python_packages():
    """Check if required Python packages are installed."""
    try:
        import pandas
        return True
    except ImportError:
        return False


def install_packages():
    """Install required packages."""
    project_root = Path(__file__).parent.parent
    requirements_file = project_root / "requirements.txt"

    print(f"{Colors.YELLOW}Warning: Required Python packages not found. Installing...{Colors.NC}")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(requirements_file)],
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        print(f"{Colors.RED}Error: Failed to install Python dependencies{Colors.NC}", file=sys.stderr)
        return False


def run_sync(start_date: str, end_date: str, single_date: str = None):
    """Run sync operation."""
    script_dir = Path(__file__).parent
    sync_script = script_dir / "sync_logs.py"

    args = [sys.executable, str(sync_script)]
    if single_date:
        args.extend(["--date", single_date])
    else:
        args.extend(["--start-date", start_date, "--end-date", end_date])

    print(f"{Colors.GREEN}[1/3] Syncing logs from S3...{Colors.NC}")
    try:
        result = subprocess.run(args, check=True)
        print()
        return result.returncode == 0
    except subprocess.CalledProcessError:
        print(f"{Colors.RED}Error: Sync failed{Colors.NC}", file=sys.stderr)
        return False


def run_parse():
    """Run parse operation for all enabled sources."""
    script_dir = Path(__file__).parent
    parse_script = script_dir / "parse_logs.py"

    print(f"{Colors.GREEN}[2/3] Parsing log files...{Colors.NC}")

    # Check Python packages
    if not check_python_packages():
        if not install_packages():
            return None

    # Get enabled sources
    try:
        sources = load_config()
        enabled = get_enabled_sources(sources)
    except Exception as e:
        print(f"{Colors.RED}Error: Failed to load configuration: {e}{Colors.NC}", file=sys.stderr)
        return None

    if not enabled:
        print(f"{Colors.RED}Error: No enabled sources found to parse{Colors.NC}", file=sys.stderr)
        return None

    # Parse each enabled source
    parsed_outputs = []
    for name, config in enabled.items():
        local_dir = config.get('local_dir', f"logs/{name}/raw")
        parsed_dir = config.get('parsed_dir', f"logs/{name}/parsed")
        output_file = f"{parsed_dir}/parsed_logs.json"

        print(f"{Colors.BLUE}  Parsing source: {name}{Colors.NC}")

        args = [
            sys.executable, str(parse_script),
            "--input-dir", local_dir,
            "--output", output_file,
            "--format", "json"
        ]

        try:
            subprocess.run(args, check=True)
            parsed_outputs.append(output_file)
        except subprocess.CalledProcessError:
            print(f"{Colors.YELLOW}Warning: Parsing failed for {name}, continuing...{Colors.NC}", file=sys.stderr)

    print()
    return parsed_outputs[0] if parsed_outputs else None


def run_analyze(parsed_output: str, analytics_output: str = None, last_hours: float = None):
    """Run analyze operation."""
    script_dir = Path(__file__).parent
    analyze_script = script_dir / "analyze_logs.py"

    print(f"{Colors.GREEN}[3/3] Generating analytics...{Colors.NC}")

    # Check if parsed output exists
    if not Path(parsed_output).exists():
        print(f"{Colors.RED}Error: Parsed log file not found: {parsed_output}{Colors.NC}", file=sys.stderr)
        print("Run parse operation first or specify correct --parsed-output path", file=sys.stderr)
        return False

    args = [
        sys.executable, str(analyze_script),
        "--input", parsed_output,
        "--format", "console"
    ]

    if analytics_output:
        args.extend(["--output", analytics_output])

    if last_hours:
        args.extend(["--last-hours", str(last_hours)])

    try:
        subprocess.run(args, check=True)
        print()
        return True
    except subprocess.CalledProcessError:
        print(f"{Colors.RED}Error: Analytics failed{Colors.NC}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="AWS WAF Log Query Tool - Orchestrates sync, parse, and analyze operations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --date 2025-12-16
  %(prog)s --start-date 2025-12-16 --end-date 2025-12-17 --operation sync
  %(prog)s --operation analyze --parsed-output ./logs/your-source/parsed/parsed_logs.json
        """
    )
    parser.add_argument("--start-date", type=str, help="Start date in YYYY-MM-DD or YYYY-MM-DDTHH format (e.g., 2025-11-25 or 2025-11-25T00)")
    parser.add_argument("--end-date", type=str, help="End date in YYYY-MM-DD or YYYY-MM-DDTHH format (e.g., 2025-11-25 or 2025-11-25T23)")
    parser.add_argument("--date", type=str, help="Start date in YYYY-MM-DD or YYYY-MM-DDTHH format (syncs from this date to today)")
    parser.add_argument(
        "--operation",
        choices=["sync", "parse", "analyze", "all"],
        default="all",
        help="Operation to perform (default: all)"
    )
    parser.add_argument(
        "--parsed-output",
        type=str,
        default=None,
        help="Output file for parsed logs (default: first enabled source's parsed output)"
    )
    parser.add_argument(
        "--analytics-output",
        type=str,
        help="Output file for analytics report (optional)"
    )
    parser.add_argument(
        "--last-hours",
        type=float,
        help="Filter to only entries from the last N hours (e.g., 1.0 for last hour). Only applies to analyze operation."
    )

    args = parser.parse_args()

    # Parse date range (only if dates are provided)
    start_date = None
    end_date = None
    has_dates = bool(args.start_date or args.end_date or args.date)
    if has_dates:
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

    # If --last-hours is specified without dates and without explicit operation:
    # - Check if parsed logs exist
    # - If not, automatically sync today's logs and parse them, then analyze
    # - If yes, just analyze
    if args.last_hours and not has_dates and args.operation == "all":
        # Check if parsed logs exist
        try:
            sources = load_config()
            enabled = get_enabled_sources(sources)
            if enabled:
                first_source = next(iter(enabled))
                first_config = enabled[first_source]
                parsed_dir = first_config.get('parsed_dir', f"logs/{first_source}/parsed")
                parsed_output_path = Path(f"{parsed_dir}/parsed_logs.json")

                if parsed_output_path.exists():
                    # Parsed logs exist, just analyze
                    args.operation = "analyze"
                else:
                    # No parsed logs, sync today's logs and parse, then analyze
                    print(f"{Colors.YELLOW}No parsed logs found. Syncing today's logs...{Colors.NC}")
                    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                    try:
                        start_date, end_date = parse_date_range(today, today, None)
                        has_dates = True
                        args.operation = "all"
                    except ValueError as e:
                        print(f"{Colors.RED}Error setting date: {e}{Colors.NC}", file=sys.stderr)
                        args.operation = "analyze"
            else:
                args.operation = "analyze"
        except Exception:
            # If we can't determine, default to analyze
            args.operation = "analyze"

    # Validate date parameters for sync operation
    if args.operation in ["sync", "all"]:
        if not start_date or not end_date:
            print(f"{Colors.RED}Error: Start date and end date are required for sync operation{Colors.NC}", file=sys.stderr)
            parser.print_help()
            sys.exit(1)

    print(f"{Colors.BLUE}AWS WAF Log Query Tool{Colors.NC}")
    print("===========================")
    print()

    # Step 1: Sync logs from S3
    if args.operation in ["sync", "all"]:
        if not run_sync(start_date, end_date, args.date):
            sys.exit(1)

    # Step 2: Parse logs
    parsed_output = args.parsed_output
    if args.operation in ["parse", "all"]:
        result = run_parse()
        if result is None:
            sys.exit(1)
        # Use parsed output from run_parse if not explicitly set
        if not parsed_output:
            parsed_output = result

    # Step 3: Analyze logs
    if args.operation in ["analyze", "all"]:
        if not parsed_output:
            # Try to get first enabled source's output
            try:
                sources = load_config()
                enabled = get_enabled_sources(sources)
                if enabled:
                    first_source = next(iter(enabled))
                    first_config = enabled[first_source]
                    parsed_dir = first_config.get('parsed_dir', f"logs/{first_source}/parsed")
                    parsed_output = f"{parsed_dir}/parsed_logs.json"
                else:
                    print(f"{Colors.RED}Error: No enabled sources found{Colors.NC}", file=sys.stderr)
                    sys.exit(1)
            except Exception as e:
                print(f"{Colors.RED}Error: Failed to determine parsed output: {e}{Colors.NC}", file=sys.stderr)
                sys.exit(1)

        if not run_analyze(parsed_output, args.analytics_output, args.last_hours):
            sys.exit(1)

    print(f"{Colors.GREEN}All operations completed successfully!{Colors.NC}")


if __name__ == "__main__":
    main()

