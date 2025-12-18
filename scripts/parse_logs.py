#!/usr/bin/env python3
"""
AWS WAF Log Parser CLI
Uses the shared WAF parser to convert NDJSON Firehose logs to JSON/CSV with optional multiprocessing.
"""

import json
import csv
import argparse
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Dict, List, Tuple
import sys

# Ensure src is importable for shared WAF parser
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.parse.log_parser import process_log_file as waf_process_log_file


def process_log_file(file_path: Path):
    """
    Process a log file (compressed or uncompressed) and yield parsed entries lazily.

    Args:
        file_path: Path to the log file

    Yields:
        Parsed log entry dictionaries
    """
    try:
        if file_path.suffix == '.gz':
            with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    entry = parse_log_line(line)
                    if entry:
                        entry['source_file'] = str(file_path)
                        entry['line_number'] = line_num
                        yield entry
        else:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    entry = parse_log_line(line)
                    if entry:
                        entry['source_file'] = str(file_path)
                        entry['line_number'] = line_num
                        yield entry
    except Exception as e:
        print(f"Error processing {file_path}: {e}", file=sys.stderr)


def save_json_streaming(entries, output_path: Path):
    """Save parsed data as JSON using streaming (memory efficient)."""
    # Create directory if it doesn't exist
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        f.write('[\n')
        first = True
        for entry in entries:
            if not first:
                f.write(',\n')
            json.dump(entry, f, indent=2)
            first = False
        f.write('\n]')


def save_csv_streaming(entries, output_path: Path):
    """Save parsed data as CSV using streaming (memory efficient)."""
    # Create directory if it doesn't exist
    output_path.parent.mkdir(parents=True, exist_ok=True)
    writer = None
    first_entry = True

    with open(output_path, 'w', newline='') as f:
        for entry in entries:
            # Flatten query_params for CSV
            flat_entry = entry.copy()
            # Convert query_params dict to string for CSV
            flat_entry['query_params'] = json.dumps(entry['query_params'])

            if first_entry:
                # Initialize writer with fieldnames from first entry
                fieldnames = flat_entry.keys()
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                first_entry = False

            writer.writerow(flat_entry)


def _parse_file_collect(path_str: str) -> Tuple[str, int, List[Dict]]:
    """
    Parse a single log file and return (filename, count, entries).
    Separated for multiprocessing pickling.
    """
    path = Path(path_str)
    entries: List[Dict] = []
    file_count = 0
    for entry in waf_process_log_file(path):
        file_count += 1
        entries.append(entry)
    return path.name, file_count, entries


def main():
    parser = argparse.ArgumentParser(description='Parse AWS WAF log files')
    parser.add_argument(
        '--input-dir',
        type=str,
        default='./logs/your-source/raw',
        help='Directory containing log files (default: ./logs/your-source/raw)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='./logs/your-source/parsed/parsed_logs.json',
        help='Output file path (default: ./logs/your-source/parsed/parsed_logs.json)'
    )
    parser.add_argument(
        '--format',
        choices=['json', 'csv'],
        default='json',
        help='Output format (default: json)'
    )
    parser.add_argument(
        '--pattern',
        type=str,
        default='*.log*',
        help='File pattern to match (default: *.log*)'
    )
    parser.add_argument(
        '--workers',
        type=int,
        default=0,
        help='Number of parallel workers (0 = cpu_count)'
    )

    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    if not input_dir.exists():
        print(f"Error: Input directory does not exist: {input_dir}", file=sys.stderr)
        sys.exit(1)

    # Find all log files
    log_files = []
    for pattern in [args.pattern, '*.log.gz', '*.log']:
        log_files.extend(input_dir.glob(pattern))

    # Remove duplicates
    log_files = list(set(log_files))

    if not log_files:
        print(f"No log files found in {input_dir}", file=sys.stderr)
        sys.exit(1)

    # Determine output path
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = Path(args.input_dir) / f"parsed_logs.{args.format}"

    # Check for incremental parsing - only process files newer than output
    existing_entries = []
    files_to_process = []
    output_mtime = output_path.stat().st_mtime if output_path.exists() else 0

    if output_path.exists():
        print(f"Found existing parsed file: {output_path}")
        print(f"Checking which files need to be (re)parsed...")

        # Load existing entries if we're doing incremental parsing
        try:
            if args.format == 'json':
                with open(output_path, 'r') as f:
                    existing_entries = json.load(f)
                print(f"  Loaded {len(existing_entries):,} existing entries")
            # For CSV, we'd need to load it differently, but JSON is the default
        except Exception as e:
            print(f"  Warning: Could not load existing file: {e}")
            print(f"  Will reparse all files")
            existing_entries = []

        # Check which files need processing
        for log_file in sorted(log_files):
            file_mtime = log_file.stat().st_mtime
            if file_mtime > output_mtime:
                files_to_process.append(log_file)
            else:
                print(f"  Skipping {log_file.name} (already parsed)")
    else:
        # No existing file, process all
        files_to_process = log_files
        print(f"Found {len(log_files)} log file(s) to parse")

    if not files_to_process:
        print(f"All files already parsed. No new files to process.")
        print(f"Total entries: {len(existing_entries):,}")
        return

    print(f"Parsing {len(files_to_process)} new/changed file(s)...")
    workers = args.workers if args.workers and args.workers > 0 else cpu_count()
    print(f"Using {workers} worker(s) for parsing...")

    new_entries: List[Dict] = []
    new_count = 0

    file_paths = [str(p) for p in sorted(files_to_process)]
    with Pool(processes=workers) as pool:
        for file_name, file_count, entries in pool.imap(_parse_file_collect, file_paths):
            new_count += file_count
            new_entries.extend(entries)
            print(f"  Processed: {file_name} ({file_count} entries)")

    # Merge with existing entries
    if existing_entries:
        print(f"Merging {len(new_entries):,} new entries with {len(existing_entries):,} existing entries...")
        all_entries = existing_entries + new_entries
    else:
        all_entries = new_entries

    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Save merged output
    print(f"Saving {len(all_entries):,} total entries to {output_path}...")
    if args.format == 'json':
        with open(output_path, 'w') as f:
            json.dump(all_entries, f, indent=2)
    else:
        save_csv_streaming(all_entries, output_path)

    print(f"\nTotal entries parsed: {len(all_entries):,}")
    if new_entries:
        print(f"  New entries: {len(new_entries):,}")
    if existing_entries:
        print(f"  Existing entries: {len(existing_entries):,}")

    print("Done!")


if __name__ == '__main__':
    main()

