#!/usr/bin/env python3
"""
AWS WAFv2 Log Parser
Parses WAF Firehose-delivered NDJSON logs and normalizes fields for analytics.
"""

import argparse
import csv
import gzip
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

ACTION_STATUS_MAP = {
    "ALLOW": 200,
    "COUNT": 200,
    "EXCLUDED_AS_COUNT": 200,
    "BLOCK": 403,
    "CHALLENGE": 403,
    "CAPTCHA": 403,
}

def safe_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_query_params(args_str: Optional[str]) -> Dict[str, str]:
    if not args_str:
        return {}
    params = {}
    for part in args_str.split("&"):
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            params[k] = v
        else:
            params[part] = ""
    return params


def headers_to_map(headers_list):
    if not headers_list:
        return {}
    return {h.get("name", "").lower(): h.get("value") for h in headers_list if isinstance(h, dict)}


def parse_timestamp(ts) -> Optional[str]:
    """
    WAF logs use epoch millis in `timestamp`.
    """
    try:
        if ts is None:
            return None
        if isinstance(ts, (int, float)):
            dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
            return dt.isoformat()
        # fallback if already a string
        return datetime.fromisoformat(str(ts)).isoformat()
    except Exception:
        return None


def parse_waf_record(raw: Dict, source_file: str, line_number: int) -> Dict:
    http = raw.get("httpRequest", {}) or {}
    headers_map = headers_to_map(http.get("headers", []))

    query_string = http.get("args") or ""
    response_code = safe_int(raw.get("responseCodeSent"))
    action = raw.get("action")
    status_fallback = ACTION_STATUS_MAP.get(action, None)
    status_code = response_code if response_code is not None else status_fallback

    parsed = {
        "timestamp": parse_timestamp(raw.get("timestamp")),
        "action": action,
        "webacl_id": raw.get("webaclId"),
        "terminating_rule_id": raw.get("terminatingRuleId"),
        "terminating_rule_type": raw.get("terminatingRuleType"),
        "rule_group_list": raw.get("ruleGroupList", []),
        "rate_based_rule_list": raw.get("rateBasedRuleList", []),
        "non_terminating_rules": raw.get("nonTerminatingMatchingRules", []),
        "http_source_name": raw.get("httpSourceName"),
        "http_source_id": raw.get("httpSourceId"),
        "client_ip": http.get("clientIp"),
        "country": http.get("country"),
        "path": http.get("uri"),
        "query_string": query_string,
        "query_params": parse_query_params(query_string),
        "http_method": http.get("httpMethod"),
        "http_version": http.get("httpVersion"),
        "request_id": http.get("requestId"),
        "host": http.get("host") or headers_map.get("host"),
        "referrer": headers_map.get("referer"),
        "user_agent": headers_map.get("user-agent"),
        "headers": http.get("headers", []),
        "ja3": raw.get("ja3Fingerprint"),
        "ja4": raw.get("ja4Fingerprint"),
        "response_code": response_code,
        "status_code": status_code,
        "source_file": source_file,
        "line_number": line_number,
    }
    return parsed


def process_log_file(file_path: Path):
    """
    Process a log file (compressed or uncompressed) and yield parsed entries lazily.
    """
    opener = gzip.open if file_path.suffix == ".gz" else open
    try:
        with opener(file_path, "rt", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as e:
                    print(f"Error parsing JSON in {file_path} line {line_num}: {e}", file=sys.stderr)
                    continue
                entry = parse_waf_record(raw, str(file_path), line_num)
                if entry:
                    yield entry
    except Exception as e:
        print(f"Error processing {file_path}: {e}", file=sys.stderr)


def save_json_streaming(entries, output_path: Path):
    """Save parsed data as JSON using streaming (memory efficient)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write("[\n")
        first = True
        for entry in entries:
            if not first:
                f.write(",\n")
            json.dump(entry, f, indent=2)
            first = False
        f.write("\n]")


def save_csv_streaming(entries, output_path: Path):
    """Save parsed data as CSV using streaming (memory efficient)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    writer = None
    first_entry = True

    with open(output_path, "w", newline="") as f:
        for entry in entries:
            flat = entry.copy()
            flat["query_params"] = json.dumps(entry.get("query_params", {}))

            if first_entry:
                fieldnames = flat.keys()
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                first_entry = False

            writer.writerow(flat)


def main():
    parser = argparse.ArgumentParser(description="Parse AWS WAFv2 log files")
    parser.add_argument(
        "--input-dir",
        type=str,
        default="./logs/your-source/raw",
        help="Directory containing log files (default: ./logs/your-source/raw)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./logs/your-source/parsed/parsed_logs.json",
        help="Output file path (default: ./logs/your-source/parsed/parsed_logs.json)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--pattern",
        type=str,
        default="*.log*",
        help="File pattern to match (default: *.log*)",
    )

    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    if not input_dir.exists():
        print(f"Error: Input directory does not exist: {input_dir}", file=sys.stderr)
        sys.exit(1)

    log_files = []
    for pattern in [args.pattern, "*.log.gz", "*.log"]:
        log_files.extend(input_dir.glob(pattern))

    log_files = list(set(log_files))
    if not log_files:
        print(f"No log files found in {input_dir}", file=sys.stderr)
        sys.exit(1)

    output_path = Path(args.output) if args.output else Path(args.input_dir) / f"parsed_logs.{args.format}"

    print(f"Found {len(log_files)} log file(s)")
    print("Parsing logs (streaming)...")

    total_count = 0

    def all_entries():
        nonlocal total_count
        for log_file in sorted(log_files):
            print(f"  Processing: {log_file.name}")
            file_count = 0
            for entry in process_log_file(log_file):
                total_count += 1
                file_count += 1
                yield entry
            print(f"    Parsed {file_count} entries")

    print(f"Saving to {output_path}...")
    if args.format == "json":
        save_json_streaming(all_entries(), output_path)
    else:
        save_csv_streaming(all_entries(), output_path)

    print(f"\nTotal entries parsed: {total_count}")
    print("Done!")


if __name__ == "__main__":
    main()

