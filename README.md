# python-waf-log-query

Python tool for syncing, parsing, and analyzing **AWS WAFv2** logs from S3 with a Streamlit dashboard, adapted to the WAF log format and S3 prefix layout.

## What it does

- Sync WAF log files from S3 (Firehose-delivered path layout).
- Parse NDJSON WAF records into normalized fields (action, rule, path, query params, country, client IP, JA3/JA4, etc).
- Run analytics (traffic, actions, rules, IPs, endpoints) with optional time-window filtering.
- Visualize results with a Streamlit dashboard.

## Quickstart

1. Copy the config template and edit:

   ```bash
   cp config/log_sources.yaml.example config/log_sources.yaml
   ```

   Set `s3_bucket` to your WAF Firehose prefix (replace with your bucket/account/region/web-acl), and adjust local/parsed dirs as needed.

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Sync logs (date or date+hour, UTC):

   ```bash
   python3 scripts/sync_logs.py --date 2025-12-16T22
   # or day range
   python3 scripts/sync_logs.py --start-date 2025-12-16 --end-date 2025-12-17
   ```

4. Parse to JSON:

   ```bash
   python3 scripts/parse_logs.py
   ```

5. Analyze (console or JSON output):

   ```bash
   python3 scripts/analyze_logs.py --input logs/your-source/parsed/parsed_logs.json --format console
   # filter last hour
   python3 scripts/analyze_logs.py --input logs/your-source/parsed/parsed_logs.json --last-hours 1.0
   ```

6. Dashboard:

   ```bash
   streamlit run dashboard/dashboard.py
   ```

## Notes

- Expected S3 layout: `AWSLogs/<account>/WAFLogs/<region>/<web-acl>/YYYY/MM/DD/HH/<file>.log.gz`.
- Parsed outputs and `config/log_sources.yaml` are gitignored; do not commit real logs or credentials.
- Uses standard AWS credential resolution; optionally set a profile in config.

## License

MIT

## ⚠️ Security Notice

**This tool processes log files that may contain sensitive information including:**

- IP addresses
- User agents
- Request paths and query parameters
- Response data
- Other potentially sensitive application data

**Please ensure:**

- Log files are stored securely and access is restricted
- Parsed log files are not committed to version control
- Configuration files with real bucket names/paths are gitignored
- Access to the dashboard and analytics is restricted to authorized personnel only

## Features

- **Date/hour S3 sync** for WAF Firehose prefixes
- **Incremental sync** (skips unchanged files)
- **WAF parsing**: NDJSON → structured JSON/CSV (action, rules, path, args, IP, UA, JA3/JA4)
- **Analytics**: traffic, errors, WAF actions/rules, IPs, endpoints, query params, slowness signals
- **Time-based filtering**: `--last-hours` for recent slices
- **Dashboard**: Streamlit UI with WAF tab
- **Modular**: run sync/parse/analyze separately or orchestrated

## Prerequisites

- **AWS CLI**: Required for S3 sync operations
  - Install: [https://aws.amazon.com/cli/](https://aws.amazon.com/cli/)
  - Configure credentials: `aws configure` or set environment variables
- **Python 3**: Required for parsing and analytics
- **Python packages**: Install with `pip install -r requirements.txt`

## Installation

1. Clone or download this repository
2. Install Python dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Create your configuration file:

   ```bash
   cp config/log_sources.yaml.example config/log_sources.yaml
   ```

   Then edit `config/log_sources.yaml` with your actual log source configurations (S3 buckets, paths, etc.). This file is gitignored and won't be committed.

4. Ensure AWS CLI is installed and configured with appropriate credentials

## Usage

### Full Pipeline (Sync → Parse → Analyze)

Run all operations in sequence:

**From date to today** (syncs logs from the specified date to today, inclusive):

```bash
python3 scripts/query_logs.py --date 2025-11-10
```

**Date range** (syncs logs from start date to end date, inclusive):

```bash
python3 scripts/query_logs.py --start-date 2025-11-10 --end-date 2025-11-12
```

**Note**: The `--date` parameter syncs logs from the specified date **to today** (in UTC, since logs are stored in UTC). To sync a specific date range, use `--start-date` and `--end-date`.

**Timezone Note**: All date operations use UTC to match the log file organization in S3. Log timestamps are preserved in UTC throughout parsing and analysis.

### Time-Based Filtering

Filter logs to analyze only entries from the last N hours:

**Analyze last hour from existing parsed logs** (no sync needed):

```bash
python3 scripts/query_logs.py --last-hours 1.0
```

**Sync, parse, and analyze with time filter**:

```bash
python3 scripts/query_logs.py --date 2025-11-23 --last-hours 1.0
```

**Other time filter examples**:

```bash
python3 scripts/query_logs.py --last-hours 0.5   # Last 30 minutes
python3 scripts/query_logs.py --last-hours 24.0  # Last 24 hours
python3 scripts/query_logs.py --last-hours 2.5   # Last 2.5 hours
```

**Note**: When using `--last-hours` without dates:

- If parsed logs exist, it will analyze them with the time filter
- If no parsed logs exist, it will automatically sync today's logs, parse them, then analyze with the time filter

### Individual Operations

#### Sync Only

Download logs from S3 without parsing or analyzing:

```bash
python3 scripts/query_logs.py --operation sync --start-date 2025-11-10 --end-date 2025-11-12
```

Or use the sync script directly:

```bash
python3 scripts/sync_logs.py --start-date 2025-11-10 --end-date 2025-11-12
```

#### Parse Only

Parse existing log files in the `logs/` directory:

```bash
python3 scripts/query_logs.py --operation parse
```

Or use the parser directly:

```bash
python3 scripts/parse_logs.py --input-dir ./logs/example-source-1/raw --output ./logs/example-source-1/parsed/parsed_logs.json
```

#### Analyze Only

Generate analytics from already-parsed logs:

```bash
python3 scripts/query_logs.py --operation analyze --parsed-output ./logs/example-source-1/parsed/parsed_logs.json
```

Or use the analyzer directly:

```bash
python3 scripts/analyze_logs.py --input ./logs/example-source-1/parsed/parsed_logs.json --format console
```

#### Interactive Dashboard

Launch the Streamlit dashboard for interactive visualization:

```bash
streamlit run dashboard/dashboard.py
```

The dashboard will open in your browser (typically at `http://localhost:8501`) and provides:

- **Traffic Patterns**: Requests over time, popular endpoints, HTTP method distribution
- **Error Analysis**: Status code breakdown, error rates, error-prone endpoints
- **Performance Metrics**: Cache hit/miss rates, response size statistics
- **User Agent Analysis**: Top user agents and agent type distribution
- **Query Patterns**: Most common query parameters and value distributions
- **Slowness Investigation**: Cache miss patterns, large response endpoints, peak traffic times, **top client IPs by request volume**

**New in Slowness Investigation**: Top client IPs analysis helps identify:

- Bots and crawlers generating high traffic
- Potential abuse or DDoS patterns
- Most active clients
- Security investigation

You can specify a custom parsed log file path in the dashboard sidebar.

## Command-Line Options

### query_logs.py

- `--start-date DATE`: Start date in YYYY-MM-DD format (required for sync)
- `--end-date DATE`: End date in YYYY-MM-DD format (required for sync)
- `--date DATE`: Start date in YYYY-MM-DD format (syncs from this date to today)
- `--operation OP`: Operation to perform: `sync`, `parse`, `analyze`, or `all` (default: `all`)
- `--parsed-output FILE`: Output file for parsed logs (default: first enabled source's parsed output)
- `--analytics-output FILE`: Output file for analytics report (optional)
- `--last-hours HOURS`: Filter to only entries from the last N hours (e.g., `1.0` for last hour). Only applies to analyze operation. If no parsed logs exist, automatically syncs today's logs first.

### sync_logs.sh

- `--start-date DATE`: Start date in YYYY-MM-DD format
- `--end-date DATE`: End date in YYYY-MM-DD format
- `--date DATE`: Start date in YYYY-MM-DD format (syncs from this date to today)
- `-h, --help`: Show help message

### parse_logs.py

- `--input-dir DIR`: Directory containing log files (default: `./logs/example-source-1/raw`)
- `--output FILE`: Output file path (default: `./logs/example-source-1/parsed/parsed_logs.json`)
- `--format FORMAT`: Output format: `json` or `csv` (default: `json`)
- `--pattern PATTERN`: File pattern to match (default: `*.log*`)

### analyze_logs.py

- `--input FILE`: Input file (parsed JSON or CSV) - **required**
- `--output FILE`: Output file path (optional)
- `--format FORMAT`: Output format: `json` or `console` (default: `console`)
- `--last-hours HOURS`: Filter to only entries from the last N hours (e.g., `1.0` for last hour)

### clear_logs.py

Utility script to clear all log files (raw and parsed):

- `--logs-dir DIR`: Path to logs directory (default: `./logs`)
- `--yes, -y`: Skip confirmation prompt

**Examples**:

```bash
python3 scripts/clear_logs.py              # Clear with confirmation
python3 scripts/clear_logs.py --yes        # Clear without confirmation
python3 scripts/clear_logs.py -y           # Short form
```

## Log Format (WAF)

The tool parses AWS WAF NDJSON logs emitted by Firehose. All timestamps are UTC epoch millis. Typical fields include `timestamp`, `action`, `terminatingRuleId`, `httpRequest.clientIp`, `httpRequest.uri`, `httpRequest.args`, headers (UA/Host/Referer), and optional JA3/JA4 fingerprints.

## Output Structure

### Parsed Logs (JSON)

Each WAF log entry is parsed into structured fields, for example:

```json
{
  "timestamp": "2025-12-16T01:00:00+00:00",
  "action": "BLOCK",
  "status_code": 403,
  "terminating_rule_id": "BlockedMethods",
  "http_method": "POST",
  "path": "/api/v1/events",
  "query_string": "token=abc",
  "query_params": { "token": "abc" },
  "client_ip": "198.51.100.10",
  "country": "NZ",
  "host": "example.org",
  "user_agent": "curl/8.0.1",
  "ja3": "...",
  "ja4": "...",
  "source_file": "..."
}
```

### Analytics Report

The analytics report includes:

- **Traffic Patterns**: Total requests, per-hour/day counts, popular endpoints, HTTP methods
- **Error Analysis**: Status code distribution, 4xx/5xx rates, error-prone endpoints
- **Performance Metrics**: Response size statistics
- **User Agent Analysis**: Top user agents, agent type distribution
- **Query Patterns**: Common parameters and value distributions
- **WAF Signals**: Actions, terminating rules, countries, top IPs, JA3/JA4
- **Slowness Investigation**: Peak times, error/endpoint correlations, large responses, top IPs

## File Structure

```plaintext
waf-log-query/
├── config/
│   ├── log_sources.yaml.example  # Example configuration template
│   └── log_sources.yaml           # Log source configurations (gitignored, copy from .example)
├── logs/                    # Local log storage (created automatically, gitignored)
│   └── example-source-1/
│       ├── raw/             # Raw log files from S3 (gitignored)
│       └── parsed/          # Parsed log files (JSON/CSV, gitignored)
├── dashboard/
│   └── dashboard.py        # Streamlit interactive dashboard
├── scripts/
│   ├── query_logs.py        # Main orchestration script
│   ├── sync_logs.py         # S3 sync script
│   ├── parse_logs.py        # Log parser
│   ├── analyze_logs.py      # Analytics engine
│   └── clear_logs.py         # Utility to clear all log files
├── src/                     # Source code modules
│   ├── sync/                # Sync implementations
│   ├── parse/               # Parsing logic
│   ├── analyze/             # Analysis functions
│   └── utils/               # Utility functions
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Troubleshooting

### AWS Credentials Not Configured

If you see an error about AWS credentials:

```bash
aws configure
```

Or set environment variables:

```bash
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=ap-southeast-2
```

### Python Dependencies Missing

Install required packages:

```bash
pip install -r requirements.txt
```

### No Log Files Found

Ensure:

1. The sync operation completed successfully
2. Log files are in the `logs/` directory
3. Files match the expected naming pattern (e.g., `2025-11-10T00:00:00.000--*.log.gz`)

### Security and Privacy

**Important considerations when working with log data:**

1. **Log files contain sensitive data**: IP addresses, user agents, request paths, and potentially sensitive query parameters
2. **Storage**: Ensure log files are stored securely with appropriate access controls
3. **Version control**: Never commit log files, parsed logs, or configuration files with real credentials/bucket names to git
4. **Access control**: Restrict access to the dashboard and analytics output to authorized personnel only
5. **Data retention**: Consider implementing data retention policies for log files
6. **Compliance**: Ensure log processing complies with your organization's data privacy policies and regulations

The `.gitignore` file is configured to exclude:

- `config/log_sources.yaml` (your actual configuration)
- `logs/` directory (all log files)
- Parsed log outputs

## Examples

### Example 1: Analyze logs from a date to today

```bash
python3 scripts/query_logs.py --date 2025-11-10  # Syncs from 2025-11-10 to today
```

### Example 2: Sync logs for a week, then analyze separately

```bash
# Sync
python3 scripts/query_logs.py --operation sync --start-date 2025-11-10 --end-date 2025-11-16

# Parse
python3 scripts/query_logs.py --operation parse

# Analyze with custom output
python3 scripts/query_logs.py --operation analyze --analytics-output ./reports/weekly_report.json
```

### Example 3: Parse and analyze existing logs

```bash
# Parse
python3 scripts/parse_logs.py --input-dir ./logs/example-source-1/raw --output ./logs/example-source-1/parsed/parsed.json --format json

# Analyze
python3 scripts/analyze_logs.py --input ./logs/example-source-1/parsed/parsed.json --format console --output ./reports/analysis.txt
```

### Example 4: Use the interactive dashboard

```bash
# First, parse your logs (if not already done)
python3 scripts/parse_logs.py --input-dir ./logs/example-source-1/raw --output ./logs/example-source-1/parsed/parsed_logs.json

# Then launch the dashboard
streamlit run dashboard/dashboard.py
```

The dashboard will automatically load the parsed logs and display interactive visualizations. You can change the log file path in the sidebar if needed.

### Example 5: Analyze last hour of logs

```bash
# Analyze last hour from existing parsed logs (no sync needed)
python3 scripts/query_logs.py --last-hours 1.0

# Or sync today's logs and analyze last hour
python3 scripts/query_logs.py --date 2025-11-23 --last-hours 1.0

# Analyze last 30 minutes
python3 scripts/query_logs.py --last-hours 0.5
```

### Example 6: Clear all logs

```bash
# Clear all log files with confirmation
python3 scripts/clear_logs.py

# Clear without confirmation
python3 scripts/clear_logs.py --yes
```

## License (internal use)

This tool is provided as-is for internal use.
