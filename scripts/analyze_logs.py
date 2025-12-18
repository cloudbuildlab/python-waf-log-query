#!/usr/bin/env python3
"""
AWS WAF Log Analytics
Generates analytics reports from parsed WAF log data.
"""

import json
import csv
import argparse
import sys
import random
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
import pandas as pd
import numpy as np

# Allow importing shared analytics helpers
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.analyze.analytics import analyze_waf


def load_data_chunked(input_path: Path, chunk_size: int = 100000):
    """
    Load parsed log data in chunks (memory-efficient for large files).

    Args:
        input_path: Path to input file
        chunk_size: Number of entries to load per chunk

    Yields:
        Chunks of log entries
    """
    if input_path.suffix == '.json':
        # For JSON, we need to parse incrementally
        # This is a simplified approach - for very large files, consider using ijson
        with open(input_path, 'r') as f:
            data = json.load(f)
            if not isinstance(data, list):
                raise ValueError("JSON file must contain a list of entries")

            # Yield in chunks
            for i in range(0, len(data), chunk_size):
                yield data[i:i + chunk_size]
    elif input_path.suffix == '.csv':
        # For CSV, use pandas chunking
        for chunk in pd.read_csv(input_path, chunksize=chunk_size):
            # Convert query_params string back to dict if needed
            if 'query_params' in chunk.columns:
                chunk['query_params'] = chunk['query_params'].apply(
                    lambda x: json.loads(x) if isinstance(x, str) else {}
                )
            yield chunk.to_dict('records')
    else:
        raise ValueError(f"Unsupported file format: {input_path.suffix}")


def load_data(input_path: Path, use_chunked: bool = False) -> List[Dict]:
    """
    Load parsed log data from JSON or CSV file.

    Args:
        input_path: Path to input file
        sample_size: If specified, randomly sample this many entries
        sample_percent: If specified, randomly sample this percentage of entries (0.0-1.0)

    Returns:
        List of log entries
    """
    if use_chunked:
        # Use chunked processing - collect all chunks
        all_entries = []
        for chunk in load_data_chunked(input_path):
            all_entries.extend(chunk)
        entries = all_entries
    elif input_path.suffix == '.json':
        # For large JSON files, check size and use chunked if needed
        file_size = input_path.stat().st_size
        file_size_mb = file_size / (1024 * 1024)

        if file_size_mb > 500:  # If file is > 500MB, use chunked loading
            print(f"Large file detected ({file_size_mb:.1f} MB). Using chunked processing...", file=sys.stderr)
            all_entries = []
            for chunk in load_data_chunked(input_path):
                all_entries.extend(chunk)
            entries = all_entries
        else:
            with open(input_path, 'r') as f:
                entries = json.load(f)
    elif input_path.suffix == '.csv':
        # For CSV, use pandas with chunking for large files
        file_size = input_path.stat().st_size
        file_size_mb = file_size / (1024 * 1024)

        if file_size_mb > 500:
            print(f"Warning: Large file detected ({file_size_mb:.1f} MB). Loading in chunks...", file=sys.stderr)
            # Read in chunks and combine
            chunks = []
            for chunk in pd.read_csv(input_path, chunksize=100000):
                chunks.append(chunk)
            df = pd.concat(chunks, ignore_index=True)
        else:
            df = pd.read_csv(input_path)

        # Convert query_params string back to dict if needed
        if 'query_params' in df.columns:
            df['query_params'] = df['query_params'].apply(
                lambda x: json.loads(x) if isinstance(x, str) else {}
            )
        entries = df.to_dict('records')
    else:
        raise ValueError(f"Unsupported file format: {input_path.suffix}")

    return entries


def filter_by_time(entries: List[Dict], last_hours: float) -> List[Dict]:
    """
    Filter entries to only include those from the last N hours.

    Args:
        entries: List of log entries
        last_hours: Number of hours to look back (e.g., 1.0 for last hour)

    Returns:
        Filtered list of entries
    """
    if not entries or last_hours is None:
        return entries

    # Get current time in UTC
    now = datetime.now(timezone.utc)
    cutoff_time = now - timedelta(hours=last_hours)

    filtered = []
    for entry in entries:
        timestamp_str = entry.get('timestamp')
        if not timestamp_str:
            continue

        try:
            # Parse timestamp (handle both ISO format and other formats)
            if isinstance(timestamp_str, str):
                # Try ISO format first
                try:
                    entry_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                except ValueError:
                    # Try other common formats
                    try:
                        entry_time = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S')
                        # Assume UTC if no timezone info
                        entry_time = entry_time.replace(tzinfo=timezone.utc)
                    except ValueError:
                        continue
            else:
                continue

            # Filter entries within the time window
            if entry_time >= cutoff_time:
                filtered.append(entry)
        except (ValueError, TypeError, AttributeError):
            # Skip entries with invalid timestamps
            continue

    return filtered


def filter_by_time(entries: List[Dict], last_hours: float) -> List[Dict]:
    """
    Filter entries to only include those from the last N hours.

    Args:
        entries: List of log entries
        last_hours: Number of hours to look back (e.g., 1.0 for last hour)

    Returns:
        Filtered list of entries
    """
    if not entries or last_hours is None:
        return entries

    # Get current time in UTC
    now = datetime.now(timezone.utc)
    cutoff_time = now - timedelta(hours=last_hours)

    filtered = []
    for entry in entries:
        timestamp_str = entry.get('timestamp')
        if not timestamp_str:
            continue

        try:
            # Parse timestamp (handle both ISO format and other formats)
            if isinstance(timestamp_str, str):
                # Try ISO format first
                try:
                    entry_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                except ValueError:
                    # Try other common formats
                    try:
                        entry_time = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S')
                        # Assume UTC if no timezone info
                        entry_time = entry_time.replace(tzinfo=timezone.utc)
                    except ValueError:
                        continue
            else:
                continue

            # Filter entries within the time window
            if entry_time >= cutoff_time:
                filtered.append(entry)
        except (ValueError, TypeError, AttributeError):
            # Skip entries with invalid timestamps
            continue

    return filtered


def analyze_traffic_patterns(entries: List[Dict]) -> Dict:
    """Analyze traffic patterns."""
    if not entries:
        return {}

    # Convert to DataFrame for easier analysis
    df = pd.DataFrame(entries)

    # Handle missing timestamps
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df_with_timestamp = df[df['timestamp'].notna()]

        if len(df_with_timestamp) > 0:
            df_with_timestamp = df_with_timestamp.copy()
            # Requests per hour
            df_with_timestamp.loc[:, 'hour'] = df_with_timestamp['timestamp'].dt.floor('h')
            requests_per_hour = df_with_timestamp.groupby('hour').size().to_dict()

            # Requests per day
            df_with_timestamp.loc[:, 'day'] = df_with_timestamp['timestamp'].dt.date
            requests_per_day = {str(k): int(v) for k, v in df_with_timestamp.groupby('day').size().to_dict().items()}
        else:
            requests_per_hour = {}
            requests_per_day = {}
    else:
        requests_per_hour = {}
        requests_per_day = {}

    # Popular endpoints (handle None values)
    if 'path' in df.columns:
        endpoint_counts = df['path'].dropna().value_counts().head(20).to_dict()
    else:
        endpoint_counts = {}

    # Popular HTTP methods (handle None values)
    if 'http_method' in df.columns:
        method_counts = df['http_method'].dropna().value_counts().to_dict()
    else:
        method_counts = {}

    return {
        'total_requests': len(entries),
        'requests_per_hour': {str(k): int(v) for k, v in requests_per_hour.items()},
        'requests_per_day': requests_per_day,
        'popular_endpoints': {k: int(v) for k, v in endpoint_counts.items()},
        'http_methods': {k: int(v) for k, v in method_counts.items()}
    }


def analyze_errors(entries: List[Dict]) -> Dict:
    """Analyze error patterns."""
    if not entries:
        return {}

    df = pd.DataFrame(entries)

    # Status code distribution (handle None values)
    if 'status_code' in df.columns:
        status_counts = df['status_code'].dropna().value_counts().to_dict()
        df_with_status = df[df['status_code'].notna()]

        # Error rates
        total = len(df_with_status)
        error_4xx = len(df_with_status[df_with_status['status_code'].between(400, 499)])
        error_5xx = len(df_with_status[df_with_status['status_code'].between(500, 599)])

        # Most common errors
        error_entries = df_with_status[df_with_status['status_code'] >= 400]
        if 'path' in error_entries.columns:
            error_endpoints = error_entries['path'].dropna().value_counts().head(10).to_dict()
        else:
            error_endpoints = {}
    else:
        status_counts = {}
        total = 0
        error_4xx = 0
        error_5xx = 0
        error_endpoints = {}

    return {
        'status_code_distribution': {str(k): int(v) for k, v in status_counts.items()},
        'total_requests': int(total),
        'error_4xx_count': int(error_4xx),
        'error_4xx_rate': float(error_4xx / total * 100) if total > 0 else 0,
        'error_5xx_count': int(error_5xx),
        'error_5xx_rate': float(error_5xx / total * 100) if total > 0 else 0,
        'total_error_rate': float((error_4xx + error_5xx) / total * 100) if total > 0 else 0,
        'error_endpoints': {k: int(v) for k, v in error_endpoints.items()}
    }


def analyze_performance(entries: List[Dict]) -> Dict:
    """Analyze performance metrics."""
    if not entries:
        return {}

    df = pd.DataFrame(entries)

    # Cache hit/miss rates (handle None values)
    if 'cache_status' in df.columns:
        cache_counts = df['cache_status'].dropna().value_counts().to_dict()
        total = len(df[df['cache_status'].notna()])
        hit_count = cache_counts.get('hit', 0)
        miss_count = cache_counts.get('miss', 0)
    else:
        cache_counts = {}
        total = 0
        hit_count = 0
        miss_count = 0

    # Response size statistics (handle None values)
    if 'response_size' in df.columns:
        df_with_size = df[df['response_size'].notna()]
        if len(df_with_size) > 0:
            response_size_stats = {
                'mean': float(df_with_size['response_size'].mean()),
                'median': float(df_with_size['response_size'].median()),
                'min': int(df_with_size['response_size'].min()),
                'max': int(df_with_size['response_size'].max()),
                'p95': float(df_with_size['response_size'].quantile(0.95)),
                'p99': float(df_with_size['response_size'].quantile(0.99))
            }

            # Response size by endpoint
            if 'path' in df_with_size.columns:
                endpoint_sizes = df_with_size.groupby('path')['response_size'].agg(['mean', 'count']).to_dict('index')
                top_endpoints_by_size = dict(sorted(
                    endpoint_sizes.items(),
                    key=lambda x: x[1]['mean'],
                    reverse=True
                )[:10])
            else:
                top_endpoints_by_size = {}
        else:
            response_size_stats = {}
            top_endpoints_by_size = {}
    else:
        response_size_stats = {}
        top_endpoints_by_size = {}

    return {
        'cache_statistics': {k: int(v) for k, v in cache_counts.items()},
        'cache_hit_rate': float(hit_count / total * 100) if total > 0 else 0,
        'cache_miss_rate': float(miss_count / total * 100) if total > 0 else 0,
        'response_size_statistics': response_size_stats,
        'top_endpoints_by_size': {
            k: {'mean_size': float(v['mean']), 'request_count': int(v['count'])}
            for k, v in top_endpoints_by_size.items()
        }
    }


def analyze_user_agents(entries: List[Dict]) -> Dict:
    """Analyze user agent patterns."""
    if not entries:
        return {}

    df = pd.DataFrame(entries)

    # Top user agents (handle None values)
    if 'user_agent' in df.columns:
        top_user_agents = df['user_agent'].dropna().value_counts().head(20).to_dict()

        # Extract browser/agent type
        def extract_agent_type(ua):
            # Handle None, NaN, and empty values
            if pd.isna(ua) or ua is None or (isinstance(ua, str) and not ua):
                return 'Unknown'
            # Convert to string in case it's not already
            ua_str = str(ua) if not isinstance(ua, str) else ua
            ua_lower = ua_str.lower()
            if 'mozilla' in ua_lower and 'firefox' in ua_lower:
                return 'Firefox'
            elif 'chrome' in ua_lower and 'safari' in ua_lower:
                return 'Chrome'
            elif 'safari' in ua_lower and 'chrome' not in ua_lower:
                return 'Safari'
            elif 'python-requests' in ua_lower:
                return 'Python/requests'
            elif 'curl' in ua_lower:
                return 'curl'
            elif 'datadog' in ua_lower:
                return 'Datadog'
            else:
                return 'Other'

        df['agent_type'] = df['user_agent'].apply(extract_agent_type)
        agent_type_counts = df['agent_type'].value_counts().to_dict()
    else:
        top_user_agents = {}
        agent_type_counts = {}

    return {
        'top_user_agents': {k: int(v) for k, v in top_user_agents.items()},
        'agent_type_distribution': {k: int(v) for k, v in agent_type_counts.items()}
    }


def analyze_query_patterns(entries: List[Dict]) -> Dict:
    """Analyze query parameter patterns."""
    if not entries:
        return {}

    # Collect all query parameters
    param_counts = Counter()
    param_value_counts = defaultdict(Counter)

    for entry in entries:
        query_params = entry.get('query_params', {})
        if isinstance(query_params, str):
            try:
                query_params = json.loads(query_params)
            except:
                query_params = {}

        for param, value in query_params.items():
            param_counts[param] += 1
            param_value_counts[param][value] += 1

    # Most common parameters
    top_params = dict(param_counts.most_common(20))

    # Most common values for top parameters
    top_param_values = {}
    for param in list(top_params.keys())[:10]:
        top_param_values[param] = dict(param_value_counts[param].most_common(10))

    return {
        'most_common_parameters': {k: int(v) for k, v in top_params.items()},
        'parameter_value_distributions': {
            k: {vk: int(vv) for vk, vv in v.items()}
            for k, v in top_param_values.items()
        }
    }


def analyze_slowness_patterns(entries: List[Dict]) -> Dict:
    """Analyze patterns that might indicate slowness issues."""
    if not entries:
        return {}

    df = pd.DataFrame(entries)

    results = {}

    # 1. Time-based patterns (when does slowness occur?)
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df_with_time = df[df['timestamp'].notna()].copy()

        if len(df_with_time) > 0:
            df_with_time['hour'] = df_with_time['timestamp'].dt.hour
            df_with_time['day_of_week'] = df_with_time['timestamp'].dt.day_name()

            # Requests per hour (identify peak times)
            requests_by_hour = df_with_time.groupby('hour').size().to_dict()
            results['requests_by_hour'] = {int(k): int(v) for k, v in requests_by_hour.items()}

            # Requests by day of week
            requests_by_dow = df_with_time.groupby('day_of_week').size().to_dict()
            results['requests_by_day_of_week'] = {k: int(v) for k, v in requests_by_dow.items()}

    # 2. Cache miss patterns (cache misses are slower)
    if 'cache_status' in df.columns:
        df_with_cache = df[df['cache_status'].notna()].copy()
        if len(df_with_cache) > 0:
            # Cache miss rate by endpoint
            if 'path' in df_with_cache.columns:
                cache_by_endpoint = df_with_cache.groupby('path')['cache_status'].apply(
                    lambda x: (x == 'miss').sum() / len(x) * 100
                ).sort_values(ascending=False).head(20).to_dict()
                results['high_cache_miss_endpoints'] = {k: float(v) for k, v in cache_by_endpoint.items()}

            # Cache miss rate by hour (when are cache misses most common?)
            if 'timestamp' in df_with_cache.columns:
                df_with_cache['timestamp'] = pd.to_datetime(df_with_cache['timestamp'], errors='coerce')
                df_with_cache = df_with_cache[df_with_cache['timestamp'].notna()]
                if len(df_with_cache) > 0:
                    df_with_cache['hour'] = df_with_cache['timestamp'].dt.hour
                    cache_miss_by_hour = df_with_cache.groupby('hour').apply(
                        lambda x: (x['cache_status'] == 'miss').sum() / len(x) * 100,
                        include_groups=False
                    ).to_dict()
                    results['cache_miss_rate_by_hour'] = {int(k): float(v) for k, v in cache_miss_by_hour.items()}

    # 3. Large response sizes (could indicate slow endpoints)
    if 'response_size' in df.columns and 'path' in df.columns:
        df_with_size = df[df['response_size'].notna() & df['path'].notna()].copy()
        if len(df_with_size) > 0:
            # Endpoints with largest average response sizes
            large_responses = df_with_size.groupby('path')['response_size'].agg(['mean', 'count', 'max']).sort_values('mean', ascending=False).head(20)
            results['large_response_endpoints'] = {
                k: {
                    'mean_size': float(v['mean']),
                    'max_size': int(v['max']),
                    'request_count': int(v['count'])
                }
                for k, v in large_responses.to_dict('index').items()
            }

            # Very large responses (outliers)
            p99_size = df_with_size['response_size'].quantile(0.99)
            very_large = df_with_size[df_with_size['response_size'] > p99_size]
            if len(very_large) > 0:
                results['outlier_large_responses'] = {
                    'p99_threshold': float(p99_size),
                    'count': int(len(very_large)),
                    'percentage': float(len(very_large) / len(df_with_size) * 100),
                    'top_endpoints': very_large['path'].value_counts().head(10).to_dict()
                }

    # 4. Error correlation with slowness (errors might indicate slowness)
    if 'status_code' in df.columns and 'path' in df.columns:
        df_with_status = df[df['status_code'].notna() & df['path'].notna()].copy()
        if len(df_with_status) > 0:
            # Endpoints with high error rates (might be slow/failing)
            error_rates = df_with_status.groupby('path').apply(
                lambda x: (x['status_code'] >= 400).sum() / len(x) * 100,
                include_groups=False
            ).sort_values(ascending=False).head(20).to_dict()
            results['high_error_rate_endpoints'] = {k: float(v) for k, v in error_rates.items()}

            # 5xx errors by hour (server issues might cause slowness)
            if 'timestamp' in df_with_status.columns:
                df_with_status['timestamp'] = pd.to_datetime(df_with_status['timestamp'], errors='coerce')
                df_with_status = df_with_status[df_with_status['timestamp'].notna()]
                if len(df_with_status) > 0:
                    df_with_status['hour'] = df_with_status['timestamp'].dt.hour
                    server_errors_by_hour = df_with_status[df_with_status['status_code'] >= 500].groupby('hour').size().to_dict()
                    results['server_errors_by_hour'] = {int(k): int(v) for k, v in server_errors_by_hour.items()}

    # 5. Query parameter patterns that might cause slowness
    if 'query_params' in df.columns and 'path' in df.columns:
        # Find endpoints with complex queries (many parameters)
        complex_queries = []
        for entry in entries:
            query_params = entry.get('query_params', {})
            if isinstance(query_params, str):
                try:
                    query_params = json.loads(query_params)
                except:
                    query_params = {}

            param_count = len(query_params) if query_params else 0
            if param_count > 5:  # More than 5 parameters might indicate complex queries
                complex_queries.append({
                    'path': entry.get('path'),
                    'param_count': param_count,
                    'params': list(query_params.keys()) if query_params else []
                })

        if complex_queries:
            complex_df = pd.DataFrame(complex_queries)
            if len(complex_df) > 0:
                complex_by_endpoint = complex_df.groupby('path')['param_count'].agg(['mean', 'max', 'count']).sort_values('mean', ascending=False).head(20)
                results['complex_query_endpoints'] = {
                    k: {
                        'avg_params': float(v['mean']),
                        'max_params': int(v['max']),
                        'request_count': int(v['count'])
                    }
                    for k, v in complex_by_endpoint.to_dict('index').items()
                }

    # 6. IP address patterns (maybe certain IPs are causing slowness)
    if 'ip_address' in df.columns:
        df_with_ip = df[df['ip_address'].notna()].copy()
        if len(df_with_ip) > 0:
            # Top IPs by request volume (might indicate bots/crawlers causing load)
            top_ips = df_with_ip['ip_address'].value_counts().head(20).to_dict()
            results['top_request_ips'] = {k: int(v) for k, v in top_ips.items()}

            # Get user agent info for top IPs
            if 'user_agent' in df_with_ip.columns:
                top_ips_with_ua = {}
                for ip in list(top_ips.keys())[:10]:  # Top 10 IPs
                    ip_df = df_with_ip[df_with_ip['ip_address'] == ip]
                    if 'user_agent' in ip_df.columns:
                        # Get most common user agent for this IP
                        ua_counts = ip_df['user_agent'].dropna().value_counts()
                        if len(ua_counts) > 0:
                            top_ua = ua_counts.index[0]
                            top_ua_count = int(ua_counts.iloc[0])
                            total_for_ip = len(ip_df)
                            ua_percentage = (top_ua_count / total_for_ip * 100) if total_for_ip > 0 else 0

                            # If multiple user agents, show count
                            unique_ua_count = len(ua_counts)
                            if unique_ua_count > 1:
                                top_ua_display = f"{top_ua} ({unique_ua_count} unique UAs)"
                            else:
                                top_ua_display = top_ua

                            top_ips_with_ua[ip] = {
                                'request_count': int(top_ips[ip]),
                                'top_user_agent': top_ua_display,
                                'top_ua_count': top_ua_count,
                                'top_ua_percentage': float(ua_percentage),
                                'unique_ua_count': int(unique_ua_count)
                            }
                        else:
                            top_ips_with_ua[ip] = {
                                'request_count': int(top_ips[ip]),
                                'top_user_agent': 'Unknown',
                                'top_ua_count': 0,
                                'top_ua_percentage': 0.0,
                                'unique_ua_count': 0
                            }
                    else:
                        top_ips_with_ua[ip] = {
                            'request_count': int(top_ips[ip]),
                            'top_user_agent': 'N/A',
                            'top_ua_count': 0,
                            'top_ua_percentage': 0.0,
                            'unique_ua_count': 0
                        }
                results['top_request_ips_with_ua'] = top_ips_with_ua

            # Requests per minute by IP (rate-based analysis)
            if 'timestamp' in df_with_ip.columns:
                df_with_ip['timestamp'] = pd.to_datetime(df_with_ip['timestamp'], errors='coerce')
                df_with_ip = df_with_ip[df_with_ip['timestamp'].notna()]
                if len(df_with_ip) > 0:
                    ip_rates = {}
                    for ip in df_with_ip['ip_address'].unique():
                        ip_df = df_with_ip[df_with_ip['ip_address'] == ip]
                        if len(ip_df) > 1:
                            # Calculate time span
                            min_time = ip_df['timestamp'].min()
                            max_time = ip_df['timestamp'].max()
                            time_span = (max_time - min_time).total_seconds() / 60.0  # Convert to minutes

                            # Calculate requests per minute
                            if time_span > 0:
                                requests_per_min = len(ip_df) / time_span
                            else:
                                # If all requests are at the same time, use 1 minute as minimum
                                requests_per_min = len(ip_df) / 1.0

                            ip_rates[ip] = {
                                'requests_per_minute': float(requests_per_min),
                                'total_requests': int(len(ip_df)),
                                'time_span_minutes': float(time_span) if time_span > 0 else 1.0
                            }
                        else:
                            # Single request - assume 1 minute span
                            ip_rates[ip] = {
                                'requests_per_minute': float(len(ip_df)),
                                'total_requests': int(len(ip_df)),
                                'time_span_minutes': 1.0
                            }

                    # Sort by requests per minute and get top 10
                    top_ips_by_rate = dict(sorted(
                        ip_rates.items(),
                        key=lambda x: x[1]['requests_per_minute'],
                        reverse=True
                    )[:10])
                    results['top_ips_by_request_rate'] = top_ips_by_rate

    # 7. User agent patterns (certain clients might be slower)
    if 'user_agent' in df.columns and 'response_size' in df.columns:
        df_with_ua = df[df['user_agent'].notna() & df['response_size'].notna()].copy()
        if len(df_with_ua) > 0:
            # Average response size by user agent (some clients might get different responses)
            ua_response_sizes = df_with_ua.groupby('user_agent')['response_size'].agg(['mean', 'count']).sort_values('mean', ascending=False).head(10).to_dict('index')
            results['user_agent_response_sizes'] = {
                k: {'mean_size': float(v['mean']), 'request_count': int(v['count'])}
                for k, v in ua_response_sizes.items()
            }

    return results


def generate_report(analytics: Dict, output_format: str, output_path: Optional[Path] = None):
    """Generate and output analytics report."""
    if output_format == 'json':
        output = json.dumps(analytics, indent=2)
        if output_path:
            with open(output_path, 'w') as f:
                f.write(output)
        else:
            print(output)
    elif output_format == 'console':
        print("\n" + "="*80)
        print("WAF LOG ANALYTICS REPORT")
        print("="*80)

        # Traffic Patterns
        if 'traffic' in analytics:
            tp = analytics['traffic']
            print("\n## Traffic Patterns")
            print(f"Total Requests: {tp.get('total_requests', 0):,}")
            print(f"\nHTTP Methods:")
            for method, count in tp.get('http_methods', {}).items():
                print(f"  {method}: {count:,}")
            print(f"\nTop 10 Endpoints:")
            for endpoint, count in list(tp.get('popular_endpoints', {}).items())[:10]:
                print(f"  {endpoint}: {count:,}")

        # Error Analysis
        if 'errors' in analytics:
            err = analytics['errors']
            print("\n## Error Analysis")
            print(f"Total Requests: {err.get('total_requests', 0):,}")
            print(f"4xx Errors: {err.get('error_4xx_count', 0):,} ({err.get('error_4xx_rate', 0):.2f}%)")
            print(f"5xx Errors: {err.get('error_5xx_count', 0):,} ({err.get('error_5xx_rate', 0):.2f}%)")
            print(f"Total Error Rate: {err.get('total_error_rate', 0):.2f}%")
            print(f"\nStatus Code Distribution:")
            for code, count in sorted(err.get('status_code_distribution', {}).items()):
                print(f"  {code}: {count:,}")

        # Top IPs (all and error-only) derived from slowness block
        slow = analytics.get('slowness_investigation', {})
        top_ips_all = list(slow.get('top_request_ips', {}).items())[:10]
        top_ips_err = list(slow.get('top_error_ips', {}).items())[:10]

        # Fallback to direct counts if slowness didn't populate
        if not top_ips_all and 'top_ips_all' in analytics:
            top_ips_all = list(analytics['top_ips_all'].items())
        if not top_ips_err and 'top_ips_error' in analytics:
            top_ips_err = list(analytics['top_ips_error'].items())

        if top_ips_all:
            print("\nTop Client IPs (all requests):")
            for ip, count in top_ips_all:
                print(f"  {ip}: {count:,}")

        if top_ips_err:
            print("\nTop Client IPs (errors >= 400):")
            for ip, count in top_ips_err:
                print(f"  {ip}: {count:,}")

        # Performance
        if 'performance' in analytics:
            perf = analytics['performance']
            print("\n## Performance Metrics")
            rs = perf.get('response_size_statistics', {})
            print(f"\nResponse Size Statistics:")
            print(f"  Mean: {rs.get('mean', 0):.2f} bytes")
            print(f"  Median: {rs.get('median', 0):.2f} bytes")
            print(f"  P95: {rs.get('p95', 0):.2f} bytes")
            print(f"  P99: {rs.get('p99', 0):.2f} bytes")

        # User Agents
        if 'user_agents' in analytics:
            ua = analytics['user_agents']
            print("\n## User Agent Analysis")
            print(f"Agent Type Distribution:")
            for agent_type, count in ua.get('agent_type_distribution', {}).items():
                print(f"  {agent_type}: {count:,}")

        # Query Patterns
        if 'query_patterns' in analytics:
            qp = analytics['query_patterns']
            print("\n## Query Parameter Analysis")
            print(f"Most Common Parameters:")
            for param, count in list(qp.get('most_common_parameters', {}).items())[:10]:
                print(f"  {param}: {count:,}")

        # WAF-specific
        if 'waf' in analytics:
            waf = analytics['waf']
            print("\n## WAF Signals")
            if waf.get('actions'):
                print("Actions:")
                for action, count in waf['actions'].items():
                    print(f"  {action}: {count:,}")
            if waf.get('terminating_rules'):
                print("Top terminating rules:")
                for rule, count in list(waf['terminating_rules'].items())[:10]:
                    print(f"  {rule}: {count:,}")
            if waf.get('countries'):
                print("Top countries:")
                for c, count in list(waf['countries'].items())[:10]:
                    print(f"  {c}: {count:,}")

        # Slowness Investigation
        if 'slowness_investigation' in analytics:
            slow = analytics['slowness_investigation']
            print("\n## Slowness Investigation")

            # Time-based patterns
            if 'requests_by_hour' in slow:
                print("\n### Traffic by Hour (identify peak times)")
                peak_hours = sorted(slow['requests_by_hour'].items(), key=lambda x: x[1], reverse=True)[:5]
                for hour, count in peak_hours:
                    print(f"  Hour {hour:02d}:00 - {count:,} requests")

            if 'cache_miss_rate_by_hour' in slow:
                print("\n### Cache Miss Rate by Hour (cache misses are slower)")
                for hour in sorted(slow['cache_miss_rate_by_hour'].keys()):
                    rate = slow['cache_miss_rate_by_hour'][hour]
                    print(f"  Hour {hour:02d}:00 - {rate:.1f}% cache miss rate")

            # High cache miss endpoints
            if 'high_cache_miss_endpoints' in slow:
                print("\n### Endpoints with High Cache Miss Rates (>50%)")
                high_miss = {k: v for k, v in slow['high_cache_miss_endpoints'].items() if v > 50}
                if high_miss:
                    for endpoint, rate in sorted(high_miss.items(), key=lambda x: x[1], reverse=True)[:10]:
                        print(f"  {endpoint}: {rate:.1f}% miss rate")
                else:
                    print("  (No endpoints with >50% cache miss rate)")

            # Large response sizes
            if 'large_response_endpoints' in slow:
                print("\n### Endpoints with Largest Average Response Sizes")
                for endpoint, data in list(slow['large_response_endpoints'].items())[:10]:
                    size_mb = data['mean_size'] / (1024 * 1024)
                    print(f"  {endpoint}: {size_mb:.2f} MB avg ({data['request_count']:,} requests)")

            # Outlier large responses
            if 'outlier_large_responses' in slow:
                outlier = slow['outlier_large_responses']
                print(f"\n### Very Large Responses (Outliers)")
                print(f"  P99 threshold: {outlier['p99_threshold'] / (1024*1024):.2f} MB")
                print(f"  Outlier count: {outlier['count']:,} ({outlier['percentage']:.2f}% of requests)")
                if 'top_endpoints' in outlier and outlier['top_endpoints']:
                    print(f"  Top endpoints with outliers:")
                    for endpoint, count in list(outlier['top_endpoints'].items())[:5]:
                        print(f"    {endpoint}: {count:,}")

            # High error rate endpoints
            if 'high_error_rate_endpoints' in slow:
                print("\n### Endpoints with High Error Rates (might indicate slowness)")
                high_errors = {k: v for k, v in slow['high_error_rate_endpoints'].items() if v > 5}
                err_counts = slow.get('high_error_rate_endpoint_errors', {})
                totals = slow.get('high_error_rate_endpoint_totals', {})
                if high_errors:
                    for endpoint, rate in sorted(high_errors.items(), key=lambda x: x[1], reverse=True)[:10]:
                        err_count = err_counts.get(endpoint, 0)
                        total_count = totals.get(endpoint, 0)
                        # Always show counts to avoid missing data if keys are absent
                        if total_count > 0:
                            print(f"  {endpoint}: {rate:.1f}% error rate ({err_count}/{total_count} errors)")
                        else:
                            print(f"  {endpoint}: {rate:.1f}% error rate ({err_count} errors)")
                else:
                    print("  (No endpoints with >5% error rate)")

            # Server errors by hour
            if 'server_errors_by_hour' in slow and slow['server_errors_by_hour']:
                print("\n### Server Errors (5xx) by Hour")
                for hour in sorted(slow['server_errors_by_hour'].keys()):
                    count = slow['server_errors_by_hour'][hour]
                    print(f"  Hour {hour:02d}:00 - {count:,} server errors")

            # Complex queries
            if 'complex_query_endpoints' in slow:
                print("\n### Endpoints with Complex Queries (>5 parameters avg)")
                for endpoint, data in list(slow['complex_query_endpoints'].items())[:10]:
                    print(f"  {endpoint}: {data['avg_params']:.1f} avg params ({data['request_count']:,} requests)")

            # Top request IPs
            if 'top_request_ips' in slow:
                print("\n### Top Request IPs (might indicate bots/crawlers)")
                for ip, count in list(slow['top_request_ips'].items())[:10]:
                    print(f"  {ip}: {count:,} requests")

            # Top error IPs (status >= 400)
            if 'top_error_ips' in slow:
                print("\n### Top Error IPs (status >= 400)")
                for ip, count in list(slow['top_error_ips'].items())[:10]:
                    print(f"  {ip}: {count:,} errors")

            # Top IPs by request rate
            if 'top_ips_by_request_rate' in slow:
                print("\n### Top IPs by Request Rate (requests per minute)")
                for ip, data in list(slow['top_ips_by_request_rate'].items())[:10]:
                    rate = data['requests_per_minute']
                    total = data['total_requests']
                    time_span = data['time_span_minutes']
                    print(f"  {ip}: {rate:.2f} req/min ({total:,} total requests over {time_span:.1f} min)")

        print("\n" + "="*80)

        if output_path:
            # Also save JSON to file
            json_output = json.dumps(analytics, indent=2)
            with open(output_path, 'w') as f:
                f.write(json_output)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")


def main():
    parser = argparse.ArgumentParser(description='Analyze parsed AWS WAF log data')
    parser.add_argument(
        '--input',
        type=str,
        required=True,
        help='Input file (parsed JSON or CSV)'
    )
    parser.add_argument(
        '--output',
        type=str,
        help='Output file path (optional)'
    )
    parser.add_argument(
        '--format',
        choices=['json', 'console'],
        default='console',
        help='Output format (default: console)'
    )
    parser.add_argument(
        '--last-hours',
        type=float,
        help='Filter to only entries from the last N hours (e.g., 1.0 for last hour)'
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file does not exist: {input_path}", file=sys.stderr)
        sys.exit(1)

    # Check file size to determine processing strategy
    file_size = input_path.stat().st_size
    file_size_mb = file_size / (1024 * 1024)
    use_chunked = file_size_mb > 200  # Use chunked processing for files > 200MB

    if use_chunked:
        print(f"Large file detected ({file_size_mb:.1f} MB). Processing in chunks (memory-efficient)...")

        # Process in chunks and accumulate results
        all_entries = []
        chunk_count = 0
        total_entries = 0

        try:
            for chunk in load_data_chunked(input_path, chunk_size=50000):
                chunk_count += 1
                total_entries += len(chunk)

                # Apply time filter if specified
                if args.last_hours:
                    chunk = filter_by_time(chunk, args.last_hours)

                if chunk:
                    all_entries.extend(chunk)

                # Progress indicator
                if chunk_count % 10 == 0:
                    print(f"  Processed {chunk_count} chunks ({total_entries:,} entries so far)...", end='\r', file=sys.stderr)

            print(f"\nLoaded {len(all_entries):,} log entries from {total_entries:,} total", file=sys.stderr)
            entries = all_entries

        except MemoryError:
            print(f"\nError: Out of memory. File is too large to process.", file=sys.stderr)
            print(f"Consider using --last-hours to filter to recent entries only.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"\nError loading data: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            sys.exit(1)
    else:
        print(f"Loading data from {input_path}...")
        try:
            entries = load_data(input_path, use_chunked=False)
            print(f"Loaded {len(entries):,} log entries")
        except MemoryError:
            print(f"Error: Out of memory loading file.", file=sys.stderr)
            print(f"Try using --last-hours to filter to recent entries only.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error loading data: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            sys.exit(1)

        # Apply time filter if specified
        if args.last_hours:
            print(f"Filtering to last {args.last_hours} hour(s)...")
            entries = filter_by_time(entries, args.last_hours)
            print(f"Filtered to {len(entries):,} log entries")

    if not entries:
        print(f"Error: No entries to analyze after filtering", file=sys.stderr)
        sys.exit(1)

    print("Generating analytics...")
    try:
        analytics = {
            'traffic': analyze_traffic_patterns(entries),
            'errors': analyze_errors(entries),
            'performance': analyze_performance(entries),
            'user_agents': analyze_user_agents(entries),
            'query_patterns': analyze_query_patterns(entries),
            'slowness_investigation': analyze_slowness_patterns(entries),
            'waf': analyze_waf(entries),
        }

        # Ensure high-error endpoint counts are present (for console display)
        slow = analytics.get('slowness_investigation', {})
        if slow and 'high_error_rate_endpoints' in slow:
            from collections import Counter
            err_counts = Counter()
            totals = Counter()
            for e in entries:
                path = e.get('path')
                sc = e.get('status_code')
                if path:
                    totals[path] += 1
                    if sc is not None and sc >= 400:
                        err_counts[path] += 1
            # Only keep the endpoints already identified as high error
            endpoints = slow.get('high_error_rate_endpoints', {}).keys()
            slow['high_error_rate_endpoint_errors'] = {p: err_counts.get(p, 0) for p in endpoints}
            slow['high_error_rate_endpoint_totals'] = {p: totals.get(p, 0) for p in endpoints}
            analytics['slowness_investigation'] = slow

        # Add top IP summaries directly for console output
        ip_col = 'client_ip'
        if entries and ip_col not in entries[0]:
            ip_col = 'ip_address' if entries and 'ip_address' in entries[0] else None
        if ip_col:
            from collections import Counter
            top_all = Counter()
            top_err = Counter()
            for e in entries:
                ip = e.get(ip_col)
                if not ip:
                    continue
                top_all[ip] += 1
                sc = e.get('status_code')
                if sc is not None and sc >= 400:
                    top_err[ip] += 1
            analytics['top_ips_all'] = dict(top_all.most_common(10))
            analytics['top_ips_error'] = dict(top_err.most_common(10))
    except MemoryError:
        print(f"Error: Out of memory during analysis.", file=sys.stderr)
        print(f"Try using --last-hours to filter to recent entries only.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

    output_path = Path(args.output) if args.output else None
    generate_report(analytics, args.format, output_path)

    if output_path:
        print(f"\nReport saved to {output_path}")
    print("Done!")


if __name__ == '__main__':
    main()

