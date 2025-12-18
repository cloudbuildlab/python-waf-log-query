#!/usr/bin/env python3
"""
AWS WAF Log Analytics
Generates analytics reports from parsed WAF log data.
"""

import json
import csv
import argparse
import sys
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Optional
import pandas as pd
import numpy as np


def load_data(input_path: Path) -> List[Dict]:
    """Load parsed log data from JSON or CSV file."""
    if input_path.suffix == '.json':
        with open(input_path, 'r') as f:
            return json.load(f)
    elif input_path.suffix == '.csv':
        df = pd.read_csv(input_path)
        # Convert query_params string back to dict if needed
        if 'query_params' in df.columns:
            df['query_params'] = df['query_params'].apply(
                lambda x: json.loads(x) if isinstance(x, str) else {}
            )
        return df.to_dict('records')
    else:
        raise ValueError(f"Unsupported file format: {input_path.suffix}")


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


def analyze_waf(entries: List[Dict]) -> Dict:
    """WAF-specific stats (actions, rules, sources, countries, TLS fingerprints)."""
    if not entries:
        return {}

    df = pd.DataFrame(entries)

    actions = df['action'].dropna().value_counts().to_dict() if 'action' in df.columns else {}
    rules = df['terminating_rule_id'].dropna().value_counts().to_dict() if 'terminating_rule_id' in df.columns else {}
    rule_types = df['terminating_rule_type'].dropna().value_counts().to_dict() if 'terminating_rule_type' in df.columns else {}
    countries = df['country'].dropna().value_counts().head(20).to_dict() if 'country' in df.columns else {}
    hosts = df['host'].dropna().value_counts().head(20).to_dict() if 'host' in df.columns else {}
    sources = df['http_source_name'].dropna().value_counts().to_dict() if 'http_source_name' in df.columns else {}
    client_ips = df['client_ip'].dropna().value_counts().head(20).to_dict() if 'client_ip' in df.columns else {}
    ja3 = df['ja3'].dropna().value_counts().head(20).to_dict() if 'ja3' in df.columns else {}
    ja4 = df['ja4'].dropna().value_counts().head(20).to_dict() if 'ja4' in df.columns else {}

    return {
        'actions': {k: int(v) for k, v in actions.items()},
        'terminating_rules': {k: int(v) for k, v in rules.items()},
        'terminating_rule_types': {k: int(v) for k, v in rule_types.items()},
        'countries': {k: int(v) for k, v in countries.items()},
        'hosts': {k: int(v) for k, v in hosts.items()},
        'http_sources': {k: int(v) for k, v in sources.items()},
        'client_ips': {k: int(v) for k, v in client_ips.items()},
        'ja3': {k: int(v) for k, v in ja3.items()},
        'ja4': {k: int(v) for k, v in ja4.items()},
    }


def create_query_signature(entry: Dict) -> str:
    """
    Create a unique signature for a query based on path and query parameters.

    Args:
        entry: Log entry dictionary

    Returns:
        Query signature string (path + sorted params)
    """
    path = entry.get('path', '')
    query_params = entry.get('query_params', {})

    if isinstance(query_params, str):
        try:
            query_params = json.loads(query_params)
        except:
            query_params = {}

    if query_params and isinstance(query_params, dict):
        # Sort parameters for consistent signatures
        sorted_params = sorted(query_params.items())
        param_str = '&'.join([f"{k}={v}" if v else k for k, v in sorted_params])
        return f"{path}?{param_str}" if param_str else path
    else:
        return path


def analyze_query_patterns(entries: List[Dict]) -> Dict:
    """Analyze query parameter patterns."""
    if not entries:
        return {}

    # Collect all query parameters
    param_counts = Counter()
    param_value_counts = defaultdict(Counter)
    query_signatures = Counter()

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

        # Track query signatures (path + params)
        query_sig = create_query_signature(entry)
        query_signatures[query_sig] += 1

    # Most common parameters
    top_params = dict(param_counts.most_common(20))

    # Most common values for top parameters
    top_param_values = {}
    for param in list(top_params.keys())[:10]:
        top_param_values[param] = dict(param_value_counts[param].most_common(10))

    # Top query signatures (unique queries)
    top_queries = dict(query_signatures.most_common(20))

    return {
        'most_common_parameters': {k: int(v) for k, v in top_params.items()},
        'parameter_value_distributions': {
            k: {vk: int(vv) for vk, vv in v.items()}
            for k, v in top_param_values.items()
        },
        'top_query_signatures': {k: int(v) for k, v in top_queries.items()}
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
            df_with_time['minute'] = df_with_time['timestamp'].dt.floor('min')
            df_with_time['five_min'] = df_with_time['timestamp'].dt.floor('5min')

            # Requests per hour (identify peak times)
            requests_by_hour = df_with_time.groupby('hour').size().to_dict()
            results['requests_by_hour'] = {int(k): int(v) for k, v in requests_by_hour.items()}

            # Peak hour detection
            if requests_by_hour:
                max_requests = max(requests_by_hour.values())
                peak_hours = [k for k, v in requests_by_hour.items() if v == max_requests]
                results['peak_hour'] = {
                    'hour': int(peak_hours[0]) if peak_hours else None,
                    'requests': int(max_requests)
                }

            # Requests per minute (to see spikes)
            requests_per_minute = df_with_time.groupby('minute').size().to_dict()
            results['requests_per_minute'] = {str(k): int(v) for k, v in requests_per_minute.items()}

            # Peak minute detection
            if requests_per_minute:
                max_requests = max(requests_per_minute.values())
                peak_minutes = [k for k, v in requests_per_minute.items() if v == max_requests]
                results['peak_minute'] = {
                    'time': str(peak_minutes[0]) if peak_minutes else None,
                    'requests': int(max_requests)
                }

            # Requests per 5-minute window (for rate of change analysis)
            requests_per_5min = df_with_time.groupby('five_min').size().to_dict()
            results['requests_per_5min'] = {str(k): int(v) for k, v in requests_per_5min.items()}

            # Calculate rate of change (spikes)
            if len(requests_per_5min) > 1:
                sorted_times = sorted(requests_per_5min.keys())
                rate_changes = []
                for i in range(1, len(sorted_times)):
                    prev_count = requests_per_5min[sorted_times[i-1]]
                    curr_count = requests_per_5min[sorted_times[i]]
                    if prev_count > 0:
                        rate_change = ((curr_count - prev_count) / prev_count) * 100
                        rate_changes.append({
                            'time': str(sorted_times[i]),
                            'rate_change_pct': float(rate_change),
                            'requests': int(curr_count)
                        })
                # Find largest spikes
                if rate_changes:
                    largest_spikes = sorted(rate_changes, key=lambda x: abs(x['rate_change_pct']), reverse=True)[:5]
                    results['largest_traffic_spikes'] = largest_spikes

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

                    # Hourly cache performance breakdown
                    hourly_cache = {}
                    for hour in df_with_cache['hour'].unique():
                        hour_df = df_with_cache[df_with_cache['hour'] == hour]
                        hour_cache_counts = hour_df['cache_status'].value_counts().to_dict()
                        hour_total = len(hour_df)
                        hourly_cache[int(hour)] = {
                            'hit_count': int(hour_cache_counts.get('hit', 0)),
                            'miss_count': int(hour_cache_counts.get('miss', 0)),
                            'hit_rate': float((hour_cache_counts.get('hit', 0) / hour_total) * 100) if hour_total > 0 else 0.0,
                            'miss_rate': float((hour_cache_counts.get('miss', 0) / hour_total) * 100) if hour_total > 0 else 0.0,
                        }
                    results['hourly_cache_performance'] = hourly_cache

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

            # Hourly response size breakdown
            if 'timestamp' in df_with_size.columns:
                df_with_size['timestamp'] = pd.to_datetime(df_with_size['timestamp'], errors='coerce')
                df_with_size = df_with_size[df_with_size['timestamp'].notna()]
                if len(df_with_size) > 0:
                    df_with_size['hour'] = df_with_size['timestamp'].dt.hour
                    hourly_sizes = {}
                    for hour in df_with_size['hour'].unique():
                        hour_df = df_with_size[df_with_size['hour'] == hour]
                        hour_sizes = hour_df['response_size'].dropna()
                        if len(hour_sizes) > 0:
                            hourly_sizes[int(hour)] = {
                                'mean_mb': float(hour_sizes.mean() / (1024 * 1024)),
                                'median_mb': float(hour_sizes.median() / (1024 * 1024)),
                                'p95_mb': float(hour_sizes.quantile(0.95) / (1024 * 1024)),
                            }
                    results['hourly_response_sizes'] = hourly_sizes

    # 4. Error correlation with slowness (errors might indicate slowness)
    if 'status_code' in df.columns and 'path' in df.columns:
        df_with_status = df[df['status_code'].notna() & df['path'].notna()].copy()
        if len(df_with_status) > 0:
            # Endpoints with high error rates (might be slow/failing)
            grouped = df_with_status.groupby('path')
            error_counts = grouped.apply(
                lambda x: (x['status_code'] >= 400).sum(),
                include_groups=False
            )
            total_counts = grouped.size()
            error_rates = ((error_counts / total_counts) * 100).sort_values(ascending=False).head(20)

            results['high_error_rate_endpoints'] = {k: float(v) for k, v in error_rates.to_dict().items()}
            results['high_error_rate_endpoint_errors'] = {k: int(error_counts[k]) for k in error_rates.index}
            results['high_error_rate_endpoint_totals'] = {k: int(total_counts[k]) for k in error_rates.index}

            # 5xx errors by hour (server issues might cause slowness)
            if 'timestamp' in df_with_status.columns:
                df_with_status['timestamp'] = pd.to_datetime(df_with_status['timestamp'], errors='coerce')
                df_with_status = df_with_status[df_with_status['timestamp'].notna()]
                if len(df_with_status) > 0:
                    df_with_status['hour'] = df_with_status['timestamp'].dt.hour
                    server_errors_by_hour = df_with_status[df_with_status['status_code'] >= 500].groupby('hour').size().to_dict()
                    results['server_errors_by_hour'] = {int(k): int(v) for k, v in server_errors_by_hour.items()}

                    # Hourly error breakdown
                    hourly_errors = {}
                    for hour in df_with_status['hour'].unique():
                        hour_df = df_with_status[df_with_status['hour'] == hour]
                        hour_total = len(hour_df)
                        hour_4xx = len(hour_df[(hour_df['status_code'] >= 400) & (hour_df['status_code'] < 500)])
                        hour_5xx = len(hour_df[(hour_df['status_code'] >= 500) & (hour_df['status_code'] < 600)])
                        hourly_errors[int(hour)] = {
                            'total': int(hour_total),
                            '4xx_count': int(hour_4xx),
                            '4xx_percentage': float((hour_4xx / hour_total) * 100) if hour_total > 0 else 0.0,
                            '5xx_count': int(hour_5xx),
                            '5xx_percentage': float((hour_5xx / hour_total) * 100) if hour_total > 0 else 0.0,
                        }
                    results['hourly_error_rates'] = hourly_errors

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
    ip_col = 'ip_address' if 'ip_address' in df.columns else ('client_ip' if 'client_ip' in df.columns else None)
    if ip_col:
        df_with_ip = df[df[ip_col].notna()].copy()
        if len(df_with_ip) > 0:
            # Top IPs by request volume (might indicate bots/crawlers causing load)
            top_ips = df_with_ip[ip_col].value_counts().head(20).to_dict()
            results['top_request_ips'] = {k: int(v) for k, v in top_ips.items()}

            # Get user agent info for top IPs
            if 'user_agent' in df_with_ip.columns:
                top_ips_with_ua = {}
                for ip in list(top_ips.keys())[:10]:  # Top 10 IPs
                    ip_df = df_with_ip[df_with_ip[ip_col] == ip]
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
                    for ip in df_with_ip[ip_col].unique():
                        ip_df = df_with_ip[df_with_ip[ip_col] == ip]
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

            # Top IPs by error volume (status >= 400)
            if 'status_code' in df_with_ip.columns:
                df_errors = df_with_ip[df_with_ip['status_code'].notna() & (df_with_ip['status_code'] >= 400)]
                if len(df_errors) > 0:
                    top_error_ips = df_errors[ip_col].value_counts().head(20).to_dict()
                    results['top_error_ips'] = {k: int(v) for k, v in top_error_ips.items()}

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


def analyze_endpoint(entries: List[Dict], endpoint: str) -> Dict:
    """
    Perform detailed analysis on a specific endpoint.

    Args:
        entries: List of log entries
        endpoint: Endpoint path to analyze

    Returns:
        Dictionary with detailed endpoint analysis
    """
    # Filter entries for this endpoint
    endpoint_entries = [
        e for e in entries
        if e.get('path') == endpoint
    ]

    if not endpoint_entries:
        return {'error': f'No entries found for endpoint: {endpoint}'}

    df = pd.DataFrame(endpoint_entries)

    results = {
        'endpoint': endpoint,
        'total_requests': len(endpoint_entries),
    }

    # Time-based analysis
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df_with_time = df[df['timestamp'].notna()].copy()

        if len(df_with_time) > 0:
            df_with_time['hour'] = df_with_time['timestamp'].dt.hour
            df_with_time['day'] = df_with_time['timestamp'].dt.date

            # Requests by hour
            requests_by_hour = df_with_time.groupby('hour').size().to_dict()
            results['requests_by_hour'] = {int(k): int(v) for k, v in requests_by_hour.items()}

            # Peak hours
            peak_hours = sorted(requests_by_hour.items(), key=lambda x: x[1], reverse=True)[:5]
            results['peak_hours'] = [{'hour': int(h), 'count': int(c)} for h, c in peak_hours]

    # Status codes and errors
    if 'status_code' in df.columns:
        df_with_status = df[df['status_code'].notna()].copy()
        status_counts = df_with_status['status_code'].value_counts().to_dict()
        results['status_codes'] = {str(k): int(v) for k, v in status_counts.items()}

        total = len(df_with_status)
        error_4xx = len(df_with_status[df_with_status['status_code'].between(400, 499)])
        error_5xx = len(df_with_status[df_with_status['status_code'].between(500, 599)])

        results['error_analysis'] = {
            'total': int(total),
            'error_4xx': int(error_4xx),
            'error_4xx_rate': float(error_4xx / total * 100) if total > 0 else 0,
            'error_5xx': int(error_5xx),
            'error_5xx_rate': float(error_5xx / total * 100) if total > 0 else 0,
        }

    # Response sizes
    if 'response_size' in df.columns:
        df_with_size = df[df['response_size'].notna()].copy()
        if len(df_with_size) > 0:
            results['response_size_stats'] = {
                'mean': float(df_with_size['response_size'].mean()),
                'median': float(df_with_size['response_size'].median()),
                'min': int(df_with_size['response_size'].min()),
                'max': int(df_with_size['response_size'].max()),
                'p95': float(df_with_size['response_size'].quantile(0.95)),
                'p99': float(df_with_size['response_size'].quantile(0.99)),
            }

    # Cache performance
    if 'cache_status' in df.columns:
        df_with_cache = df[df['cache_status'].notna()].copy()
        if len(df_with_cache) > 0:
            cache_counts = df_with_cache['cache_status'].value_counts().to_dict()
            total = len(df_with_cache)
            hit_count = cache_counts.get('hit', 0)
            miss_count = cache_counts.get('miss', 0)

            results['cache_analysis'] = {
                'total': int(total),
                'hit': int(hit_count),
                'miss': int(miss_count),
                'hit_rate': float(hit_count / total * 100) if total > 0 else 0,
                'miss_rate': float(miss_count / total * 100) if total > 0 else 0,
            }

    # Query parameters
    param_counts = Counter()
    param_value_counts = defaultdict(Counter)

    for entry in endpoint_entries:
        query_params = entry.get('query_params', {})
        if isinstance(query_params, str):
            try:
                query_params = json.loads(query_params)
            except:
                query_params = {}

        if query_params:
            for param, value in query_params.items():
                param_counts[param] += 1
                param_value_counts[param][value] += 1

    results['query_parameters'] = {
        'most_common': {k: int(v) for k, v in param_counts.most_common(10)},
        'parameter_values': {
            k: {vk: int(vv) for vk, vv in v.most_common(5)}
            for k, v in list(param_value_counts.items())[:5]
        }
    }

    return results


def analyze_daily_summary(entries: List[Dict]) -> Dict:
    """
    Analyze daily request totals with HTTP status code breakdown.

    Args:
        entries: List of log entries

    Returns:
        Dictionary with daily summary including status code breakdown
    """
    if not entries:
        return {'error': 'No entries found'}

    df = pd.DataFrame(entries)

    # Convert timestamp
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df[df['timestamp'].notna()]
    else:
        return {'error': 'No timestamp field found in logs'}

    # Extract date (day)
    df['date'] = df['timestamp'].dt.date

    results = {
        'total_requests': len(df),
        'date_range': {
            'start': str(df['date'].min()),
            'end': str(df['date'].max()),
        },
        'daily_summary': {}
    }

    # Group by date
    for date in sorted(df['date'].unique()):
        day_df = df[df['date'] == date]
        date_str = str(date)

        # Total requests for the day
        total_requests = len(day_df)

        # Status code breakdown
        status_breakdown = {}
        if 'status_code' in day_df.columns:
            status_counts = day_df['status_code'].dropna().value_counts().to_dict()
            status_breakdown = {int(k): int(v) for k, v in status_counts.items()}

            # Calculate percentages
            status_percentages = {}
            for code, count in status_breakdown.items():
                status_percentages[code] = float((count / total_requests) * 100) if total_requests > 0 else 0.0

            # Group by status code ranges
            status_ranges = {
                '1xx': sum(v for k, v in status_breakdown.items() if 100 <= k < 200),
                '2xx': sum(v for k, v in status_breakdown.items() if 200 <= k < 300),
                '3xx': sum(v for k, v in status_breakdown.items() if 300 <= k < 400),
                '4xx': sum(v for k, v in status_breakdown.items() if 400 <= k < 500),
                '5xx': sum(v for k, v in status_breakdown.items() if 500 <= k < 600),
            }

            status_range_percentages = {
                range_name: float((count / total_requests) * 100) if total_requests > 0 else 0.0
                for range_name, count in status_ranges.items()
            }
        else:
            status_breakdown = {}
            status_percentages = {}
            status_ranges = {}
            status_range_percentages = {}

        results['daily_summary'][date_str] = {
            'total_requests': int(total_requests),
            'status_codes': status_breakdown,
            'status_percentages': status_percentages,
            'status_ranges': status_ranges,
            'status_range_percentages': status_range_percentages,
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

        # Performance
        if 'performance' in analytics:
            perf = analytics['performance']
            print("\n## Performance Metrics")
            print(f"Cache Hit Rate: {perf.get('cache_hit_rate', 0):.2f}%")
            print(f"Cache Miss Rate: {perf.get('cache_miss_rate', 0):.2f}%")
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

        # Query Patterns
        if 'query_patterns' in analytics:
            qp = analytics['query_patterns']
            print("\n## Query Parameter Analysis")
            print(f"Most Common Parameters:")
            for param, count in list(qp.get('most_common_parameters', {}).items())[:10]:
                print(f"  {param}: {count:,}")

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
                if high_errors:
                    for endpoint, rate in sorted(high_errors.items(), key=lambda x: x[1], reverse=True)[:10]:
                        print(f"  {endpoint}: {rate:.1f}% error rate")
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

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file does not exist: {input_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading data from {input_path}...")
    entries = load_data(input_path)
    print(f"Loaded {len(entries):,} log entries")

    print("Generating analytics...")
    analytics = {
        'traffic': analyze_traffic_patterns(entries),
        'errors': analyze_errors(entries),
        'performance': analyze_performance(entries),
        'user_agents': analyze_user_agents(entries),
        'query_patterns': analyze_query_patterns(entries),
        'slowness_investigation': analyze_slowness_patterns(entries),
        'waf': analyze_waf(entries),
    }

    output_path = Path(args.output) if args.output else None
    generate_report(analytics, args.format, output_path)

    if output_path:
        print(f"\nReport saved to {output_path}")
    print("Done!")


if __name__ == '__main__':
    main()

