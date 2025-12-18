#!/usr/bin/env python3
"""
WAF Log Analytics Dashboard
Interactive Streamlit dashboard for analyzing AWS WAF log data.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import itertools
from datetime import datetime
from typing import Dict, List

from src.analyze.analytics import (
    load_data,
    analyze_traffic_patterns,
    analyze_errors,
    analyze_performance,
    analyze_user_agents,
    analyze_query_patterns,
    analyze_slowness_patterns,
    analyze_waf,
)
from src.utils.config_loader import load_config, get_enabled_sources

# Page configuration
st.set_page_config(
    page_title="WAF Log Analytics",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        margin-bottom: 1rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    </style>
""", unsafe_allow_html=True)


@st.cache_data
def load_log_data(file_path: Path) -> List[Dict]:
    """Load and cache log data."""
    return load_data(file_path)


def format_number(num: int) -> str:
    """Format large numbers with commas."""
    return f"{num:,}"


def create_time_series_chart(data: Dict[str, int], title: str, x_label: str = "Time", y_label: str = "Requests"):
    """Create a time series chart from data."""
    if not data:
        return None

    # Convert keys to datetime if possible
    try:
        times = [datetime.fromisoformat(k.replace('Z', '+00:00')) for k in data.keys()]
        df = pd.DataFrame({'time': times, 'count': list(data.values())})
        df = df.sort_values('time')
    except:
        # If datetime conversion fails, use as-is
        df = pd.DataFrame({'time': list(data.keys()), 'count': list(data.values())})

    fig = px.line(df, x='time', y='count', title=title)
    fig.update_layout(
        xaxis_title=x_label,
        yaxis_title=y_label,
        hovermode='x unified',
        height=400
    )
    return fig


def create_bar_chart(data: Dict, title: str, x_label: str = "Item", y_label: str = "Count", limit: int = 20):
    """Create a bar chart from data."""
    if not data:
        return None

    # Sort by value and limit
    sorted_data = dict(sorted(data.items(), key=lambda x: x[1], reverse=True)[:limit])

    df = pd.DataFrame({
        x_label: list(sorted_data.keys()),
        y_label: list(sorted_data.values())
    })

    fig = px.bar(df, x=x_label, y=y_label, title=title)
    fig.update_layout(
        xaxis_title=x_label,
        yaxis_title=y_label,
        height=400,
        xaxis={'categoryorder': 'total descending'}
    )
    return fig


def create_pie_chart(data: Dict, title: str):
    """Create a pie chart from data."""
    if not data:
        return None

    df = pd.DataFrame({
        'label': list(data.keys()),
        'value': list(data.values())
    })

    fig = px.pie(df, values='value', names='label', title=title)
    fig.update_layout(height=400)
    return fig


chart_counter = itertools.count()


def render_plotly(fig):
    """Render a plotly figure with a unique key to avoid duplicate element IDs."""
    if fig is None:
        return
    st.plotly_chart(fig, width="stretch", key=f"plotly-{next(chart_counter)}")


def main():
    st.title("📊 WAF Log Analytics Dashboard")

    # Sidebar for file selection
    st.sidebar.header("Configuration")

    # Get enabled sources from config
    try:
        sources = load_config()
        enabled_sources = get_enabled_sources(sources)

        # Build list of available parsed log files
        available_files = {}
        for name, config in enabled_sources.items():
            parsed_dir = config.get('parsed_dir', f"logs/{name}/parsed")
            output_file = f"{parsed_dir}/parsed_logs.json"
            available_files[name] = output_file

        # Source selection
        if available_files:
            selected_source = st.sidebar.selectbox(
                "Select Log Source",
                options=list(available_files.keys()),
                help="Choose which log source to analyze"
            )
            default_path = available_files[selected_source]
        else:
            # Fallback if no sources configured
            st.sidebar.info("No enabled sources in config; provide a custom path below.")
            default_path = ""
            selected_source = None
    except Exception as e:
        st.sidebar.warning(f"⚠️ Could not load config: {e}")
        default_path = ""
        selected_source = None

    # Allow custom path override
    custom_path = st.sidebar.text_input(
        "Custom Parsed Logs File Path (optional)",
        value="",
        help="Override with a custom path to a parsed JSON log file"
    )

    # Use custom path if provided, otherwise use selected source
    if custom_path and custom_path.strip():
        log_file_path = Path(custom_path.strip())
    elif default_path:
        log_file_path = Path(default_path)
    else:
        st.warning("Please provide a parsed log file path in the sidebar.")
        return

    if not log_file_path.exists():
        st.error(f"❌ Log file not found: {log_file_path}")
        st.info("💡 Make sure you've parsed your logs first using `python3 scripts/parse_logs.py`")
        return

    # Load data
    with st.spinner("Loading log data... This may take a moment for large files."):
        try:
            entries = load_log_data(log_file_path)
            st.sidebar.success(f"✅ Loaded {format_number(len(entries))} log entries")
        except Exception as e:
            st.error(f"❌ Error loading data: {e}")
            return

    if not entries:
        st.warning("⚠️ No log entries found in the file.")
        return

    # Generate analytics
    with st.spinner("Generating analytics..."):
        analytics = {
            'traffic': analyze_traffic_patterns(entries),
            'errors': analyze_errors(entries),
            'performance': analyze_performance(entries),
            'user_agents': analyze_user_agents(entries),
            'query_patterns': analyze_query_patterns(entries),
            'slowness': analyze_slowness_patterns(entries),
            'waf': analyze_waf(entries)
        }

    # Main metrics row
    st.markdown("---")
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Requests", format_number(analytics['traffic'].get('total_requests', 0)))

    with col2:
        error_rate = analytics['errors'].get('total_error_rate', 0)
        st.metric("Error Rate", f"{error_rate:.2f}%")

    with col3:
        cache_hit_rate = analytics['performance'].get('cache_hit_rate', 0)
        st.metric("Cache Hit Rate", f"{cache_hit_rate:.2f}%")

    with col4:
        error_4xx = analytics['errors'].get('error_4xx_count', 0)
        error_5xx = analytics['errors'].get('error_5xx_count', 0)
        st.metric("4xx/5xx Errors", f"{error_4xx}/{error_5xx}")

    st.markdown("---")

    # Tabs for different analytics sections
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "📈 Traffic", "❌ Errors", "⚡ Performance", "👤 User Agents", "🔍 Query Patterns", "🐌 Slowness", "🛡️ WAF"
    ])

    # Tab 1: Traffic Patterns
    with tab1:
        st.header("Traffic Patterns")

        col1, col2 = st.columns(2)

        with col1:
            # Requests per day
            if analytics['traffic'].get('requests_per_day'):
                fig = create_time_series_chart(
                    analytics['traffic']['requests_per_day'],
                    "Requests Per Day"
                )
                if fig:
                    render_plotly(fig)

        with col2:
            # Requests per hour
            if analytics['traffic'].get('requests_per_hour'):
                fig = create_time_series_chart(
                    analytics['traffic']['requests_per_hour'],
                    "Requests Per Hour"
                )
                if fig:
                    render_plotly(fig)

        # Popular endpoints
        if analytics['traffic'].get('popular_endpoints'):
            st.subheader("Top Endpoints")
            fig = create_bar_chart(
                analytics['traffic']['popular_endpoints'],
                "Most Requested Endpoints",
                "Endpoint",
                "Requests"
            )
            if fig:
                st.plotly_chart(fig, width='stretch')

        # HTTP methods
        if analytics['traffic'].get('http_methods'):
            st.subheader("HTTP Method Distribution")
            col1, col2 = st.columns([2, 1])
            with col1:
                fig = create_pie_chart(
                    analytics['traffic']['http_methods'],
                    "HTTP Methods"
                )
                if fig:
                    render_plotly(fig)
            with col2:
                st.dataframe(
                    pd.DataFrame({
                        'Method': list(analytics['traffic']['http_methods'].keys()),
                        'Count': list(analytics['traffic']['http_methods'].values())
                    }),
                    width='stretch'
                )

    # Tab 2: Error Analysis
    with tab2:
        st.header("Error Analysis")

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Status Code Distribution")
            if analytics['errors'].get('status_code_distribution'):
                fig = create_bar_chart(
                    analytics['errors']['status_code_distribution'],
                    "HTTP Status Codes",
                    "Status Code",
                    "Count"
                )
                if fig:
                    render_plotly(fig)

        with col2:
            st.subheader("Error Rates")
            error_data = {
                '4xx Errors': analytics['errors'].get('error_4xx_rate', 0),
                '5xx Errors': analytics['errors'].get('error_5xx_rate', 0),
                'Success (2xx/3xx)': 100 - analytics['errors'].get('total_error_rate', 0)
            }
            fig = create_pie_chart(error_data, "Error Rate Breakdown")
            if fig:
                st.plotly_chart(fig, width='stretch')

            st.metric("4xx Error Rate", f"{analytics['errors'].get('error_4xx_rate', 0):.2f}%")
            st.metric("5xx Error Rate", f"{analytics['errors'].get('error_5xx_rate', 0):.2f}%")

        # Error-prone endpoints
        if analytics['errors'].get('error_endpoints'):
            st.subheader("Most Error-Prone Endpoints")
            fig = create_bar_chart(
                analytics['errors']['error_endpoints'],
                "Endpoints with Most Errors",
                "Endpoint",
                "Error Count"
            )
            if fig:
                st.plotly_chart(fig, width='stretch')

        # Top client IPs (all requests) for quick visibility in Error tab
        if analytics['slowness'].get('top_request_ips'):
            st.subheader("Top 10 Client IPs (All Requests)")
            top_all = analytics['slowness']['top_request_ips']
            top_10_all = dict(sorted(top_all.items(), key=lambda x: x[1], reverse=True)[:10])

            col1, col2 = st.columns([2, 1])
            with col1:
                fig = create_bar_chart(
                    top_10_all,
                    "Top 10 Client IPs",
                    "IP Address",
                    "Request Count",
                    limit=10
                )
                if fig:
                    render_plotly(fig)
            with col2:
                df_all = pd.DataFrame({
                    'IP Address': list(top_10_all.keys()),
                    'Requests': list(top_10_all.values())
                })
                st.dataframe(df_all, width='stretch', hide_index=True)

        # Top client IPs by error volume
        if analytics['slowness'].get('top_error_ips'):
            st.subheader("Top 10 Client IPs by Error Volume (status ≥ 400)")
            top_err = analytics['slowness']['top_error_ips']
            top_10_err = dict(sorted(top_err.items(), key=lambda x: x[1], reverse=True)[:10])

            col1, col2 = st.columns([2, 1])
            with col1:
                fig = create_bar_chart(
                    top_10_err,
                    "Top 10 Error Client IPs",
                    "IP Address",
                    "Error Count",
                    limit=10
                )
                if fig:
                    render_plotly(fig)

            with col2:
                df_err = pd.DataFrame({
                    'IP Address': list(top_10_err.keys()),
                    'Errors (>=400)': list(top_10_err.values())
                })
                st.dataframe(df_err, width='stretch', hide_index=True)

    # Tab 3: Performance
    with tab3:
        st.header("Performance Metrics")

        st.subheader("Response Size Statistics")
        size_stats = analytics['performance'].get('response_size_statistics', {})
        if size_stats:
            metrics_data = {
                'Mean': f"{size_stats.get('mean', 0):,.0f} bytes",
                'Median': f"{size_stats.get('median', 0):,.0f} bytes",
                'P95': f"{size_stats.get('p95', 0):,.0f} bytes",
                'P99': f"{size_stats.get('p99', 0):,.0f} bytes",
                'Min': f"{size_stats.get('min', 0):,} bytes",
                'Max': f"{size_stats.get('max', 0):,} bytes"
            }
            cols = st.columns(3)
            labels = list(metrics_data.keys())
            for idx, (label, value) in enumerate(metrics_data.items()):
                with cols[idx % 3]:
                    st.metric(label, value)

        # Top endpoints by response size
        if analytics['performance'].get('top_endpoints_by_size'):
            st.subheader("Endpoints with Largest Response Sizes")
            endpoints_data = analytics['performance']['top_endpoints_by_size']
            df = pd.DataFrame([
                {
                    'Endpoint': endpoint,
                    'Mean Size (bytes)': int(data['mean_size']),
                    'Request Count': int(data['request_count'])
                }
                for endpoint, data in endpoints_data.items()
            ])
            st.dataframe(df, width='stretch', hide_index=True)

    # Tab 4: User Agents
    with tab4:
        st.header("User Agent Analysis")

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Top User Agents")
            if analytics['user_agents'].get('top_user_agents'):
                # Show top 10 in chart
                top_10 = dict(list(analytics['user_agents']['top_user_agents'].items())[:10])
                fig = create_bar_chart(
                    top_10,
                    "Top 10 User Agents",
                    "User Agent",
                    "Requests"
                )
                if fig:
                    render_plotly(fig)

        with col2:
            st.subheader("Agent Type Distribution")
            if analytics['user_agents'].get('agent_type_distribution'):
                fig = create_pie_chart(
                    analytics['user_agents']['agent_type_distribution'],
                    "User Agent Types"
                )
                if fig:
                    render_plotly(fig)

        # Full user agent list
        if analytics['user_agents'].get('top_user_agents'):
            st.subheader("All User Agents (Top 20)")
            df = pd.DataFrame({
                'User Agent': list(analytics['user_agents']['top_user_agents'].keys())[:20],
                'Count': list(analytics['user_agents']['top_user_agents'].values())[:20]
            })
            st.dataframe(df, width='stretch', hide_index=True)

    # Tab 5: Query Patterns
    with tab5:
        st.header("Query Parameter Patterns")

        if analytics['query_patterns'].get('most_common_parameters'):
            st.subheader("Most Common Query Parameters")
            fig = create_bar_chart(
                analytics['query_patterns']['most_common_parameters'],
                "Query Parameters Usage",
                "Parameter",
                "Occurrences"
            )
            if fig:
                st.plotly_chart(fig, width='stretch')

        # Parameter value distributions
        if analytics['query_patterns'].get('parameter_value_distributions'):
            st.subheader("Parameter Value Distributions")
            param_values = analytics['query_patterns']['parameter_value_distributions']

            selected_param = st.selectbox(
                "Select Parameter",
                options=list(param_values.keys())
            )

            if selected_param:
                fig = create_bar_chart(
                    param_values[selected_param],
                    f"Value Distribution for '{selected_param}'",
                    "Value",
                    "Count"
                )
                if fig:
                    render_plotly(fig)

    # Tab 6: Slowness Investigation
    with tab6:
        st.header("Slowness Investigation")

        col1, col2 = st.columns(2)

        with col1:
            if analytics['slowness'].get('requests_by_hour'):
                st.subheader("Requests by Hour")
                # Convert to proper format for chart
                hour_data = {f"{k:02d}:00": v for k, v in analytics['slowness']['requests_by_hour'].items()}
                fig = create_bar_chart(
                    hour_data,
                    "Request Volume by Hour",
                    "Hour",
                    "Requests"
                )
                if fig:
                    render_plotly(fig)

        with col2:
            if analytics['slowness'].get('requests_by_day_of_week'):
                st.subheader("Requests by Day of Week")
                fig = create_bar_chart(
                    analytics['slowness']['requests_by_day_of_week'],
                    "Request Volume by Day",
                    "Day",
                    "Requests"
                )
                if fig:
                    render_plotly(fig)

        # Large response endpoints
        if analytics['slowness'].get('large_response_endpoints'):
            st.subheader("Endpoints with Largest Response Sizes")
            large_resp = analytics['slowness']['large_response_endpoints']
            df = pd.DataFrame([
                {
                    'Endpoint': endpoint,
                    'Mean Size (bytes)': int(data['mean_size']),
                    'Max Size (bytes)': int(data['max_size']),
                    'Request Count': int(data['request_count'])
                }
                for endpoint, data in large_resp.items()
            ])
            st.dataframe(df, width='stretch', hide_index=True)

        # Top 10 Client IPs
        if analytics['slowness'].get('top_request_ips'):
            st.subheader("Top 10 Client IPs by Request Volume")
            st.markdown("**Identifying clients generating the most traffic can help detect bots, crawlers, or potential abuse.**")

            top_ips = analytics['slowness']['top_request_ips']
            # Get top 10
            top_10_ips = dict(sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:10])

            col1, col2 = st.columns([2, 1])

            with col1:
                fig = create_bar_chart(
                    top_10_ips,
                    "Top 10 Client IPs",
                    "IP Address",
                    "Request Count",
                    limit=10
                )
                if fig:
                    render_plotly(fig)

            with col2:
                # Table with top 10 IPs - include user agent if available
                if analytics['slowness'].get('top_request_ips_with_ua'):
                    ip_ua_data = analytics['slowness']['top_request_ips_with_ua']
                    df_ips = pd.DataFrame([
                        {
                            'IP Address': ip,
                            'Requests': data['request_count'],
                            'Top User Agent': data['top_user_agent'][:80] if len(data['top_user_agent']) > 80 else data['top_user_agent']  # Truncate long UAs
                        }
                        for ip, data in ip_ua_data.items()
                    ])
                else:
                    # Fallback if user agent data not available
                    df_ips = pd.DataFrame({
                        'IP Address': list(top_10_ips.keys()),
                        'Requests': list(top_10_ips.values())
                    })
                st.dataframe(df_ips, width='stretch', hide_index=True)

        # Top 10 Client IPs by Error Volume
        if analytics['slowness'].get('top_error_ips'):
            st.subheader("Top 10 Client IPs by Error Volume (status ≥ 400)")
            top_err = analytics['slowness']['top_error_ips']
            top_10_err = dict(sorted(top_err.items(), key=lambda x: x[1], reverse=True)[:10])

            col1, col2 = st.columns([2, 1])
            with col1:
                fig = create_bar_chart(
                    top_10_err,
                    "Top 10 Error Client IPs",
                    "IP Address",
                    "Error Count",
                    limit=10
                )
                if fig:
                    render_plotly(fig)

            with col2:
                df_err = pd.DataFrame({
                    'IP Address': list(top_10_err.keys()),
                    'Errors (>=400)': list(top_10_err.values())
                })
                st.dataframe(df_err, width='stretch', hide_index=True)

        # Top 10 IPs by Request Rate (requests per minute)
        if analytics['slowness'].get('top_ips_by_request_rate'):
            st.subheader("Top 10 Client IPs by Request Rate (Requests per Minute)")
            st.markdown("**IPs with high request rates may indicate automated traffic, bots, or potential abuse.**")

            ip_rates = analytics['slowness']['top_ips_by_request_rate']

            col1, col2 = st.columns([2, 1])

            with col1:
                # Create chart with requests per minute
                rate_data = {ip: data['requests_per_minute'] for ip, data in ip_rates.items()}
                fig = create_bar_chart(
                    rate_data,
                    "Top 10 IPs by Request Rate",
                    "IP Address",
                    "Requests per Minute",
                    limit=10
                )
                if fig:
                    render_plotly(fig)

            with col2:
                # Table with detailed metrics
                df_rates = pd.DataFrame([
                    {
                        'IP Address': ip,
                        'Req/min': f"{data['requests_per_minute']:.2f}",
                        'Total Requests': int(data['total_requests']),
                        'Time Span (min)': f"{data['time_span_minutes']:.1f}"
                    }
                    for ip, data in ip_rates.items()
                ])
                st.dataframe(df_rates, width='stretch', hide_index=True)

    # Tab 7: WAF Signals
    with tab7:
        st.header("WAF Signals")
        waf = analytics.get('waf', {})

        col1, col2 = st.columns(2)

        with col1:
            if waf.get('actions'):
                st.subheader("Actions")
                fig = create_bar_chart(waf['actions'], "Action Distribution", "Action", "Count")
                if fig:
                    render_plotly(fig)
            if waf.get('terminating_rules'):
                st.subheader("Top Terminating Rules")
                fig = create_bar_chart(waf['terminating_rules'], "Terminating Rules", "Rule", "Count")
                if fig:
                    render_plotly(fig)
            if waf.get('hosts'):
                st.subheader("Top Hosts")
                fig = create_bar_chart(waf['hosts'], "Hosts", "Host", "Requests")
                if fig:
                    render_plotly(fig)

        with col2:
            if waf.get('countries'):
                st.subheader("Top Countries")
                fig = create_bar_chart(waf['countries'], "Countries", "Country", "Requests")
                if fig:
                    render_plotly(fig)
            if waf.get('client_ips'):
                st.subheader("Top Client IPs")
                fig = create_bar_chart(waf['client_ips'], "Client IPs", "IP", "Requests")
                if fig:
                    st.plotly_chart(fig, width='stretch')
            if waf.get('ja3'):
                st.subheader("Top JA3")
                fig = create_bar_chart(waf['ja3'], "JA3 Fingerprints", "JA3", "Count")
                if fig:
                    st.plotly_chart(fig, width='stretch')
            if waf.get('ja4'):
                st.subheader("Top JA4")
                fig = create_bar_chart(waf['ja4'], "JA4 Fingerprints", "JA4", "Count")
                if fig:
                    st.plotly_chart(fig, width='stretch')


if __name__ == "__main__":
    main()

