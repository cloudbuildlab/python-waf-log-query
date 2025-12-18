"""
Configuration loading utilities
"""

import sys
import yaml
from pathlib import Path
from typing import Dict

# Colors for output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color

# Default config path
DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "log_sources.yaml"

def load_config(config_path: Path = None) -> Dict:
    """Load log sources configuration from YAML file."""
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH

    if not config_path.exists():
        print(f"{Colors.RED}Error: Configuration file not found: {config_path}{Colors.NC}", file=sys.stderr)
        print(f"Please create {config_path} with log source definitions.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        if not config or 'log_sources' not in config:
            print(f"{Colors.RED}Error: Invalid configuration file format{Colors.NC}", file=sys.stderr)
            sys.exit(1)

        return config['log_sources']
    except yaml.YAMLError as e:
        print(f"{Colors.RED}Error: Failed to parse configuration file: {e}{Colors.NC}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}Error: Failed to load configuration: {e}{Colors.NC}", file=sys.stderr)
        sys.exit(1)

def get_enabled_sources(sources: Dict) -> Dict:
    """Get all enabled log sources."""
    return {name: config for name, config in sources.items()
            if config.get('enabled', False)}

