"""Entry point for running the PISC API server.

Usage:
    python -m api.run
    or
    uvicorn api.main:app --reload --port 8000
"""

import os
import sys
import argparse
from pathlib import Path

# Add the project root directory to Python path to ensure imports work
pisc_root = Path(__file__).parent.parent
sys.path.insert(0, str(pisc_root))

import uvicorn

# Security Configuration (A05)
# Default to localhost (127.0.0.1) instead of 0.0.0.0 for security
DEFAULT_HOST = os.getenv("HOST", "127.0.0.1")
DEFAULT_PORT = int(os.getenv("PORT", "8000"))


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="PISC API Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  python -m api.run
  python -m api.run --host 0.0.0.0 --port 9000
  python -m api.run --no-reload
        """,
    )

    parser.add_argument(
        "--host",
        type=str,
        default=DEFAULT_HOST,
        help=f"Host to bind to (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port to listen on (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--no-reload",
        action="store_true",
        help="Disable auto-reload (for production deployment)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload (development only, default: True if --no-reload not specified)",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    # Determine reload behavior
    reload = True
    if args.no_reload:
        reload = False
    elif args.reload:
        reload = True

    uvicorn.run(
        "api.main:app",
        host=args.host,  # A05: Bind to localhost by default
        port=args.port,
        reload=reload,
        # A05: Timeout settings
        timeout_keep_alive=30,
        limit_concurrency=100,
        limit_max_requests=1000,
    )
