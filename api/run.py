"""Entry point for running the PISC API server.

Usage:
    python -m api.run
    or
    uvicorn api.main:app --reload --port 8000
"""

import os
import uvicorn

# Security Configuration (A05)
# Default to localhost (127.0.0.1) instead of 0.0.0.0 for security
DEFAULT_HOST = os.getenv("HOST", "127.0.0.1")
DEFAULT_PORT = int(os.getenv("PORT", "8000"))

if __name__ == "__main__":
    uvicorn.run(
        "api.main:app",
        host=DEFAULT_HOST,  # A05: Bind to localhost by default
        port=DEFAULT_PORT,
        reload=True,
        # A05: Timeout settings
        timeout_keep_alive=30,
        limit_concurrency=100,
        limit_max_requests=1000,
    )
