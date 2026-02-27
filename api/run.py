"""Entry point for running the PISC API server.

Usage:
    python -m pisc.api.run
    or
    uvicorn pisc.api.main:app --reload --port 8000
"""

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "pisc.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
