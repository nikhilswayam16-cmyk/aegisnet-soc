"""Command-line entry point."""

from __future__ import annotations

import argparse

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(prog="aegisnet", description="AegisNet SOC local server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="HTTP port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable development auto-reload")
    args = parser.parse_args()
    uvicorn.run("aegisnet.main:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
