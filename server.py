#!/usr/bin/env python3
"""
Bugasura MCP Server — entry point.

Server logic lives in the flat modules at the repo root (`app`, `client`,
`auth`, `helpers`, `tools/*`, `resources`, `prompts`). This module only parses
CLI arguments and dispatches to the selected transport. Importing `tools`,
`resources`, and `prompts` triggers FastMCP registration via decorator
side-effects.
"""
import argparse
import sys

import uvicorn

import prompts  # noqa: F401
import resources  # noqa: F401
import tools  # noqa: F401
from app import app, mcp
from config import API_BASE, logger


def main():
    """
    Run the MCP server with stdio or streamable HTTP transport.
    """
    parser = argparse.ArgumentParser(description='Bugasura MCP Server')
    parser.add_argument('--transport', choices=['stdio', 'streamable-http'], default='stdio',
                        help='Transport type: stdio (local dev) or streamable-http (recommended remote, mounted at /mcp)')
    parser.add_argument('--host', default='0.0.0.0',
                        help='Host to bind to for HTTP transports (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8000,
                        help='Port to bind to for HTTP transports (default: 8000)')
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("Bugasura MCP Server Starting")
    logger.info(f"API Base URL: {API_BASE}")
    logger.info(f"Transport Mode: {args.transport}")
    logger.info("=" * 60)
    print(f"Bugasura MCP Server | API: {API_BASE} | Transport: {args.transport}", file=sys.stderr)

    if args.transport == 'streamable-http':
        logger.info(f"Starting streamable-http server on {args.host}:{args.port}/mcp")
        try:
            uvicorn.run(app, host=args.host, port=args.port, log_level="info")
        except Exception as e:
            logger.critical(f"Failed to start HTTP server: {e}", exc_info=True)
            sys.exit(1)
    else:
        logger.info("Starting STDIO server (stdin/stdout communication)")
        try:
            mcp.run(transport='stdio')
        except KeyboardInterrupt:
            logger.info("Server stopped by user (Ctrl+C)")
        except Exception as e:
            logger.critical(f"Failed to start STDIO server: {e}", exc_info=True)
            sys.exit(1)


if __name__ == "__main__":
    main()