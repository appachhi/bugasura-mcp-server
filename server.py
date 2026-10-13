#!/usr/bin/env python3
"""
Bugasura MCP Server — entry point.

Server logic lives in the packages next to this file: `config/` (settings),
`core/` (FastMCP app, OAuth, upload links), `utils/` (API client, auth,
resolvers, formatting), `tools/` and `assistant_guides/` (prompts,
resources). This module only parses CLI arguments and dispatches to the
selected transport. Importing `tools` and `assistant_guides` triggers FastMCP
registration via decorator side-effects.
"""
import argparse, sys, uvicorn, assistant_guides, tools  # noqa: F401  (registration side effects)
from config.config import API_BASE, MCP_PUBLIC_BASE_URL, MCP_SERVER_NAME, logger, oauth_configured
from core.app import app, mcp


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
    parser.add_argument('--forwarded-allow-ips', default='127.0.0.1',
                        help='Reverse proxies whose X-Forwarded-* headers uvicorn should trust (default: 127.0.0.1)')
    parser.add_argument('--allow-insecure-http', action='store_true',
                        help='Allow an http:// MCP_PUBLIC_BASE_URL (local testing only; OAuth needs https in production)')
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("Bugasura MCP Server Starting")
    logger.info(f"Server Name: {MCP_SERVER_NAME}")
    logger.info(f"API Base URL: {API_BASE}")
    logger.info(f"Transport Mode: {args.transport}")
    logger.info("=" * 60)
    print(f"Bugasura MCP Server | Name: {MCP_SERVER_NAME} | API: {API_BASE} | Transport: {args.transport}", file=sys.stderr)

    if args.transport == 'streamable-http':
        # HTTP clients sign in with OAuth; without the front door every /mcp call would be anonymous.
        if not oauth_configured():
            msg = ("streamable-http requires the OAuth sign-in to be configured. Set MCP_PUBLIC_BASE_URL, "
                   "BUGASURA_OAUTH_CLIENT_ID and BUGASURA_OAUTH_CLIENT_SECRET (see README: Deploying the OAuth sign-in).")
            logger.critical(msg)
            print(f"ERROR: {msg}", file=sys.stderr)
            sys.exit(2)
        if not MCP_PUBLIC_BASE_URL.startswith("https://") and not args.allow_insecure_http:
            msg = (f"MCP_PUBLIC_BASE_URL={MCP_PUBLIC_BASE_URL} is not https. OAuth callbacks and consent cookies "
                   "need TLS; pass --allow-insecure-http for local testing only.")
            logger.critical(msg)
            print(f"ERROR: {msg}", file=sys.stderr)
            sys.exit(2)
        logger.info(f"Starting streamable-http server on {args.host}:{args.port}/mcp (public URL {MCP_PUBLIC_BASE_URL})")
        try:
            uvicorn.run(app, host=args.host, port=args.port, log_level="info",
                        proxy_headers=True, forwarded_allow_ips=args.forwarded_allow_ips)
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