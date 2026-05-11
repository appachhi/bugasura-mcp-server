"""Shared configuration: environment variables + logging setup."""
import logging
import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

logger = logging.getLogger('bugasura_mcp')
logger.setLevel(logging.INFO)

_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
if not logger.handlers:
    _console = logging.StreamHandler()
    _console.setLevel(logging.DEBUG)
    _console.setFormatter(_formatter)
    logger.addHandler(_console)

    _log_path = os.getenv("LOG_PATH")
    if _log_path:
        os.makedirs(_log_path, exist_ok=True)
        _log_date = datetime.now().strftime("%Y-%m-%d")
        _dated_log_file = os.path.join(_log_path, f"bugasura-mcp-server.{_log_date}.log")
        _file_handler = logging.FileHandler(_dated_log_file)
        _file_handler.setLevel(logging.INFO)
        _file_handler.setFormatter(_formatter)
        logger.addHandler(_file_handler)
        logger.info(f"File logging enabled: {_dated_log_file}")

logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)

API_BASE = os.getenv("API_BASE_URL", "http://localhost/api.appachhi.com")
MCP_SERVER_NAME = os.getenv("MCP_SERVER_NAME", "bugasura_mcp")
BUGASURA_API_KEY = os.getenv("BUGASURA_API_KEY", "")

logger.info(f"MCP Server: {MCP_SERVER_NAME}")
