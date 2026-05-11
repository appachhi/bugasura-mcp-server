#!/bin/bash
# Setup script for Bugasura MCP Server
set -euo pipefail

echo "Setting up Bugasura MCP Server..."

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv .venv

if [ ! -f .venv/bin/activate ]; then
    echo "Error: .venv/bin/activate not found — venv creation failed. Aborting." >&2
    exit 1
fi

# Activate virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo ""
echo "Local development (STDIO):"
echo "  source .venv/bin/activate"
echo "  python server.py"
echo ""
echo "Production (Streamable HTTP, mounted at /mcp):"
echo "  source .venv/bin/activate"
echo "  python server.py --transport streamable-http --port 8000"
echo ""
