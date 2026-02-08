#!/bin/bash
# Quick Start Script for Dashboard Testing
# This runs the dashboard in FILE MODE (no API needed)

echo "🚀 Starting AIShield Dashboard (File Mode)"
echo "=========================================="
echo ""

# Navigate to dashboard directory
cd "$(dirname "$0")/../dashboard"

# Check if server.js exists
if [ ! -f "server.js" ]; then
    echo "❌ Error: server.js not found"
    echo "   Make sure you're in the AIShield root directory"
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Error: Node.js is not installed"
    echo "   Please install Node.js first"
    exit 1
fi

echo "✅ Found server.js"
echo "✅ Node.js is installed: $(node --version)"
echo ""

# Start the dashboard server
echo "🌐 Starting dashboard on http://localhost:3000"
echo "   Press Ctrl+C to stop"
echo ""

node server.js
