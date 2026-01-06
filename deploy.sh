#!/bin/bash

# Domain Analyzer - Quick Deploy Script for Linux
# Utopia Tech - www.utopiats.com

set -e

echo "🚀 Domain Analyzer - Quick Deploy Script"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
   echo "❌ Please do not run as root"
   exit 1
fi

# Check Python version
echo "📋 Checking requirements..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

# Try to find the best Python version
if command -v python3.12 &> /dev/null; then
    PYTHON_CMD="python3.12"
elif command -v python3.11 &> /dev/null; then
    PYTHON_CMD="python3.11"
elif command -v python3.10 &> /dev/null; then
    PYTHON_CMD="python3.10"
else
    PYTHON_CMD="python3"
fi

PYTHON_VERSION=$($PYTHON_CMD --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "✅ Python $PYTHON_VERSION found (using $PYTHON_CMD)"

# Check for libmagic (Linux)
echo ""
echo "📋 Checking system dependencies..."
if ! ldconfig -p | grep -q libmagic; then
    echo "⚠️  libmagic not found. Installing..."
    sudo apt install -y libmagic1 2>/dev/null || sudo yum install -y file-libs 2>/dev/null || echo "⚠️  Please install libmagic manually"
else
    echo "✅ libmagic found"
fi

# Create virtual environment
echo ""
echo "🔧 Creating virtual environment..."
if [ ! -d "venv" ]; then
    $PYTHON_CMD -m venv venv
    echo "✅ Virtual environment created with $PYTHON_CMD"
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
echo ""
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo ""
echo "📦 Upgrading pip..."
pip install --upgrade pip -q

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
pip install -r requirements.txt -q
echo "✅ Dependencies installed"

# Create uploads directory
echo ""
echo "📁 Setting up directories..."
mkdir -p static/uploads
chmod 755 static/uploads
echo "✅ Directories configured"

# Success message
echo ""
echo "=========================================="
echo "✅ Installation Complete!"
echo "=========================================="
echo ""
echo "🎯 To start the server:"
echo "   source venv/bin/activate"
echo "   uvicorn app.main:app --host 0.0.0.0 --port 8000"
echo ""
echo "   Or simply run:"
echo "   ./start.sh"
echo ""
echo "📖 For production deployment, see INSTALLATION.md"
echo ""
