#!/bin/bash

# Start Domain Analyzer Server
# Utopia Tech - www.utopiats.com

# Activate virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
else
    echo "❌ Virtual environment not found. Please run ./deploy.sh first"
    exit 1
fi

# Start server
echo "🚀 Starting Domain Analyzer..."
echo "📊 Access the application at: http://localhost:8000"
echo "📖 API Documentation: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
