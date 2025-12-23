# Domain Analyzer - Utopia Tech

A FastAPI-based web application for analyzing DNS records of domains from uploaded Excel files.

Developed by [Utopia Tech](https://www.utopiats.com)

## Setup

1. Create virtual environment:
```bash
python -m venv venv
```

2. Activate virtual environment:
```bash
# Windows
.\venv\Scripts\Activate.ps1
# Linux/Mac
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
uvicorn app.main:app --reload
```

5. Open your browser to: http://localhost:8000

## Features

- Upload Excel/CSV files containing domain names
- Analyze DNS records (MX, SPF, DMARC)
- Check website availability and www subdomain configuration
- Download results as Excel file
- Real-time progress tracking

## File Format

Upload files should contain a 'Domain' column with domain names to analyze.

## API Documentation

When running the application, visit http://localhost:8000/docs for interactive API documentation.