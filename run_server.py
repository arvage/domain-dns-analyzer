#!/usr/bin/env python
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    import uvicorn
    # Configure uvicorn to exclude venv directory from watching
    uvicorn.run(
        "app.main:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=True,
        reload_excludes=["venv/*", "*.pyc", "__pycache__/*"],
        reload_includes=["*.py", "*.html", "*.css"],
        reload_dirs=["."],
        log_level="info"
    )