"""
wsgi.py - Entry point for production WSGI servers (Gunicorn) on Render.
Serves both the Flask API endpoints and the React production frontend from a single web service.
"""
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
backend_dir = HERE / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    app.run(host=host, port=port)
