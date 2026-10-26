"""
app.py - Flask backend for PhishGuard AI.

    python app.py                      -> http://127.0.0.1:5000
Endpoints
    GET  /api/health    server + model status
    POST /api/predict   body {"url": "..."}  -> prediction from the saved model
    GET  /api/report    real training/evaluation report (for the dashboard)

Environment variables
    FRONTEND_ORIGIN       allowed browser origin(s), comma separated (default: the Vite dev server on localhost / 127.0.0.1 :5173)
    PHISHGUARD_MODEL_DIR  folder with the saved model   (default backend/models)
    PHISHGUARD_REPORT_DIR folder with the reports       (default backend/reports)
    PORT                  port for `python app.py`      (default 5000)
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from feature_extractor import InvalidURLError
from predictor import ModelNotAvailableError, ModelService

HERE = Path(__file__).resolve().parent
log = logging.getLogger("phishguard.api")


def error(code: str, message: str, status: int):
    return jsonify({"error": {"code": code, "message": message}}), status


def create_app(model_dir=None, report_dir=None, frontend_origin=None, service=None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # a URL request never needs more than 16 KB
    origins = [o.strip().rstrip("/") for o in
               (frontend_origin or os.environ.get("FRONTEND_ORIGIN", "http://localhost:5173,http://127.0.0.1:5173")).split(",") if o.strip()]
    report_path = Path(report_dir or os.environ.get("PHISHGUARD_REPORT_DIR", HERE / "reports")) / "training_report.json"

    # the model is loaded ONCE here, never per request
    svc = service or ModelService(model_dir or os.environ.get("PHISHGUARD_MODEL_DIR", HERE / "models"))
    app.extensions["model_service"] = svc
    startup_error = None
    if not svc.loaded:
        try:
            svc.load()
        except ModelNotAvailableError as exc:
            startup_error = str(exc)
            log.error("Model not available: %s", exc)
    app.extensions["startup_error"] = startup_error

    @app.after_request
    def add_cors(resp):
        origin = request.headers.get("Origin", "").rstrip("/")
        if origin and origin in origins:  # only the configured frontend origin(s)
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Vary"] = "Origin"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
            resp.headers["Access-Control-Max-Age"] = "600"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/")
    def index():
        return jsonify({
            "service": "PhishGuard AI Backend",
            "status": "running",
            "health": "/api/health"
        })

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "model_loaded": svc.loaded,
                        "model": (svc.meta.get("model_name") if svc.loaded else None),
                        "message": None if svc.loaded else (app.extensions["startup_error"] or "Model is not loaded.")})

    @app.post("/api/predict")
    def predict():
        if not svc.loaded:
            return error("model_not_available", app.extensions["startup_error"] or "Model is not loaded. Run: python train.py", 503)
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or "url" not in data:
            return error("bad_request", 'Send JSON like {"url": "https://example.com"}.', 400)
        if not isinstance(data["url"], str):
            return error("bad_request", "The 'url' field must be text.", 400)
        try:
            result = svc.predict(data["url"])
        except InvalidURLError as exc:
            return error("invalid_url", str(exc), 422)
        except ModelNotAvailableError as exc:
            return error("model_not_available", str(exc), 503)
        log.info("prediction served: %s", result["prediction"])  # the URL itself is deliberately NOT logged
        return jsonify(result)

    @app.get("/api/report")
    def report():
        if not report_path.is_file():
            return error("report_not_available", "No training report found. Run: python train.py", 404)
        try:
            return jsonify(json.loads(report_path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            return error("report_unreadable", "The training report could not be read. Re-run: python train.py", 500)

    @app.errorhandler(HTTPException)
    def http_error(exc):
        messages = {404: "Endpoint not found.", 405: "Method not allowed for this endpoint.",
                    413: "Request is too large.", 415: "Send the request as JSON."}
        return error(exc.name.lower().replace(" ", "_"), messages.get(exc.code, exc.description), exc.code)

    @app.errorhandler(Exception)
    def unexpected(exc):
        log.exception("Unexpected error")
        return error("internal_error", "Something went wrong on the server.", 500)

    return app


app = create_app() if os.environ.get("PHISHGUARD_NO_AUTOCREATE") != "1" else None

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)), debug=False)
