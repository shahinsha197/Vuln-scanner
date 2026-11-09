"""
Passive Scanner — Flask Web App
Serves the scanner dashboard and report UI.
Also exposes a REST API endpoint for n8n integration.
"""
import uuid
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, session

from scanner_engine import run_scan

app = Flask(__name__)
app.secret_key = "scanner-secret-key-change-in-prod"

# In-memory scan store (scan_id → result)
scan_store = {}

# ── n8n webhook URL (set this after importing the workflow into n8n) ──
N8N_WEBHOOK_URL = "http://localhost:5678/webhook/passive-scan"
N8N_ENABLED = False   # Set to True after n8n is configured


# ─────────────────────────────────────────────
# Web Routes
# ─────────────────────────────────────────────

@app.route("/")
def index():
    """Scanner dashboard — enter a URL to scan."""
    return render_template("index.html", n8n_enabled=N8N_ENABLED)


@app.route("/scan", methods=["POST"])
def scan():
    """Trigger a scan from the web form."""
    url = request.form.get("url", "").strip()
    if not url:
        return render_template("index.html", error="Please enter a URL.", n8n_enabled=N8N_ENABLED)

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    if N8N_ENABLED:
        # ── Route through n8n ──────────────────────────────────────
        import requests as req
        scan_id = str(uuid.uuid4())
        try:
            n8n_resp = req.post(N8N_WEBHOOK_URL,
                                json={"url": url, "scan_id": scan_id},
                                timeout=60)
            result = n8n_resp.json()
            scan_store[scan_id] = result
        except Exception as e:
            return render_template("index.html",
                                   error=f"n8n error: {str(e)}",
                                   n8n_enabled=N8N_ENABLED)
    else:
        # ── Direct scan (no n8n) ───────────────────────────────────
        scan_id = str(uuid.uuid4())
        result = run_scan(url)
        result["scan_id"] = scan_id
        result["scanned_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_store[scan_id] = result

    return redirect(url_for("report", scan_id=scan_id))


@app.route("/report/<scan_id>")
def report(scan_id):
    """Show the scan report page."""
    result = scan_store.get(scan_id)
    if not result:
        return render_template("index.html",
                               error="Scan not found. Please run a new scan.",
                               n8n_enabled=N8N_ENABLED)
    return render_template("report.html", result=result)


# ─────────────────────────────────────────────
# REST API (used by n8n workflow)
# ─────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    JSON API endpoint — called by n8n or any HTTP client.

    Request body:
        { "url": "http://target.com", "scan_id": "optional-uuid" }

    Response:
        Full scan result as JSON
    """
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "").strip()
    scan_id = data.get("scan_id", str(uuid.uuid4()))

    if not url:
        return jsonify({"error": "url is required"}), 400

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    result = run_scan(url)
    result["scan_id"] = scan_id
    result["scanned_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_store[scan_id] = result

    return jsonify(result)


@app.route("/api/results/<scan_id>")
def api_results(scan_id):
    """Retrieve a stored scan result by ID."""
    result = scan_store.get(scan_id)
    if not result:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(result)


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "scanner": "PassiveScanner v1.0"})


if __name__ == "__main__":
    print("=" * 55)
    print("  PassiveScanner -- running on http://localhost:5002")
    print("=" * 55)
    app.run(debug=True, host="0.0.0.0", port=5002)
