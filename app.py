"""
SentinelX — AI-Powered Web Security Auditor
Main Application & REST API Server
Integrates OWASP ZAP and SentinelX Native Security Auditor.
"""
import time
import threading
import logging
from typing import Dict, Any
from flask import Flask, request, jsonify, render_template, send_file, abort
from flask_cors import CORS

from config import (
    SECRET_KEY, SERVER_HOST, SERVER_PORT, DEBUG,
    SCAN_PROFILES, MAX_CONCURRENT_SCANS, ALLOW_LOCAL_TESTING, ALLOWED_TEST_PORTS
)
from security_validator import validate_target_url
from models import (
    create_scan, update_scan_progress, finalize_scan, save_findings,
    add_audit_log, get_scan, get_scan_findings, get_scan_logs, get_all_scans, compare_scans
)
from zap_engine import ZAPEngine
from native_engine import NativeAuditorEngine
from ai_advisory import get_ai_advisory
from report_generator import generate_pdf_report, generate_json_report

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinelx.app")

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
CORS(app)

# Global concurrency lock & active scan tracking
active_scans_lock = threading.Lock()
active_scan_ids = set()

# Initialize Engines
zap_engine = ZAPEngine()
native_engine = NativeAuditorEngine(allow_local_for_test=ALLOW_LOCAL_TESTING)


@app.route("/")
def index():
    """Serves the primary SentinelX Dashboard."""
    return render_template("index.html")


@app.route("/api/status", methods=["GET"])
def get_system_status():
    """Returns engine connectivity, ZAP version, and runtime status."""
    zap_health = zap_engine.check_health()
    with active_scans_lock:
        running_count = len(active_scan_ids)

    return jsonify({
        "status": "operational",
        "active_scans": running_count,
        "max_concurrent_scans": MAX_CONCURRENT_SCANS,
        "zap_engine": zap_health,
        "native_engine": {
            "status": "ready",
            "features": [
                "OWASP Secure Headers Audit",
                "Transport Security & TLS Inspection",
                "Exposed Credential & Token Detection",
                "Cookie Attribute Auditing",
                "CORS Policy Evaluation",
                "Sensitive File Disclosure Probing"
            ]
        },
        "profiles": SCAN_PROFILES,
        "allow_local_testing": ALLOW_LOCAL_TESTING
    })


def run_scan_worker(scan_id: str, target_url: str, profile_code: str):
    """Background worker thread executing the security audit."""
    start_time = time.time()
    try:
        # Check ZAP connectivity
        zap_health = zap_engine.check_health()
        
        if zap_health.get("online"):
            add_audit_log(scan_id, "INFO", f"Active ZAP Daemon detected (v{zap_health.get('version')}). Dispatching scan to OWASP ZAP...")
            findings = zap_engine.execute_scan(scan_id, target_url, profile_code)
            scanner_type = f"OWASP ZAP v{zap_health.get('version')}"
        else:
            add_audit_log(
                scan_id, "INFO",
                f"ZAP Daemon is offline ({zap_health.get('error', 'connection refused')}). "
                "Switching to SentinelX Native Auditor Engine for evidence-based dynamic assessment..."
            )
            findings = native_engine.execute_scan(scan_id, target_url, profile_code)
            scanner_type = "SentinelX Native Auditor"

        # Save all normalized findings
        save_findings(scan_id, findings)
        duration = time.time() - start_time
        finalize_scan(scan_id, "completed", duration, findings)
        add_audit_log(scan_id, "INFO", f"Scan {scan_id} successfully completed in {duration:.2f}s with {len(findings)} findings.")

    except Exception as e:
        logger.exception(f"Error during scan execution {scan_id}: {e}")
        duration = time.time() - start_time
        finalize_scan(scan_id, "failed", duration, [], error_message=str(e))
        add_audit_log(scan_id, "ERROR", f"Assessment halted unexpectedly: {str(e)}")
    finally:
        with active_scans_lock:
            active_scan_ids.discard(scan_id)


@app.route("/api/scan", methods=["POST"])
def trigger_scan():
    """
    Initiates a new website scan after validating URL, scope, and explicit authorization.
    """
    data = request.get_json() or {}
    target_url = data.get("url", "").strip()
    profile = data.get("profile", "quick").lower()
    authorized = data.get("authorized", False)
    authorized_by = data.get("authorized_by", "Authorized Security Operator").strip()

    # 1. Verification of Legal Authorization Checkbox
    if not authorized:
        return jsonify({
            "error": "Scan Rejected: Explicit authorization certification is required.",
            "message": "You must confirm that you are authorized to assess this target."
        }), 403

    # 2. Profile Validation
    if profile not in SCAN_PROFILES:
        return jsonify({
            "error": f"Invalid profile '{profile}'. Allowed profiles: {list(SCAN_PROFILES.keys())}."
        }), 400

    # 3. Target URL & SSRF Validation
    is_valid, err_msg, details = validate_target_url(
        target_url,
        allow_local_for_test=ALLOW_LOCAL_TESTING,
        allowed_ports=ALLOWED_TEST_PORTS
    )
    if not is_valid:
        return jsonify({
            "error": "URL Validation / SSRF Protection Error",
            "message": err_msg
        }), 400

    normalized_url = details["normalized_url"]

    # 4. Concurrency Limit Check
    with active_scans_lock:
        if len(active_scan_ids) >= MAX_CONCURRENT_SCANS:
            return jsonify({
                "error": "Scanner Resource Limit Reached",
                "message": f"Maximum concurrent scan limit ({MAX_CONCURRENT_SCANS}) reached. Please wait for active scans to finish."
            }), 429

        # 5. Create Scan Record
        # Preliminary engine label
        initial_scanner_label = "OWASP ZAP Engine" if zap_engine.check_health().get("online") else "SentinelX Native Auditor"
        scan_id = create_scan(normalized_url, profile, initial_scanner_label, authorized_by)
        active_scan_ids.add(scan_id)

    # 6. Spawn Background Worker Thread
    worker = threading.Thread(target=run_scan_worker, args=(scan_id, normalized_url, profile), daemon=True)
    worker.start()

    return jsonify({
        "status": "started",
        "scan_id": scan_id,
        "target_url": normalized_url,
        "profile": profile,
        "engine": initial_scanner_label,
        "message": f"Security assessment initiated for {normalized_url}."
    }), 202


@app.route("/api/scans", methods=["GET"])
def list_scans():
    """Lists historical scans."""
    scans = get_all_scans(limit=50)
    return jsonify({"scans": scans})


@app.route("/api/scans/<scan_id>", methods=["GET"])
def get_scan_status(scan_id: str):
    """Returns single scan progress and status."""
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan with ID '{scan_id}' not found."}), 404
    return jsonify({"scan": scan})


@app.route("/api/scans/<scan_id>/findings", methods=["GET"])
def get_findings(scan_id: str):
    """Returns findings for a scan with optional severity/category filters."""
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": f"Scan with ID '{scan_id}' not found."}), 404

    severity_filter = request.args.get("severity", "").strip().capitalize()
    category_filter = request.args.get("category", "").strip()
    search_query = request.args.get("q", "").strip().lower()

    findings = get_scan_findings(scan_id)

    # Apply Filters
    filtered = []
    for f in findings:
        if severity_filter and f.get("severity") != severity_filter:
            continue
        if category_filter and category_filter.lower() not in f.get("category", "").lower():
            continue
        if search_query:
            text_corpus = f"{f.get('name', '')} {f.get('description', '')} {f.get('affected_url', '')} {f.get('cwe_id', '')}".lower()
            if search_query not in text_corpus:
                continue
        filtered.append(f)

    return jsonify({
        "scan_id": scan_id,
        "total": len(findings),
        "count": len(filtered),
        "findings": filtered
    })


@app.route("/api/scans/<scan_id>/logs", methods=["GET"])
def get_logs(scan_id: str):
    """Returns real-time execution logs for a scan."""
    logs = get_scan_logs(scan_id)
    return jsonify({"scan_id": scan_id, "logs": logs})


@app.route("/api/findings/<finding_id>/advisory", methods=["GET"])
def get_finding_advisory(finding_id: str):
    """Returns AI-assisted or deterministic remediation advisory for a finding."""
    # Find finding by id
    from models import get_db_connection
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not row:
            return jsonify({"error": "Finding not found."}), 404
        finding_dict = dict(row)

    advisory = get_ai_advisory(finding_dict)
    return jsonify({
        "finding_id": finding_id,
        "name": finding_dict.get("name"),
        "severity": finding_dict.get("severity"),
        "cwe_id": finding_dict.get("cwe_id"),
        "advisory": advisory
    })


@app.route("/api/scans/<scan_id>/export/json", methods=["GET"])
def export_json(scan_id: str):
    """Exports structured JSON report."""
    try:
        report_path = generate_json_report(scan_id)
        return send_file(
            str(report_path),
            as_attachment=True,
            download_name=f"sentinelx_report_{scan_id[:8]}.json",
            mimetype="application/json"
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate JSON report: {str(e)}"}), 500


@app.route("/api/scans/<scan_id>/export/pdf", methods=["GET"])
def export_pdf(scan_id: str):
    """Exports executive-grade PDF assessment report."""
    try:
        pdf_path = generate_pdf_report(scan_id)
        return send_file(
            str(pdf_path),
            as_attachment=True,
            download_name=f"sentinelx_security_report_{scan_id[:8]}.pdf",
            mimetype="application/pdf"
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate PDF report: {str(e)}"}), 500


@app.route("/api/scans/compare/<scan_id_1>/<scan_id_2>", methods=["GET"])
def compare_two_scans(scan_id_1: str, scan_id_2: str):
    """Compares findings between two scans to track remediation progress."""
    try:
        diff_result = compare_scans(scan_id_1, scan_id_2)
        return jsonify(diff_result)
    except Exception as e:
        return jsonify({"error": f"Comparison failed: {str(e)}"}), 500


if __name__ == "__main__":
    logger.info(f"Starting SentinelX Security Auditor Server on http://{SERVER_HOST}:{SERVER_PORT}")
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=DEBUG)
