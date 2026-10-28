"""
SentinelX Database Models & Persistence Module
SQLite-backed storage for scans, security findings, and execution audit logs.
"""
import sqlite3
import json
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from config import DATABASE_PATH


def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection with dict-like row factory."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes database schema with required tables and indexes."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                profile TEXT NOT NULL,
                scanner_type TEXT NOT NULL,
                status TEXT NOT NULL,
                progress INTEGER DEFAULT 0,
                stage TEXT DEFAULT 'Initializing',
                started_at TEXT NOT NULL,
                completed_at TEXT,
                duration_seconds REAL,
                risk_score INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                error_message TEXT,
                authorized_by TEXT DEFAULT 'Authorized User'
            )
        """)
        
        # Findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                name TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                affected_url TEXT NOT NULL,
                evidence TEXT,
                cwe_id TEXT,
                wasc_id TEXT,
                description TEXT,
                impact TEXT,
                remediation TEXT,
                request_snippet TEXT,
                response_snippet TEXT,
                status TEXT NOT NULL,
                category TEXT,
                scanner TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)
        
        # Audit Logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)
        
        # Indexes for fast querying
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_scan_id ON audit_logs(scan_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC)")
        conn.commit()


def create_scan(target_url: str, profile: str, scanner_type: str, authorized_by: str = "Authorized User") -> str:
    """Creates a new scan record and returns scan_id."""
    scan_id = str(uuid.uuid4())
    now_str = datetime.utcnow().isoformat() + "Z"
    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO scans (id, target_url, profile, scanner_type, status, progress, stage, started_at, authorized_by)
            VALUES (?, ?, ?, ?, 'running', 5, 'Validating Target & Initializing Engine', ?, ?)
        """, (scan_id, target_url, profile, scanner_type, now_str, authorized_by))
        conn.commit()
    return scan_id


def update_scan_progress(scan_id: str, progress: int, stage: str):
    """Updates scan progress and current stage."""
    with get_db_connection() as conn:
        conn.execute("UPDATE scans SET progress = ?, stage = ? WHERE id = ?", (progress, stage, scan_id))
        conn.commit()


def add_audit_log(scan_id: str, level: str, message: str):
    """Appends an event to the scan audit log."""
    now_str = datetime.utcnow().isoformat() + "Z"
    with get_db_connection() as conn:
        conn.execute("INSERT INTO audit_logs (scan_id, timestamp, level, message) VALUES (?, ?, ?, ?)",
                     (scan_id, now_str, level, message))
        conn.commit()


def save_findings(scan_id: str, findings: List[Dict[str, Any]]):
    """Bulk inserts findings for a completed scan."""
    with get_db_connection() as conn:
        for f in findings:
            f_id = f.get("id") or str(uuid.uuid4())
            conn.execute("""
                INSERT INTO findings (
                    id, scan_id, name, severity, confidence, affected_url, evidence,
                    cwe_id, wasc_id, description, impact, remediation,
                    request_snippet, response_snippet, status, category, scanner
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f_id,
                scan_id,
                f.get("name", "Unknown Finding"),
                f.get("severity", "Informational"),
                f.get("confidence", "Medium"),
                f.get("affected_url", ""),
                f.get("evidence", ""),
                f.get("cwe_id", ""),
                f.get("wasc_id", ""),
                f.get("description", ""),
                f.get("impact", ""),
                f.get("remediation", ""),
                f.get("request_snippet", ""),
                f.get("response_snippet", ""),
                f.get("status", "Potential Finding"),
                f.get("category", "General Security"),
                f.get("scanner", "SentinelX Engine")
            ))
        conn.commit()


def finalize_scan(scan_id: str, status: str, duration: float, findings: List[Dict[str, Any]], error_message: Optional[str] = None):
    """Calculates summary statistics and marks scan as completed or failed."""
    now_str = datetime.utcnow().isoformat() + "Z"
    
    high = sum(1 for f in findings if f.get("severity") == "High")
    med = sum(1 for f in findings if f.get("severity") == "Medium")
    low = sum(1 for f in findings if f.get("severity") == "Low")
    info = sum(1 for f in findings if f.get("severity") == "Informational")
    total = len(findings)

    # Risk Score calculation: 100 base, deductions for vulnerabilities
    # High: -20, Medium: -10, Low: -4, Info: -1 (min score: 0)
    deduction = (high * 20) + (med * 10) + (low * 4) + (info * 1)
    risk_score = max(0, 100 - deduction)

    with get_db_connection() as conn:
        conn.execute("""
            UPDATE scans SET
                status = ?,
                progress = 100,
                stage = 'Assessment Complete',
                completed_at = ?,
                duration_seconds = ?,
                risk_score = ?,
                total_findings = ?,
                high_count = ?,
                medium_count = ?,
                low_count = ?,
                info_count = ?,
                error_message = ?
            WHERE id = ?
        """, (status, now_str, round(duration, 2), risk_score, total, high, med, low, info, error_message, scan_id))
        conn.commit()


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves single scan details."""
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        return dict(row)


def get_scan_findings(scan_id: str) -> List[Dict[str, Any]]:
    """Retrieves all findings for a scan."""
    with get_db_connection() as conn:
        rows = conn.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY CASE severity WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END", (scan_id,)).fetchall()
        return [dict(r) for r in rows]


def get_scan_logs(scan_id: str) -> List[Dict[str, Any]]:
    """Retrieves event logs for a scan."""
    with get_db_connection() as conn:
        rows = conn.execute("SELECT * FROM audit_logs WHERE scan_id = ? ORDER BY id ASC", (scan_id,)).fetchall()
        return [dict(r) for r in rows]


def get_all_scans(limit: int = 25) -> List[Dict[str, Any]]:
    """Retrieves recent scan history."""
    with get_db_connection() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


def compare_scans(scan_id_1: str, scan_id_2: str) -> Dict[str, Any]:
    """Compares findings between two scans of the same target."""
    f1 = get_scan_findings(scan_id_1)
    f2 = get_scan_findings(scan_id_2)

    names_1 = {f["name"] for f in f1}
    names_2 = {f["name"] for f in f2}

    resolved = [f for f in f1 if f["name"] not in names_2]
    new_findings = [f for f in f2 if f["name"] not in names_1]
    persistent = [f for f in f2 if f["name"] in names_1]

    return {
        "scan_1_id": scan_id_1,
        "scan_2_id": scan_id_2,
        "resolved_findings": resolved,
        "new_findings": new_findings,
        "persistent_findings": persistent,
        "total_scan_1": len(f1),
        "total_scan_2": len(f2),
    }


# Initialize DB automatically on import
init_db()
