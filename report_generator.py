"""
SentinelX Report Generator Module
Produces publication-grade executive PDF assessment reports using ReportLab
and standardized JSON machine-readable export files.
"""
import json
import html
from pathlib import Path
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)

from config import REPORTS_DIR
from models import get_scan, get_scan_findings


def xml_esc(val: Any) -> str:
    """Escapes XML entities so text renders safely in ReportLab Paragraphs."""
    if not val:
        return ""
    return html.escape(str(val))


def generate_json_report(scan_id: str) -> Path:
    """Generates and persists a structured JSON report for a scan."""
    scan = get_scan(scan_id)
    if not scan:
        raise ValueError(f"Scan {scan_id} not found.")

    findings = get_scan_findings(scan_id)

    report_data = {
        "report_metadata": {
            "application": "SentinelX Web Security Auditor",
            "version": "2.0.0",
            "scan_id": scan_id,
            "generated_at": scan["completed_at"],
            "confidentiality": "CONFIDENTIAL - AUTHORIZED SECURITY ASSESSMENT ONLY",
        },
        "target": {
            "url": scan["target_url"],
            "profile": scan["profile"],
            "scanner_engine": scan["scanner_type"],
            "authorized_by": scan["authorized_by"],
        },
        "executive_summary": {
            "risk_score": scan["risk_score"],
            "total_findings": scan["total_findings"],
            "high_severity": scan["high_count"],
            "medium_severity": scan["medium_count"],
            "low_severity": scan["low_count"],
            "informational": scan["info_count"],
            "scan_duration_seconds": scan["duration_seconds"],
        },
        "findings": findings
    }

    output_path = REPORTS_DIR / f"sentinelx_report_{scan_id}.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    return output_path


def generate_pdf_report(scan_id: str) -> Path:
    """Generates an executive-grade PDF security assessment report."""
    scan = get_scan(scan_id)
    if not scan:
        raise ValueError(f"Scan {scan_id} not found.")

    findings = get_scan_findings(scan_id)
    output_path = REPORTS_DIR / f"sentinelx_report_{scan_id}.pdf"

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    # Custom color palette
    c_dark = colors.HexColor("#0B0F19")
    c_primary = colors.HexColor("#0284C7")
    c_slate = colors.HexColor("#475569")
    c_red = colors.HexColor("#EF4444")
    c_amber = colors.HexColor("#F59E0B")
    c_blue = colors.HexColor("#3B82F6")
    c_green = colors.HexColor("#10B981")
    c_bg_box = colors.HexColor("#F8FAFC")
    c_border = colors.HexColor("#E2E8F0")

    # Typography styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=c_dark
    )
    subtitle_style = ParagraphStyle(
        "DocSub",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=c_primary
    )
    meta_style = ParagraphStyle(
        "MetaText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=c_slate
    )
    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=c_dark,
        spaceBefore=14,
        spaceAfter=8
    )
    finding_title = ParagraphStyle(
        "FindingTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=c_dark
    )
    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1E293B")
    )
    code_snippet_style = ParagraphStyle(
        "CodeSnippet",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0F172A")
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("SENTINELX", subtitle_style))
    story.append(Paragraph("Security Assessment Report", title_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"Target: <b>{scan['target_url']}</b> &bull; Authorized by: <b>{scan.get('authorized_by', 'User')}</b>", meta_style))
    story.append(Paragraph(f"Scan ID: {scan_id} &bull; Engine: {scan['scanner_type']} &bull; Profile: {scan['profile'].upper()}", meta_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=c_primary, spaceBefore=4, spaceAfter=14))

    # 2. Executive Summary Metrics Box
    risk_score = scan.get("risk_score", 0)
    risk_label = "SECURE"
    risk_color = c_green
    if risk_score < 40:
        risk_label = "CRITICAL RISK"
        risk_color = c_red
    elif risk_score < 65:
        risk_label = "HIGH RISK"
        risk_color = c_red
    elif risk_score < 80:
        risk_label = "MODERATE RISK"
        risk_color = c_amber
    elif risk_score < 95:
        risk_label = "LOW RISK"
        risk_color = c_blue

    summary_data = [
        [
            Paragraph("<b>Overall Posture</b>", meta_style),
            Paragraph("<b>Total Findings</b>", meta_style),
            Paragraph("<b>High</b>", meta_style),
            Paragraph("<b>Medium</b>", meta_style),
            Paragraph("<b>Low</b>", meta_style),
            Paragraph("<b>Info</b>", meta_style),
        ],
        [
            Paragraph(f"<font color='{risk_color.hexval()}'><b>{risk_score}/100</b> ({risk_label})</font>", finding_title),
            Paragraph(f"<b>{scan['total_findings']}</b>", finding_title),
            Paragraph(f"<font color='{c_red.hexval()}'><b>{scan['high_count']}</b></font>", finding_title),
            Paragraph(f"<font color='{c_amber.hexval()}'><b>{scan['medium_count']}</b></font>", finding_title),
            Paragraph(f"<font color='{c_blue.hexval()}'><b>{scan['low_count']}</b></font>", finding_title),
            Paragraph(f"<font color='{c_slate.hexval()}'><b>{scan['info_count']}</b></font>", finding_title),
        ]
    ]

    summary_table = Table(summary_data, colWidths=[1.8*inch, 1.1*inch, 0.9*inch, 0.9*inch, 0.9*inch, 0.9*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_bg_box),
        ('BOX', (0, 0), (-1, -1), 1, c_border),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 14))

    # 3. Scope & Assessment Overview
    story.append(Paragraph("Assessment Scope & Engine Verification", heading_style))
    exec_text = (
        f"This security assessment of <b>{scan['target_url']}</b> was executed using the "
        f"<b>{scan['scanner_type']}</b> engine. Completed in {scan.get('duration_seconds', 0)} seconds, "
        f"the audit assessed transport layer resilience, HTTP security response headers, cookie attributes, "
        f"potential exposed credential patterns, and endpoint configuration. All findings reflect real, "
        f"unsimulated HTTP response evidence."
    )
    story.append(Paragraph(exec_text, body_style))
    story.append(Spacer(1, 14))

    # 4. Detailed Findings Section
    story.append(Paragraph("Detailed Security Findings", heading_style))

    if not findings:
        story.append(Paragraph("<b>No security vulnerabilities or configuration defects were detected during this assessment.</b>", body_style))
    else:
        for idx, f in enumerate(findings, 1):
            sev = f.get("severity", "Informational")
            sev_color = c_slate
            if sev == "High":
                sev_color = c_red
            elif sev == "Medium":
                sev_color = c_amber
            elif sev == "Low":
                sev_color = c_blue

            cwe_tag = f" &bull; {xml_esc(f['cwe_id'])}" if f.get("cwe_id") else ""
            status_tag = f" &bull; <i>{xml_esc(f.get('status', 'Finding'))}</i>"

            finding_header = [
                [
                    Paragraph(f"<b>#{idx} {xml_esc(f.get('name', 'Observation'))}</b>", finding_title),
                    Paragraph(f"<font color='{sev_color.hexval()}'><b>[{sev.upper()}]{cwe_tag}{status_tag}</b></font>", meta_style)
                ]
            ]
            header_table = Table(finding_header, colWidths=[4.2*inch, 2.8*inch])
            header_table.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
                ('TOPPADDING', (0, 0), (-1, -1), 2),
            ]))

            finding_body_rows = [
                [Paragraph("<b>Affected URL:</b>", meta_style), Paragraph(f"<code>{xml_esc(f.get('affected_url', ''))}</code>", body_style)],
                [Paragraph("<b>Description:</b>", meta_style), Paragraph(xml_esc(f.get("description", "")), body_style)],
                [Paragraph("<b>Impact:</b>", meta_style), Paragraph(xml_esc(f.get("impact", "")), body_style)],
                [Paragraph("<b>Remediation:</b>", meta_style), Paragraph(xml_esc(f.get("remediation", "")), body_style)],
            ]

            evidence_txt = f.get("evidence", "").strip()
            if evidence_txt:
                finding_body_rows.append([
                    Paragraph("<b>Evidence:</b>", meta_style),
                    Paragraph(f"<font face='Courier' size=8 color='#0F172A'>{xml_esc(evidence_txt[:350])}</font>", code_snippet_style)
                ])

            detail_table = Table(finding_body_rows, colWidths=[1.3*inch, 5.7*inch])
            detail_table.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('LINEBELOW', (0, -1), (-1, -1), 0.5, c_border),
            ]))

            finding_block = [
                header_table,
                Spacer(1, 2),
                detail_table,
                Spacer(1, 10)
            ]
            story.append(KeepTogether(finding_block))

    # 5. Legal Disclaimer & Authorization Notice
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.5, color=c_border, spaceBefore=4, spaceAfter=8))
    legal_text = (
        "<b>CONFIDENTIALITY NOTICE & DISCLAIMER:</b> This security report is produced solely for the authorized "
        "organization and recipient. While SentinelX utilizes rigorous dynamic scanning methods, no automated assessment "
        "can guarantee complete immunity from emerging threats or unassessed code paths. Findings are evidence-based observations "
        "and should be verified by professional security personnel before applying production changes."
    )
    story.append(Paragraph(legal_text, ParagraphStyle("Legal", parent=styles["Normal"], fontName="Helvetica", fontSize=7, leading=9, textColor=c_slate)))

    doc.build(story)
    return output_path
