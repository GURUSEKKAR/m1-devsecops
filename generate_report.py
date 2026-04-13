#!/usr/bin/env python3
"""
M1 DevSecOps Pipeline - Unified Report Generator (Stage 9)
Reads ai-remediation-results.json and generates unified-security-report.html
"""

import json
import os
import sys
from datetime import datetime


def load_json(filepath):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f'[WARN] Could not load {filepath}: {e}')
        return None


def severity_badge(severity):
    colors = {
        'CRITICAL': '#dc3545',
        'HIGH': '#fd7e14',
        'MEDIUM': '#ffc107',
        'LOW': '#28a745',
        'INFORMATIONAL': '#17a2b8',
        'UNKNOWN': '#6c757d'
    }
    color = colors.get(severity.upper(), '#6c757d')
    text_color = '#fff' if severity.upper() in ['CRITICAL', 'HIGH'] else '#000'
    return f'<span style="background:{color};color:{text_color};padding:2px 10px;border-radius:4px;font-weight:bold;font-size:12px;">{severity}</span>'


def escape_html(text):
    if not text:
        return ''
    return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


def generate_report():
    # Load AI remediation results
    data = load_json('ai-remediation-results.json')
    if not data:
        print('[ERROR] Cannot load ai-remediation-results.json')
        sys.exit(1)

    pipeline = data.get('pipeline', {})
    scanners = data.get('scanners', {})
    total = data.get('total_findings', 0)
    processed = data.get('processed', 0)
    success = data.get('success', 0)
    failed = data.get('failed', 0)

    # Count by severity
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for r in data.get('results', []):
        sev = r.get('finding', {}).get('severity', 'UNKNOWN').upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # ---- BUILD HTML ----
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>M1 DevSecOps - Unified Security Report</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f6fa; color: #2d3436; line-height: 1.6; }}
.container {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}
.header {{ background: linear-gradient(135deg, #0c2461, #1e3799); color: white; padding: 30px; border-radius: 12px; margin-bottom: 24px; }}
.header h1 {{ font-size: 28px; margin-bottom: 8px; }}
.header .subtitle {{ opacity: 0.85; font-size: 14px; }}
.meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-top: 16px; }}
.meta-item {{ background: rgba(255,255,255,0.15); padding: 10px 14px; border-radius: 8px; }}
.meta-item .label {{ font-size: 11px; text-transform: uppercase; opacity: 0.7; }}
.meta-item .value {{ font-size: 16px; font-weight: bold; }}
.summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }}
.card {{ padding: 18px; border-radius: 10px; text-align: center; color: white; }}
.card .number {{ font-size: 32px; font-weight: bold; }}
.card .label {{ font-size: 12px; text-transform: uppercase; opacity: 0.9; }}
.card-critical {{ background: #dc3545; }}
.card-high {{ background: #fd7e14; }}
.card-medium {{ background: #ffc107; color: #000; }}
.card-low {{ background: #28a745; }}
.card-total {{ background: #1e3799; }}
.card-ai {{ background: #6f42c1; }}
.section {{ background: white; border-radius: 10px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
.section h2 {{ font-size: 20px; margin-bottom: 16px; padding-bottom: 10px; border-bottom: 2px solid #eee; display: flex; align-items: center; gap: 10px; }}
.scanner-icon {{ width: 28px; height: 28px; border-radius: 6px; display: inline-flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 14px; }}
.icon-trivy {{ background: #00b894; }}
.icon-owasp {{ background: #e17055; }}
.icon-sonar {{ background: #0984e3; }}
.icon-zap {{ background: #fdcb6e; color: #000; }}
.vuln-card {{ border: 1px solid #e9ecef; border-radius: 8px; padding: 16px; margin-bottom: 14px; transition: box-shadow 0.2s; }}
.vuln-card:hover {{ box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
.vuln-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 8px; }}
.vuln-id {{ font-weight: bold; color: #2d3436; font-size: 15px; }}
.vuln-pkg {{ color: #636e72; font-size: 13px; }}
.vuln-desc {{ font-size: 13px; color: #555; margin-bottom: 12px; }}
.ai-box {{ background: #f0f3ff; border-left: 4px solid #6f42c1; padding: 14px; border-radius: 0 8px 8px 0; margin-top: 10px; }}
.ai-box .ai-label {{ font-size: 12px; font-weight: bold; color: #6f42c1; text-transform: uppercase; margin-bottom: 6px; }}
.ai-box .ai-text {{ font-size: 13px; white-space: pre-wrap; word-wrap: break-word; }}
.ai-box code {{ background: #e2e8f0; padding: 1px 6px; border-radius: 3px; font-size: 12px; }}
.empty {{ text-align: center; padding: 30px; color: #b2bec3; font-style: italic; }}
.footer {{ text-align: center; padding: 20px; color: #b2bec3; font-size: 12px; }}
.collapsible {{ cursor: pointer; user-select: none; }}
.collapsible::after {{ content: ' ▼'; font-size: 12px; }}
.version-info {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }}
.version {{ font-size: 12px; padding: 2px 8px; background: #e9ecef; border-radius: 4px; }}
.fix-version {{ background: #d4edda; color: #155724; }}
</style>
</head>
<body>
<div class="container">

<!-- HEADER -->
<div class="header">
    <h1>M1 DevSecOps - Unified Security Report</h1>
    <div class="subtitle">AI-Enhanced Vulnerability Analysis with CodeLLaMA 7B</div>
    <div class="meta-grid">
        <div class="meta-item">
            <div class="label">Build Number</div>
            <div class="value">#{pipeline.get('build_number', 'N/A')}</div>
        </div>
        <div class="meta-item">
            <div class="label">Branch</div>
            <div class="value">{escape_html(pipeline.get('branch', 'N/A'))}</div>
        </div>
        <div class="meta-item">
            <div class="label">Commit</div>
            <div class="value">{escape_html(str(pipeline.get('commit', 'N/A'))[:8])}</div>
        </div>
        <div class="meta-item">
            <div class="label">Report Generated</div>
            <div class="value">{timestamp}</div>
        </div>
    </div>
</div>

<!-- SUMMARY CARDS -->
<div class="summary-cards">
    <div class="card card-total"><div class="number">{total}</div><div class="label">Total Findings</div></div>
    <div class="card card-critical"><div class="number">{severity_counts['CRITICAL']}</div><div class="label">Critical</div></div>
    <div class="card card-high"><div class="number">{severity_counts['HIGH']}</div><div class="label">High</div></div>
    <div class="card card-medium"><div class="number">{severity_counts['MEDIUM']}</div><div class="label">Medium</div></div>
    <div class="card card-low"><div class="number">{severity_counts['LOW']}</div><div class="label">Low</div></div>
    <div class="card card-ai"><div class="number">{success}</div><div class="label">AI Fixes</div></div>
</div>
"""

    # ---- TRIVY SECTION ----
    trivy_results = scanners.get('trivy', [])
    html += f"""
<div class="section">
    <h2><span class="scanner-icon icon-trivy">T</span> Trivy - Container Vulnerability Scan ({len(trivy_results)} findings)</h2>
"""
    if trivy_results:
        for r in trivy_results:
            f = r.get('finding', {})
            ai = r.get('ai_suggestion', {})
            html += f"""
    <div class="vuln-card">
        <div class="vuln-header">
            <span class="vuln-id">{escape_html(f.get('cve_id', 'N/A'))}</span>
            {severity_badge(f.get('severity', 'UNKNOWN'))}
        </div>
        <div class="vuln-pkg">
            Package: <strong>{escape_html(f.get('package', 'N/A'))}</strong>
            <div class="version-info" style="margin-top:4px;">
                <span class="version">Installed: {escape_html(f.get('installed_version', 'N/A'))}</span>
                <span class="version fix-version">Fix: {escape_html(f.get('fixed_version', 'N/A'))}</span>
            </div>
        </div>
        <div class="vuln-desc">{escape_html(f.get('title', f.get('description', '')[:200]))}</div>
        <div class="ai-box">
            <div class="ai-label">AI Remediation Suggestion</div>
            <div class="ai-text">{escape_html(ai.get('explanation', ai.get('fix_suggestion', 'No AI suggestion available')))[:800]}</div>
        </div>
    </div>"""
    else:
        html += '<div class="empty">No Trivy findings to display</div>'
    html += '\n</div>'

    # ---- OWASP DC SECTION ----
    owasp_results = scanners.get('owasp_dc', [])
    html += f"""
<div class="section">
    <h2><span class="scanner-icon icon-owasp">O</span> OWASP DC / npm audit - Dependency Scan ({len(owasp_results)} findings)</h2>
"""
    if owasp_results:
        for r in owasp_results:
            f = r.get('finding', {})
            ai = r.get('ai_suggestion', {})
            html += f"""
    <div class="vuln-card">
        <div class="vuln-header">
            <span class="vuln-id">{escape_html(f.get('cve_id', 'N/A'))}</span>
            {severity_badge(f.get('severity', 'UNKNOWN'))}
        </div>
        <div class="vuln-pkg">Package: <strong>{escape_html(f.get('package', 'N/A'))}</strong></div>
        <div class="vuln-desc">{escape_html(f.get('description', '')[:200])}</div>
        <div class="ai-box">
            <div class="ai-label">AI Remediation Suggestion</div>
            <div class="ai-text">{escape_html(ai.get('explanation', ai.get('fix_suggestion', 'No AI suggestion available')))[:800]}</div>
        </div>
    </div>"""
    else:
        html += '<div class="empty">No OWASP DC findings - dependencies are clean</div>'
    html += '\n</div>'

    # ---- SONARQUBE SECTION ----
    sonar_results = scanners.get('sonarqube', [])
    html += f"""
<div class="section">
    <h2><span class="scanner-icon icon-sonar">S</span> SonarQube - SAST / Code Quality ({len(sonar_results)} findings)</h2>
"""
    if sonar_results:
        for r in sonar_results:
            f = r.get('finding', {})
            ai = r.get('ai_suggestion', {})
            html += f"""
    <div class="vuln-card">
        <div class="vuln-header">
            <span class="vuln-id">{escape_html(f.get('cve_id', 'N/A'))}</span>
            {severity_badge(f.get('severity', 'UNKNOWN'))}
        </div>
        <div class="vuln-pkg">File: {escape_html(f.get('component', 'N/A'))} | Line: {f.get('line', 'N/A')}</div>
        <div class="vuln-desc">{escape_html(f.get('description', '')[:200])}</div>
        <div class="ai-box">
            <div class="ai-label">AI Remediation Suggestion</div>
            <div class="ai-text">{escape_html(ai.get('explanation', ai.get('fix_suggestion', 'No AI suggestion available')))[:800]}</div>
        </div>
    </div>"""
    else:
        html += '<div class="empty">No SonarQube issues found - code quality passed</div>'
    html += '\n</div>'

    # ---- ZAP SECTION ----
    zap_results = scanners.get('zap', [])
    html += f"""
<div class="section">
    <h2><span class="scanner-icon icon-zap">Z</span> OWASP ZAP - DAST / Live App Scan ({len(zap_results)} findings)</h2>
"""
    if zap_results:
        for r in zap_results:
            f = r.get('finding', {})
            ai = r.get('ai_suggestion', {})
            html += f"""
    <div class="vuln-card">
        <div class="vuln-header">
            <span class="vuln-id">{escape_html(f.get('alert_name', f.get('cve_id', 'N/A')))}</span>
            {severity_badge(f.get('severity', 'UNKNOWN'))}
        </div>
        <div class="vuln-desc">{escape_html(f.get('description', '')[:200])}</div>
        <div class="ai-box">
            <div class="ai-label">AI Remediation Suggestion</div>
            <div class="ai-text">{escape_html(ai.get('explanation', ai.get('fix_suggestion', 'No AI suggestion available')))[:800]}</div>
        </div>
    </div>"""
    else:
        html += '<div class="empty">No ZAP alerts found</div>'
    html += '\n</div>'

    # ---- AI SUMMARY - TOP FIXES ----
    top_fixes = []
    for r in data.get('results', []):
        if r.get('ai_suggestion', {}).get('status') == 'success':
            top_fixes.append(r)
    top_fixes = top_fixes[:10]

    html += f"""
<div class="section">
    <h2>AI Summary - Top {len(top_fixes)} Priority Fixes</h2>
"""
    if top_fixes:
        for i, r in enumerate(top_fixes):
            f = r.get('finding', {})
            ai = r.get('ai_suggestion', {})
            cve = f.get('cve_id', f.get('alert_name', 'N/A'))
            html += f"""
    <div class="vuln-card">
        <div class="vuln-header">
            <span class="vuln-id">#{i+1} - {escape_html(cve)} ({f.get('scanner', '')})</span>
            {severity_badge(f.get('severity', 'UNKNOWN'))}
        </div>
        <div class="ai-box">
            <div class="ai-text">{escape_html(ai.get('fix_suggestion', ai.get('explanation', '')))[:500]}</div>
        </div>
    </div>"""
    else:
        html += '<div class="empty">No AI suggestions available</div>'
    html += '\n</div>'

    # ---- FOOTER ----
    html += f"""
<div class="footer">
    <p>M1 DevSecOps Pipeline | AI Remediation by Fine-Tuned CodeLLaMA 7B | Report generated: {timestamp}</p>
    <p>Academic Year 2025-2026</p>
</div>

</div>
</body>
</html>"""

    # ---- WRITE FILE ----
    output_path = 'unified-security-report.html'
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f'\n[Stage 9] Unified security report generated: {output_path}')
    print(f'  Total findings:   {total}')
    print(f'  AI suggestions:   {success}')
    print(f'  Scanners covered: Trivy, OWASP DC, SonarQube, ZAP')
    return output_path


if __name__ == '__main__':
    generate_report()
