#!/usr/bin/env python3
"""
M1 DevSecOps Pipeline - AI Remediation Engine (Stage 8)
Reads unified-scan-report.json and zap-report.json
Sends each vulnerability to fine-tuned CodeLLaMA 7B via FastAPI
Collects AI-generated fix suggestions
"""

import json
import os
import re
import sys
import time

import requests

# FastAPI endpoint URL - set via environment variable in Jenkinsfile
AI_ENDPOINT = os.environ.get('AI_ENDPOINT_URL', 'http://localhost:8000')

# How many findings to send to the AI (sorted by severity, highest first)
MAX_FINDINGS_TO_PROCESS = 25


def load_json(filepath):
    """Safely load a JSON report file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f'  [WARN] Could not load {filepath}: {e}')
        return None


def smart_truncate(text, max_len=500):
    """Truncate at sentence boundary if possible, else at word boundary."""
    if not text or len(text) <= max_len:
        return text
    cut = text[:max_len]
    # Prefer a sentence end
    for sep in ['. ', '! ', '? ']:
        idx = cut.rfind(sep)
        if idx > max_len * 0.6:
            return cut[:idx + 1]
    # Fallback: word boundary
    idx = cut.rfind(' ')
    if idx > 0:
        return cut[:idx]
    return cut


def parse_trivy_from_unified(unified_report):
    """Extract Trivy findings from unified-scan-report.json"""
    findings = []
    if not unified_report:
        return findings

    trivy = unified_report.get('scanners', {}).get('trivy', {})
    results = trivy.get('Results', [])

    for result in results:
        target = result.get('Target', 'unknown')
        for vuln in result.get('Vulnerabilities', []):
            findings.append({
                'scanner': 'Trivy',
                'cve_id': vuln.get('VulnerabilityID', 'N/A'),
                'package': vuln.get('PkgName', 'N/A'),
                'installed_version': vuln.get('InstalledVersion', 'N/A'),
                'fixed_version': vuln.get('FixedVersion', 'No fix available'),
                'severity': vuln.get('Severity', 'UNKNOWN'),
                'title': vuln.get('Title', ''),
                'description': smart_truncate(vuln.get('Description', ''), 500),
                'target': target,
                'primary_url': vuln.get('PrimaryURL', ''),
                'cwe_ids': vuln.get('CweIDs', []),
            })
    return findings


def parse_owasp_dc_from_unified(unified_report):
    """Extract OWASP DC / npm audit findings from unified-scan-report.json"""
    findings = []
    if not unified_report:
        return findings

    owasp = unified_report.get('scanners', {}).get('owasp_dc', {})
    deps = owasp.get('dependencies', [])

    for dep in deps:
        for vuln in dep.get('vulnerabilities', []):
            findings.append({
                'scanner': 'OWASP-DC',
                'cve_id': vuln.get('name', 'N/A'),
                'package': dep.get('fileName', 'N/A'),
                'severity': vuln.get('severity', 'UNKNOWN'),
                'description': smart_truncate(vuln.get('description', ''), 500),
                'cvss_score': vuln.get('cvssv3', {}).get('baseScore', 0),
            })
    return findings


def parse_sonarqube_from_unified(unified_report):
    """Extract SonarQube findings from unified-scan-report.json"""
    findings = []
    if not unified_report:
        return findings

    sonar = unified_report.get('scanners', {}).get('sonarqube', {})
    issues = sonar.get('issues', [])

    for issue in issues:
        # Sanitize rule id (e.g. "javascript:S2068" -> "javascript-S2068")
        rule = str(issue.get('rule', 'N/A')).replace(':', '-')
        findings.append({
            'scanner': 'SonarQube',
            'cve_id': f"SONAR-{rule}",
            'severity': issue.get('severity', 'UNKNOWN'),
            'description': smart_truncate(issue.get('message', ''), 500),
            'component': issue.get('component', 'N/A'),
            'line': issue.get('line', 'N/A'),
            'type': issue.get('type', 'N/A'),
        })
    return findings


def make_zap_id(plugin_id, alert_name):
    """Build a unique, filename-safe ZAP cve_id from plugin id + alert name."""
    slug = re.sub(r'[^a-zA-Z0-9]+', '-', str(alert_name))[:30].strip('-')
    if not slug:
        slug = 'unknown'
    return f"ZAP-{plugin_id}-{slug}"


def parse_zap_html(filepath):
    """Extract ZAP findings from zap-report.html (fallback if JSON not available)"""
    findings = []

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        print(f'  [WARN] ZAP HTML report not found: {filepath}')
        return findings

    # Locate alerts table - bail out if not found instead of slicing on -1
    idx = content.find('class="alerts"')
    if idx == -1:
        print('  [WARN] ZAP HTML format unrecognized (no alerts table found)')
        return findings

    section = content[idx:]
    rows = re.findall(r'<tr[^>]*>(.*?)</tr>', section[:5000], re.DOTALL)

    for row in rows:
        tds = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
        cleaned = [re.sub(r'<[^>]+>', '', td).strip() for td in tds]
        if len(cleaned) >= 2 and cleaned[1] in ['High', 'Medium', 'Low', 'Informational']:
            alert_name = cleaned[0]
            findings.append({
                'scanner': 'ZAP',
                'cve_id': make_zap_id('HTML', alert_name),
                'alert_name': alert_name,
                'severity': cleaned[1].upper(),
                'description': f"DAST finding: {alert_name}",
                'instances': cleaned[2] if len(cleaned) > 2 else '1',
            })

    # Try to enrich with solution text from the detail section
    detail_idx = content.find('Alert Detail')
    if detail_idx != -1:
        detail_section = content[detail_idx:]
        solutions = re.findall(r'Solution.*?<td[^>]*>(.*?)</td>', detail_section, re.DOTALL)
        for i, sol in enumerate(solutions):
            clean_sol = re.sub(r'<[^>]+>', '', sol).strip()[:300]
            if i < len(findings) and clean_sol:
                findings[i]['zap_solution'] = clean_sol

    return findings


def normalize_zap_severity(alert):
    """ZAP uses many severity formats - normalize to CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL."""
    # Try riskdesc first ("Medium (Medium)", "Informational (Low)" etc.)
    riskdesc = alert.get('riskdesc', '')
    if riskdesc:
        sev = riskdesc.split(' ')[0].upper()
        if sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'):
            return sev

    # Fall back to numeric risk code
    risk_map = {
        '0': 'INFORMATIONAL',
        '1': 'LOW',
        '2': 'MEDIUM',
        '3': 'HIGH',
        '4': 'CRITICAL',
    }
    risk = str(alert.get('risk', alert.get('riskcode', '')))
    if risk in risk_map:
        return risk_map[risk]

    return 'UNKNOWN'


def parse_zap_json(filepath):
    """Extract ZAP findings from zap-report.json (preferred over HTML)"""
    findings = []
    report = load_json(filepath)
    if not report:
        return findings

    for site in report.get('site', []):
        for alert in site.get('alerts', []):
            plugin_id = alert.get('pluginid', 'N/A')
            alert_name = alert.get('name', alert.get('alert', 'Unknown'))
            findings.append({
                'scanner': 'ZAP',
                'cve_id': make_zap_id(plugin_id, alert_name),
                'alert_name': alert_name,
                'severity': normalize_zap_severity(alert),
                'description': smart_truncate(alert.get('desc', ''), 500),
                'solution': alert.get('solution', ''),
                'instances': str(len(alert.get('instances', []))),
            })
    return findings


def get_ai_remediation(finding):
    """Send a vulnerability finding to the AI endpoint and get fix suggestion."""
    try:
        # Build a rich, length-controlled description for the AI
        description_parts = []
        if finding.get('title'):
            description_parts.append(smart_truncate(finding['title'], 200))
        if finding.get('description'):
            description_parts.append(smart_truncate(finding['description'], 400))
        if finding.get('alert_name') and finding.get('alert_name') not in description_parts:
            description_parts.append(finding['alert_name'])

        description = smart_truncate('. '.join(description_parts), 600)

        # Build vulnerable code context (accumulate, don't overwrite)
        context_bits = []
        if finding.get('package') and finding.get('installed_version'):
            context_bits.append(f"Package: {finding['package']}@{finding['installed_version']}")
        if finding.get('fixed_version') and finding['fixed_version'] not in ('No fix available', 'N/A', ''):
            context_bits.append(f"Fix available: {finding['fixed_version']}")
        if finding.get('component'):
            context_bits.append(f"File: {finding['component']}")
        if finding.get('alert_name'):
            context_bits.append(f"DAST Alert: {finding['alert_name']}")
        code_context = ' | '.join(context_bits)

        payload = {
            'cve_id': finding.get('cve_id', ''),
            'description': description,
            'vulnerable_code': code_context,
            'severity': finding.get('severity', ''),
            'scanner': finding.get('scanner', '')
        }

        response = requests.post(
            f'{AI_ENDPOINT}/remediate',
            json=payload,
            timeout=120
        )

        if response.status_code == 200:
            result = response.json()
            # Mark as success if endpoint didn't already set a status
            if 'status' not in result:
                result['status'] = 'success'
            return result
        else:
            return {
                'status': 'error',
                'cve_id': finding.get('cve_id', ''),
                'explanation': f'AI server returned HTTP {response.status_code}',
                'fix_suggestion': 'AI suggestion unavailable. Please review manually.',
                'severity': finding.get('severity', 'UNKNOWN')
            }

    except requests.exceptions.ConnectionError:
        return {
            'status': 'error',
            'cve_id': finding.get('cve_id', ''),
            'explanation': 'Cannot connect to AI endpoint',
            'fix_suggestion': 'AI suggestion unavailable. Please review manually.',
            'severity': finding.get('severity', 'UNKNOWN')
        }
    except requests.exceptions.Timeout:
        return {
            'status': 'timeout',
            'cve_id': finding.get('cve_id', ''),
            'explanation': 'AI request timed out after 120 seconds',
            'fix_suggestion': 'AI suggestion unavailable. Please review manually.',
            'severity': finding.get('severity', 'UNKNOWN')
        }
    except Exception as e:
        return {
            'status': 'error',
            'cve_id': finding.get('cve_id', ''),
            'explanation': str(e),
            'fix_suggestion': 'AI suggestion unavailable. Please review manually.',
            'severity': finding.get('severity', 'UNKNOWN')
        }


def main():
    print('=' * 60)
    print('  M1 AI REMEDIATION ENGINE - Stage 8')
    print('  AI Endpoint: ' + AI_ENDPOINT)
    print('=' * 60)

    # ---- COLLECT ALL FINDINGS ----
    all_findings = []

    # 1. Parse unified-scan-report.json (Trivy + OWASP DC + SonarQube)
    unified = load_json('unified-scan-report.json')
    if unified:
        trivy_findings = parse_trivy_from_unified(unified)
        print(f'\n  [Trivy]     Vulnerabilities found: {len(trivy_findings)}')
        all_findings.extend(trivy_findings)

        owasp_findings = parse_owasp_dc_from_unified(unified)
        print(f'  [OWASP-DC]  Vulnerabilities found: {len(owasp_findings)}')
        all_findings.extend(owasp_findings)

        sonar_findings = parse_sonarqube_from_unified(unified)
        print(f'  [SonarQube] Issues found: {len(sonar_findings)}')
        all_findings.extend(sonar_findings)
    else:
        # Fallback: try individual report files
        trivy = load_json('trivy-report.json')
        if trivy:
            trivy_findings = []
            for r in trivy.get('Results', []):
                for v in r.get('Vulnerabilities', []):
                    trivy_findings.append({
                        'scanner': 'Trivy',
                        'cve_id': v.get('VulnerabilityID', ''),
                        'package': v.get('PkgName', ''),
                        'installed_version': v.get('InstalledVersion', ''),
                        'fixed_version': v.get('FixedVersion', 'N/A'),
                        'severity': v.get('Severity', ''),
                        'title': v.get('Title', ''),
                        'description': smart_truncate(v.get('Description', ''), 500),
                    })
            print(f'\n  [Trivy]     Vulnerabilities found: {len(trivy_findings)}')
            all_findings.extend(trivy_findings)

    # 2. Parse ZAP report (try JSON first, then HTML)
    zap_findings = parse_zap_json('zap-report.json')
    if not zap_findings:
        zap_findings = parse_zap_html('zap-report.html')
    print(f'  [ZAP]       Alerts found: {len(zap_findings)}')
    all_findings.extend(zap_findings)

    print(f'\n  TOTAL findings to process: {len(all_findings)}')

    if len(all_findings) == 0:
        print('\n  No findings to process. Creating empty results file.')
        output = {
            'pipeline': unified.get('pipeline', {}) if unified else {},
            'total_findings': 0,
            'processed': 0,
            'success': 0,
            'failed': 0,
            'truncated': False,
            'ai_endpoint': AI_ENDPOINT,
            'scanners': {'trivy': [], 'owasp_dc': [], 'sonarqube': [], 'zap': []},
            'results': []
        }
        with open('ai-remediation-results.json', 'w') as f:
            json.dump(output, f, indent=2)
        return

    # ---- SORT BY SEVERITY ----
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFORMATIONAL': 4, 'UNKNOWN': 5}
    all_findings.sort(key=lambda x: severity_order.get(x.get('severity', 'UNKNOWN').upper(), 5))

    # Process top N findings (to keep demo time reasonable)
    process_findings = all_findings[:MAX_FINDINGS_TO_PROCESS]
    truncated = len(all_findings) > MAX_FINDINGS_TO_PROCESS
    if truncated:
        print(f'  Processing top {MAX_FINDINGS_TO_PROCESS} of {len(all_findings)} findings '
              f'(sorted by severity)...\n')
    else:
        print(f'  Processing all {len(process_findings)} findings...\n')

    # ---- SEND TO AI ----
    results = []
    success_count = 0
    fail_count = 0

    for i, finding in enumerate(process_findings):
        scanner = finding['scanner']
        cve = finding.get('cve_id', finding.get('alert_name', 'N/A'))
        severity = finding.get('severity', '?')

        print(f'  [{i+1:2d}/{len(process_findings)}] {scanner:10s} | {severity:8s} | {cve}')

        ai_result = get_ai_remediation(finding)

        results.append({
            'finding': finding,
            'ai_suggestion': ai_result
        })

        # Count as failure ONLY if status is explicitly error/timeout
        if ai_result.get('status') in ('error', 'timeout'):
            fail_count += 1
        else:
            success_count += 1

    # ---- ORGANIZE BY SCANNER ----
    scanner_results = {'trivy': [], 'owasp_dc': [], 'sonarqube': [], 'zap': []}
    for r in results:
        scanner = r['finding']['scanner']
        if scanner == 'Trivy':
            scanner_results['trivy'].append(r)
        elif scanner == 'OWASP-DC':
            scanner_results['owasp_dc'].append(r)
        elif scanner == 'SonarQube':
            scanner_results['sonarqube'].append(r)
        elif scanner == 'ZAP':
            scanner_results['zap'].append(r)

    # ---- SAVE RESULTS ----
    output = {
        'pipeline': unified.get('pipeline', {}) if unified else {},
        'total_findings': len(all_findings),
        'processed': len(results),
        'success': success_count,
        'failed': fail_count,
        'truncated': truncated,
        'max_processed': MAX_FINDINGS_TO_PROCESS,
        'ai_endpoint': AI_ENDPOINT,
        'scanners': scanner_results,
        'results': results
    }

    with open('ai-remediation-results.json', 'w') as f:
        json.dump(output, f, indent=2)

    # ---- SUMMARY ----
    print(f'\n{"=" * 60}')
    print(f'  REMEDIATION COMPLETE')
    print(f'  Total findings:  {len(all_findings)}')
    print(f'  Processed:       {len(results)}'
          f'{" (truncated)" if truncated else ""}')
    print(f'  AI Success:      {success_count}')
    print(f'  AI Failed:       {fail_count}')
    print(f'  Results saved:   ai-remediation-results.json')
    print(f'{"=" * 60}')


if __name__ == '__main__':
    main()