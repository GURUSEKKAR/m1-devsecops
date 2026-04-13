#!/usr/bin/env python3
"""
M1 DevSecOps Pipeline - AI Remediation Engine (Stage 8)
Reads unified-scan-report.json and zap-report.json
Sends each vulnerability to fine-tuned CodeLLaMA 7B via FastAPI
Collects AI-generated fix suggestions
"""

import json
import os
import sys
import time

try:
    import requests
except ImportError:
    os.system('pip3 install requests --quiet')
    import requests

# FastAPI endpoint URL - set via environment variable in Jenkinsfile
AI_ENDPOINT = os.environ.get('AI_ENDPOINT_URL', 'http://localhost:8000')


def load_json(filepath):
    """Safely load a JSON report file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f'  [WARN] Could not load {filepath}: {e}')
        return None


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
                'description': vuln.get('Description', '')[:500],
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
                'description': vuln.get('description', '')[:500],
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
        findings.append({
            'scanner': 'SonarQube',
            'cve_id': f"SONAR-{issue.get('rule', 'N/A')}",
            'severity': issue.get('severity', 'UNKNOWN'),
            'description': issue.get('message', '')[:500],
            'component': issue.get('component', 'N/A'),
            'line': issue.get('line', 'N/A'),
            'type': issue.get('type', 'N/A'),
        })
    return findings


def parse_zap_html(filepath):
    """Extract ZAP findings from zap-report.html using regex parsing"""
    import re
    findings = []

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        print(f'  [WARN] ZAP report not found: {filepath}')
        return findings

    # Find alerts table
    section = content[content.find('class="alerts"'):]
    rows = re.findall(r'<tr[^>]*>(.*?)</tr>', section[:5000], re.DOTALL)

    for row in rows:
        tds = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
        cleaned = [re.sub(r'<[^>]+>', '', td).strip() for td in tds]
        if len(cleaned) >= 2 and cleaned[1] in ['High', 'Medium', 'Low', 'Informational']:
            findings.append({
                'scanner': 'ZAP',
                'cve_id': f"ZAP-{cleaned[0].replace(' ', '-')[:40]}",
                'alert_name': cleaned[0],
                'severity': cleaned[1].upper(),
                'description': f"DAST finding: {cleaned[0]}",
                'instances': cleaned[2] if len(cleaned) > 2 else '1',
            })

    # Also try to get solutions from detail section
    detail_section = content[content.find('Alert Detail'):]
    solutions = re.findall(r'Solution.*?<td[^>]*>(.*?)</td>', detail_section, re.DOTALL)
    for i, sol in enumerate(solutions):
        clean_sol = re.sub(r'<[^>]+>', '', sol).strip()[:300]
        if i < len(findings) and clean_sol:
            findings[i]['zap_solution'] = clean_sol

    return findings


def parse_zap_json(filepath):
    """Extract ZAP findings from zap-report.json (if available)"""
    findings = []
    report = load_json(filepath)
    if not report:
        return findings

    for site in report.get('site', []):
        for alert in site.get('alerts', []):
            findings.append({
                'scanner': 'ZAP',
                'cve_id': f"ZAP-{alert.get('pluginid', 'N/A')}",
                'alert_name': alert.get('name', alert.get('alert', 'Unknown')),
                'severity': alert.get('riskdesc', 'UNKNOWN').split(' ')[0].upper(),
                'description': alert.get('desc', '')[:500],
                'solution': alert.get('solution', ''),
                'instances': str(len(alert.get('instances', []))),
            })
    return findings


def get_ai_remediation(finding):
    """Send a vulnerability finding to the AI endpoint and get fix suggestion."""
    try:
        # Build a rich description for the AI
        description_parts = []
        if finding.get('title'):
            description_parts.append(finding['title'])
        if finding.get('description'):
            description_parts.append(finding['description'])
        if finding.get('alert_name'):
            description_parts.append(finding['alert_name'])

        description = '. '.join(description_parts)[:600]

        # Build vulnerable code context
        code_context = ''
        if finding.get('package') and finding.get('installed_version'):
            code_context = f"Package: {finding['package']}@{finding['installed_version']}"
        if finding.get('fixed_version') and finding['fixed_version'] != 'No fix available':
            code_context += f" -> Fix available: {finding['fixed_version']}"
        if finding.get('component'):
            code_context += f" File: {finding['component']}"
        if finding.get('alert_name'):
            code_context = f"DAST Alert: {finding['alert_name']}"

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
            return response.json()
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
                        'description': v.get('Description', '')[:500],
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

    # Process top 25 findings (to keep demo time reasonable)
    process_findings = all_findings[:25]
    print(f'  Processing top {len(process_findings)} findings...\n')

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

        if ai_result.get('status') == 'success':
            success_count += 1
        else:
            fail_count += 1

        time.sleep(0.5)  # Be nice to the API

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
    print(f'  Processed:       {len(results)}')
    print(f'  AI Success:      {success_count}')
    print(f'  AI Failed:       {fail_count}')
    print(f'  Results saved:   ai-remediation-results.json')
    print(f'{"=" * 60}')


if __name__ == '__main__':
    main()
