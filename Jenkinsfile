pipeline {
  agent any

  environment {
    IMAGE_NAME      = "gurusekkarreddy/m1-app"
    APP_EC2_IP      = "3.111.85.206"
    AI_ENDPOINT_URL = "https://shaunte-fixtureless-carolin.ngrok-free.dev"
  }

  triggers {
    githubPush()
  }

  options {
    timeout(time: 45, unit: 'MINUTES')
    disableConcurrentBuilds()
  }

  stages {

    // ─────────────────────────────────────────────────────────────
    // STAGE 0 — Start SonarQube
    // ─────────────────────────────────────────────────────────────
    stage('0 - Prepare') {
      steps {
        sh """
          docker start sonarqube || true
          sleep 60
          curl -s http://localhost:9000/api/system/status || true
        """
        echo "SonarQube started"
      }
    }

    // ─────────────────────────────────────────────────────────────
    // STAGE 1 — Checkout
    // ─────────────────────────────────────────────────────────────
    stage('1 - Checkout') {
      steps {
        checkout scm
        echo "Commit: ${env.GIT_COMMIT} | Branch: ${env.GIT_BRANCH}"
      }
    }

    // ─────────────────────────────────────────────────────────────
    // STAGE 2 — Docker Build
    // ─────────────────────────────────────────────────────────────
    stage('2 - Docker Build') {
      steps {
        sh "docker build --no-cache -t ${IMAGE_NAME}:${BUILD_NUMBER} -t ${IMAGE_NAME}:latest ."
        echo "Image built: ${IMAGE_NAME}:${BUILD_NUMBER}"
      }
    }

    // ─────────────────────────────────────────────────────────────
    // STAGE 3 — Parallel Security Scans
    // ─────────────────────────────────────────────────────────────
    stage('3 - Security Scans') {
      parallel {

        // ── 3A: Trivy ──────────────────────────────────────────
        stage('3A - Trivy') {
          steps {
            sh """
              mkdir -p /tmp/trivy-cache
              TRIVY_CONFIG=/dev/null trivy image \
                --cache-dir /tmp/trivy-cache \
                --format json \
                --output trivy-report.json \
                --exit-code 0 \
                --ignore-unfixed \
                --severity CRITICAL,HIGH \
                --no-progress \
                ${IMAGE_NAME}:${BUILD_NUMBER}
            """
          }
          post {
            always {
              archiveArtifacts artifacts: 'trivy-report.json',
                               allowEmptyArchive: true
            }
          }
        }

        // ── 3B: OWASP DC (npm audit) ───────────────────────────
        // FIX: must `npm install` first to generate package-lock.json
        // and node_modules. Without this, `npm audit` returns empty
        // because there's nothing to audit. Use --legacy-peer-deps
        // because intentionally-old packages have peer-dep conflicts.
        // ───────────────────────────────────────────────────────
        stage('3B - OWASP DC') {
          steps {
            sh '''
              cd src
              echo "===== Installing npm packages for audit ====="
              npm install --package-lock-only --legacy-peer-deps --no-audit --no-fund 2>&1 || \
                npm install --legacy-peer-deps --no-audit --no-fund 2>&1 || true

              echo "===== Running npm audit ====="
              npm audit --json --legacy-peer-deps > ../npm-audit-raw.json 2>&1 || true

              echo "===== Audit raw output (first 500 chars) ====="
              head -c 500 ../npm-audit-raw.json || true
              echo ""
              cd ..

              python3 << 'PYEOF'
import json
try:
    with open('npm-audit-raw.json') as f:
        audit = json.load(f)
    deps = []
    vulns = audit.get('vulnerabilities', {})
    score_map = {
        'critical': 9.5,
        'high':     8.0,
        'moderate': 5.0,
        'low':      2.0
    }
    for name, info in vulns.items():
        sev = info.get('severity', 'low')
        via      = info.get('via', [{}])
        cve_name = (via[0].get('name', name)
                    if isinstance(via[0], dict) else name)
        # Include critical, high, AND moderate (matches Trivy + Sonar coverage)
        if sev in ('critical', 'high', 'moderate'):
            v = {
                'fileName': name,
                'vulnerabilities': [{
                    'name':    cve_name,
                    'severity': sev.upper(),
                    'description': (via[0].get('title', '')
                                    if isinstance(via[0], dict) else ''),
                    'cvssv3':  {'baseScore': score_map.get(sev, 0)}
                }]
            }
            deps.append(v)
    with open('owasp-dc-report.json', 'w') as f:
        json.dump({'dependencies': deps}, f, indent=2)
    print(f"OWASP DC: {len(deps)} MODERATE+ findings written")
except Exception as e:
    print(f"OWASP DC parse error: {e}")
    with open('owasp-dc-report.json', 'w') as f:
        json.dump({'dependencies': []}, f)
PYEOF
            '''
          }
          post {
            always {
              archiveArtifacts artifacts: 'owasp-dc-report.json, npm-audit-raw.json',
                               allowEmptyArchive: true
            }
          }
        }

        // ── 3C: SonarQube ──────────────────────────────────────
        stage('3C - SonarQube') {
          steps {
            withSonarQubeEnv('SonarQube') {
              sh """
                sonar-scanner \
                  -Dsonar.projectKey=m1-app \
                  -Dsonar.projectName=m1-app \
                  -Dsonar.sources=src \
                  -Dsonar.host.url=http://localhost:9000 \
                  -Dsonar.exclusions='**/node_modules/**,**/*.json'
              """
            }
            // Wait for analysis to be ingested before Stage 3.5 queries the API
            sh 'sleep 15'
          }
        }

      }
    }

    // ─────────────────────────────────────────────────────────────
    // STAGE 3.5 — Collect & Merge Reports
    // FIX: Sonar API call now also queries ALL severities so the
    // unified report can show real issue counts even if the Quality
    // Gate didn't trip. Stage 4 still uses Quality Gate for the
    // gating decision.
    // ─────────────────────────────────────────────────────────────
    stage('3.5 - Collect Reports') {
      steps {
        script {
          def unified = [
            pipeline: [
              build_number: env.BUILD_NUMBER,
              timestamp:    new Date().format("yyyy-MM-dd HH:mm:ss"),
              commit:       env.GIT_COMMIT,
              branch:       env.GIT_BRANCH
            ],
            scanners: [:]
          ]

          try {
            unified.scanners.trivy = readJSON file: 'trivy-report.json'
            echo "Trivy report loaded"
          } catch (e) {
            unified.scanners.trivy = [error: "Report not available"]
          }

          try {
            unified.scanners.owasp_dc = readJSON file: 'owasp-dc-report.json'
            echo "OWASP DC report loaded"
          } catch (e) {
            unified.scanners.owasp_dc = [error: "Report not available"]
          }

          try {
            withCredentials([string(credentialsId: 'sonarqube-token',
                                    variable: 'SONAR_TOKEN')]) {
              // FIX: pull ALL severities, not just CRITICAL/MAJOR/BLOCKER
              // so the unified report sees the full picture
              def response = sh(
                script: """curl -s -u \${SONAR_TOKEN}: \
                  'http://localhost:9000/api/issues/search?\
projectKeys=m1-app&ps=500'""",
                returnStdout: true
              ).trim()
              unified.scanners.sonarqube = readJSON text: response
              def issueCount = unified.scanners.sonarqube.issues?.size() ?: 0
              echo "SonarQube report loaded: ${issueCount} issues"
            }
          } catch (e) {
            unified.scanners.sonarqube = [error: "Report not available"]
          }

          writeJSON file: 'unified-scan-report.json',
                    json: unified, pretty: 2
          echo "Unified report saved"
        }
      }
      post {
        always {
          archiveArtifacts artifacts: 'unified-scan-report.json',
                           allowEmptyArchive: true
        }
      }
    }

    // ─────────────────────────────────────────────────────────────
    // STAGE 4 — Decision Gate
    // FIX: Sonar branch now counts BLOCKER/CRITICAL issues directly
    // instead of relying solely on the Quality Gate status. This
    // means hardcoded credentials, eval(), command injection, etc.
    // actually contribute to the critical count.
    // ─────────────────────────────────────────────────────────────
    stage('4 - Decision Gate') {
      steps {
        script {
          def criticalCount = 0
          def highCount     = 0
          def summary       = []

          // ── Trivy ──
          try {
            def trivy = readJSON file: 'trivy-report.json'
            def tc = 0; def th = 0
            trivy.Results?.each { r ->
              r.Vulnerabilities?.each { v ->
                if (v.Severity == 'CRITICAL') { tc++; criticalCount++ }
                if (v.Severity == 'HIGH')     { th++; highCount++ }
              }
            }
            summary.add("Trivy: ${tc} CRITICAL, ${th} HIGH (unfixed excluded)")
          } catch (e) {
            summary.add("Trivy: report not available")
          }

          // ── OWASP DC ──
          try {
            def owasp = readJSON file: 'owasp-dc-report.json'
            def oc = 0; def oh = 0
            owasp.dependencies?.each { d ->
              d.vulnerabilities?.each { v ->
                def score = v.cvssv3?.baseScore ?: v.cvssv2?.score ?: 0
                if (score >= 9.0)      { oc++; criticalCount++ }
                else if (score >= 7.0) { oh++; highCount++ }
              }
            }
            summary.add("OWASP DC: ${oc} CRITICAL, ${oh} HIGH")
          } catch (e) {
            summary.add("OWASP DC: report not available")
          }

          // ── SonarQube — FIX: count actual issues, not just QG status ──
          try {
            withCredentials([string(credentialsId: 'sonarqube-token',
                                    variable: 'SONAR_TOKEN')]) {

              // 1. Quality Gate status (overall pass/fail)
              def qgResponse = sh(
                script: """curl -s -u \${SONAR_TOKEN}: \
                  'http://localhost:9000/api/qualitygates/project_status?\
projectKey=m1-app'""",
                returnStdout: true
              ).trim()
              def qg = readJSON text: qgResponse
              def qgStatus = qg.projectStatus?.status ?: 'UNKNOWN'

              // 2. Issue counts by severity (the part that was missing)
              def issuesResponse = sh(
                script: """curl -s -u \${SONAR_TOKEN}: \
                  'http://localhost:9000/api/issues/search?\
projectKeys=m1-app&severities=BLOCKER,CRITICAL,MAJOR&ps=500'""",
                returnStdout: true
              ).trim()
              def issues = readJSON text: issuesResponse
              def sc = 0; def sh_count = 0
              issues.issues?.each { i ->
                if (i.severity == 'BLOCKER' || i.severity == 'CRITICAL') {
                  sc++
                  criticalCount++
                } else if (i.severity == 'MAJOR') {
                  sh_count++
                  highCount++
                }
              }
              summary.add("SonarQube: ${sc} BLOCKER+CRITICAL, ${sh_count} MAJOR (Quality Gate: ${qgStatus})")

              // Also bump critical count if QG itself failed (defensive)
              if (qgStatus == 'ERROR' && sc == 0) {
                criticalCount++
                summary.add("SonarQube Quality Gate FAILED (counts as 1 critical)")
              }
            }
          } catch (e) {
            summary.add("SonarQube: check skipped (${e.message})")
          }

          echo "========== DECISION GATE SUMMARY =========="
          summary.each { echo it }
          echo "TOTAL: ${criticalCount} CRITICAL, ${highCount} HIGH"
          echo "============================================"

          env.CRITICAL_COUNT  = criticalCount.toString()
          env.HIGH_COUNT      = highCount.toString()
          env.TOTAL_FINDINGS  = (criticalCount + highCount).toString()

          if (criticalCount > 0) {
            env.GATE_RESULT = 'FAIL'
            echo "============================================"
            echo "  GATE FAILED — DEPLOYMENT BLOCKED"
            echo "  ${criticalCount} CRITICAL vulnerabilities found"
            echo "  Skipping Deploy + ZAP"
            echo "  Sending to AI for remediation..."
            echo "============================================"
          } else {
            env.GATE_RESULT = 'PASS'
            echo "============================================"
            echo "  GATE PASSED — NO CRITICAL VULNERABILITIES"
            echo "  Proceeding to Deploy + ZAP scan"
            echo "============================================"
          }
        }
      }
    }

    // ─────────────────────────────────────────────────────────────
    // STAGE 5 — Push to Docker Hub  (PASS path)
    // ─────────────────────────────────────────────────────────────
    stage('5 - Push to Docker Hub') {
      when {
        expression { env.GATE_RESULT == 'PASS' }
      }
      steps {
        echo 'Gate PASSED — Pushing image to Docker Hub...'
        withCredentials([usernamePassword(
          credentialsId: 'dockerhub-creds',
          usernameVariable: 'DOCKER_USER',
          passwordVariable: 'DOCKER_PASS'
        )]) {
          sh """
            echo \$DOCKER_PASS | docker login -u \$DOCKER_USER --password-stdin
            docker push ${IMAGE_NAME}:${BUILD_NUMBER}
            docker push ${IMAGE_NAME}:latest
            docker logout
          """
        }
      }
    }

    // ─────────────────────────────────────────────────────────────
    // STAGE 5.5 — Cleanup  (PASS path)
    // ─────────────────────────────────────────────────────────────
    stage('5.5 - Cleanup') {
      when {
        expression { env.GATE_RESULT == 'PASS' }
      }
      steps {
        sh """
          docker stop sonarqube || true
          docker image prune -f
          docker rmi ${IMAGE_NAME}:${BUILD_NUMBER} || true
        """
        echo "Cleanup done — SonarQube stopped to free memory"
      }
    }

    // ─────────────────────────────────────────────────────────────
    // STAGE 6 — Deploy to App EC2  (PASS path)
    // ─────────────────────────────────────────────────────────────
    stage('6 - Deploy to App EC2') {
      when {
        expression { env.GATE_RESULT == 'PASS' }
      }
      steps {
        echo 'Gate PASSED — Deploying to App EC2...'
        sshagent(['ec2-ssh-key']) {
          sh """
            ssh -o StrictHostKeyChecking=no ubuntu@${APP_EC2_IP} '
              docker stop m1-app 2>/dev/null || true
              docker rm   m1-app 2>/dev/null || true
              docker pull ${IMAGE_NAME}:latest
              docker run -d --name m1-app \
                --restart unless-stopped \
                -p 80:8080 \
                ${IMAGE_NAME}:latest
              echo "Container started, waiting for app to be ready..."
              sleep 5
              docker ps | grep m1-app
            '
          """
          sh """
            echo "Waiting for app to be live on port 80..."
            for i in \$(seq 1 12); do
              STATUS=\$(curl -s -o /dev/null -w '%{http_code}' \
                --max-time 5 http://${APP_EC2_IP}:80/health || echo '000')
              echo "Attempt \$i: HTTP \$STATUS"
              if [ "\$STATUS" = "200" ]; then
                echo "App is live!"
                exit 0
              fi
              sleep 5
            done
            echo "ERROR: App did not become ready after 60 seconds"
            exit 1
          """
        }
      }
    }

    // ─────────────────────────────────────────────────────────────
    // STAGE 7 — OWASP ZAP DAST  (PASS path)
    // ─────────────────────────────────────────────────────────────
    stage('7 - OWASP ZAP DAST') {
      when {
        expression { env.GATE_RESULT == 'PASS' }
      }
      steps {
        echo 'Gate PASSED — Running ZAP DAST on live app...'
        timeout(time: 10, unit: 'MINUTES') {
          sh """
            docker run --rm \
              -v \$(pwd):/zap/wrk \
              ghcr.io/zaproxy/zaproxy:stable \
              zap-baseline.py \
              -t http://${APP_EC2_IP}:80 \
              -r zap-report.html \
              -J zap-report.json \
              -I
          """
        }
      }
      post {
        always {
          archiveArtifacts artifacts: 'zap-report.html, zap-report.json',
                           allowEmptyArchive: true
        }
      }
    }

    // ─────────────────────────────────────────────────────────────
    // BLOCKED stage  (FAIL path)
    // ─────────────────────────────────────────────────────────────
    stage('BLOCKED - No Deploy') {
      when {
        expression { env.GATE_RESULT == 'FAIL' }
      }
      steps {
        echo '============================================'
        echo '  DEPLOYMENT BLOCKED'
        echo '  Critical vulnerabilities detected!'
        echo '  Stages 5, 6, 7 SKIPPED'
        echo '  Sending findings to AI for fix suggestions...'
        echo '============================================'

        sh """
          docker stop sonarqube || true
          docker image prune -f
          docker rmi ${IMAGE_NAME}:${BUILD_NUMBER} || true
        """
      }
    }

    // ─────────────────────────────────────────────────────────────
    // STAGE 8 — AI Remediation  (always runs)
    // ─────────────────────────────────────────────────────────────
    stage('8 - AI Remediation') {
      steps {
        script {
          echo '============================================'
          echo '  STAGE 8: AI REMEDIATION ENGINE'
          echo "  AI Endpoint: ${env.AI_ENDPOINT_URL}"
          echo "  Gate Result: ${env.GATE_RESULT}"
          echo '============================================'

          if (env.GATE_RESULT == 'FAIL') {
            echo '>>> BLOCKED BUILD: AI analyzing Trivy + OWASP DC + SonarQube'
            echo '>>> Goal: Generate fix suggestions so developer can resolve and push again'
          } else {
            echo '>>> PASSED BUILD: AI analyzing ALL findings including ZAP DAST'
            echo '>>> Goal: Generate improvement suggestions for deployed app'
          }

          sh 'pip3 install requests --quiet 2>/dev/null || true'

          def healthCheck = sh(
            script: """curl -s -o /dev/null -w '%{http_code}' \
              --max-time 10 ${env.AI_ENDPOINT_URL}/health || echo '000'""",
            returnStdout: true
          ).trim()

          if (healthCheck == '200') {
            echo 'AI endpoint is HEALTHY. Running remediation...'
            sh "AI_ENDPOINT_URL=${env.AI_ENDPOINT_URL} python3 ai_remediation.py"
            echo 'AI Remediation complete!'
          } else {
            echo "WARNING: AI endpoint not reachable (HTTP ${healthCheck}). Skipping AI."
            sh """python3 -c "
import json
data = {
    'pipeline': {},
    'total_findings': 0,
    'processed': 0,
    'success':   0,
    'failed':    0,
    'ai_endpoint': 'unavailable',
    'scanners': {
        'trivy': [], 'owasp_dc': [], 'sonarqube': [], 'zap': []
    },
    'results': [],
    'status': 'ai_unavailable'
}
with open('ai-remediation-results.json', 'w') as f:
    json.dump(data, f, indent=2)
print('Fallback results created.')
" """
          }
        }
      }
      post {
        always {
          archiveArtifacts artifacts: 'ai-remediation-results.json',
                           allowEmptyArchive: true
        }
      }
    }

    // ─────────────────────────────────────────────────────────────
    // STAGE 9 — Unified Report  (always runs)
    // ─────────────────────────────────────────────────────────────
    stage('9 - Unified Report') {
      steps {
        script {
          echo '============================================'
          echo '  STAGE 9: UNIFIED REPORT GENERATION'
          echo '============================================'

          sh 'python3 generate_report.py'
          echo 'Unified security report with AI suggestions generated!'
        }
      }
      post {
        always {
          archiveArtifacts artifacts: 'unified-security-report.html',
                           allowEmptyArchive: true
        }
      }
    }

    // ─────────────────────────────────────────────────────────────
    // STAGE 10 — Notification  (always runs)
    // ─────────────────────────────────────────────────────────────
    stage('10 - Notification') {
      steps {
        script {
          echo '============================================'
          echo '  STAGE 10: NOTIFICATION & DELIVERY'
          echo '============================================'

          publishHTML([
            allowMissing:         true,
            alwaysLinkToLastBuild: true,
            keepAll:              true,
            reportDir:            '.',
            reportFiles:          'unified-security-report.html',
            reportName:           'M1 Security Report',
            reportTitles:         'Unified Security Report with AI Remediation'
          ])

          echo 'Reports archived and published!'
        }
      }
    }

  }

  // ─────────────────────────────────────────────────────────────
  // POST — Email notification  (always runs)
  // ─────────────────────────────────────────────────────────────
  post {
    always {
      script {
        def status      = currentBuild.result ?: 'SUCCESS'
        def gateResult  = env.GATE_RESULT ?: 'N/A'
        def deployStatus = (gateResult == 'PASS')
          ? 'YES - App deployed and ZAP scanned'
          : 'NO - BLOCKED due to critical vulnerabilities'

        try {
          emailext(
            subject: "M1 Pipeline #${BUILD_NUMBER} | Gate: ${gateResult} | ${status}",
            body: """
====================================================
  M1 DevSecOps Pipeline - Build #${BUILD_NUMBER}
====================================================

Build Status:  ${status}
Gate Result:   ${gateResult}
Deployed:      ${deployStatus}
Commit:        ${env.GIT_COMMIT}
Branch:        ${env.GIT_BRANCH}

----------------------------------------------------
  VULNERABILITY SUMMARY
----------------------------------------------------
Critical: ${env.CRITICAL_COUNT ?: '0'}
High:     ${env.HIGH_COUNT ?: '0'}

${gateResult == 'FAIL' ? """*** DEPLOYMENT BLOCKED ***
Critical vulnerabilities were found during scanning.
The app was NOT deployed.

What to do:
1. Open the attached unified-security-report.html
2. Review AI-generated fix suggestions for each vulnerability
3. Apply the fixes to your code
4. Push again to trigger a new pipeline run
""" : """*** DEPLOYMENT SUCCESSFUL ***
No critical vulnerabilities found.
App deployed to http://${env.APP_EC2_IP}:80
ZAP DAST scan completed on the live app.

Review the attached report for:
- ZAP findings with AI fix suggestions
- Any HIGH severity items to address
"""}
----------------------------------------------------
  REPORTS
----------------------------------------------------
AI Security Report: ${env.BUILD_URL}M1_20Security_20Report/
All Artifacts:      ${env.BUILD_URL}artifact/

====================================================
  AI: Fine-Tuned CodeLLaMA 7B on CVEfixes
  M1 DevSecOps | Academic Year 2025-2026
====================================================
            """,
            attachmentsPattern: 'trivy-report.json, owasp-dc-report.json, unified-scan-report.json, zap-report.html, unified-security-report.html',
            to:       'gurusekkar@gmail.com',
            mimeType: 'text/plain'
          )
          echo "Email sent to developer"
        } catch (e) {
          echo "Email failed: ${e.message}"
        }
      }
    }
  }
}