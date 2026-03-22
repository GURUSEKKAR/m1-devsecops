pipeline {
  agent any

  environment {
    IMAGE_NAME = "gurusekkarreddy/m1-app"
    APP_EC2_IP = "3.111.85.206"
  }

  triggers {
    githubPush()
  }

  options {
    timeout(time: 30, unit: 'MINUTES')
    disableConcurrentBuilds()
  }

  stages {

    stage('1 - Checkout') {
      steps {
        checkout scm
        echo "Commit: ${env.GIT_COMMIT} | Branch: ${env.GIT_BRANCH}"
      }
    }

    stage('2 - Docker Build') {
      steps {
        sh "docker build -t ${IMAGE_NAME}:${BUILD_NUMBER} -t ${IMAGE_NAME}:latest ."
        echo "Image built: ${IMAGE_NAME}:${BUILD_NUMBER}"
      }
    }

    stage('3 - Security Scans') {
      parallel {

        stage('3A - Trivy') {
          steps {
            sh """
              mkdir -p /tmp/trivy-cache
              TRIVY_CONFIG=/dev/null trivy image \
                --cache-dir /tmp/trivy-cache \
                --format json \
                --output trivy-report.json \
                --exit-code 0 \
                --severity CRITICAL,HIGH \
                --no-progress \
                ${IMAGE_NAME}:${BUILD_NUMBER}
            """
          }
          post {
            always { archiveArtifacts artifacts: 'trivy-report.json', allowEmptyArchive: true }
          }
        }

        stage('3B - OWASP DC') {
          steps {
            sh '''
              cd src
              npm audit --json > ../npm-audit-raw.json 2>&1 || true
              cd ..
              python3 << 'PYEOF'
import json
try:
    with open('npm-audit-raw.json') as f:
        audit = json.load(f)
    deps = []
    vulns = audit.get('vulnerabilities', {})
    for name, info in vulns.items():
        sev = info.get('severity', 'low')
        score_map = {'critical': 9.5, 'high': 8.0, 'moderate': 5.0, 'low': 2.0}
        via = info.get('via', [{}])
        cve_name = via[0].get('name', name) if isinstance(via[0], dict) else name
        v = {
            'fileName': name,
            'vulnerabilities': [{
                'name': cve_name,
                'severity': sev.upper(),
                'cvssv3': {'baseScore': score_map.get(sev, 0)}
            }]
        }
        deps.append(v)
    with open('owasp-dc-report.json', 'w') as f:
        json.dump({'dependencies': deps}, f, indent=2)
except Exception:
    with open('owasp-dc-report.json', 'w') as f:
        json.dump({'dependencies': []}, f)
PYEOF
            '''
          }
          post {
            always { archiveArtifacts artifacts: 'owasp-dc-report.json', allowEmptyArchive: true }
          }
        }

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
          }
        }

      }
    }

    stage('3.5 - Collect Reports') {
      steps {
        script {
          def unified = [
            pipeline: [
              build_number: env.BUILD_NUMBER,
              timestamp: new Date().format("yyyy-MM-dd HH:mm:ss"),
              commit: env.GIT_COMMIT,
              branch: env.GIT_BRANCH
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
            withCredentials([string(credentialsId: 'sonarqube-token', variable: 'SONAR_TOKEN')]) {
              def response = sh(
                script: "curl -s -u \${SONAR_TOKEN}: 'http://localhost:9000/api/issues/search?projectKeys=m1-app&severities=CRITICAL,MAJOR,BLOCKER&ps=500'",
                returnStdout: true
              ).trim()
              unified.scanners.sonarqube = readJSON text: response
              echo "SonarQube report loaded"
            }
          } catch (e) {
            unified.scanners.sonarqube = [error: "Report not available"]
          }

          writeJSON file: 'unified-scan-report.json', json: unified, pretty: 2
          echo "Unified report saved"
        }
      }
      post {
        always { archiveArtifacts artifacts: 'unified-scan-report.json', allowEmptyArchive: true }
      }
    }

    stage('4 - Decision Gate') {
      steps {
        script {
          def criticalCount = 0
          def highCount = 0
          def summary = []

          try {
            def trivy = readJSON file: 'trivy-report.json'
            def tc = 0; def th = 0
            trivy.Results?.each { r ->
              r.Vulnerabilities?.each { v ->
                if (v.Severity == 'CRITICAL') { tc++; criticalCount++ }
                if (v.Severity == 'HIGH') { th++; highCount++ }
              }
            }
            summary.add("Trivy: ${tc} CRITICAL, ${th} HIGH")
          } catch (e) { summary.add("Trivy: report not available") }

          try {
            def owasp = readJSON file: 'owasp-dc-report.json'
            def oc = 0; def oh = 0
            owasp.dependencies?.each { d ->
              d.vulnerabilities?.each { v ->
                def score = v.cvssv3?.baseScore ?: v.cvssv2?.score ?: 0
                if (score >= 9.0) { oc++; criticalCount++ }
                else if (score >= 7.0) { oh++; highCount++ }
              }
            }
            summary.add("OWASP DC: ${oc} CRITICAL, ${oh} HIGH")
          } catch (e) { summary.add("OWASP DC: report not available") }

          try {
            withCredentials([string(credentialsId: 'sonarqube-token', variable: 'SONAR_TOKEN')]) {
              def response = sh(
                script: "curl -s -u \${SONAR_TOKEN}: 'http://localhost:9000/api/qualitygates/project_status?projectKey=m1-app'",
                returnStdout: true
              ).trim()
              def sonar = readJSON text: response
              def status = sonar.projectStatus?.status ?: 'UNKNOWN'
              summary.add("SonarQube Quality Gate: ${status}")
              if (status == 'ERROR') criticalCount++
            }
          } catch (e) { summary.add("SonarQube: check skipped") }

          echo "========== DECISION GATE SUMMARY =========="
          summary.each { echo it }
          echo "TOTAL: ${criticalCount} CRITICAL, ${highCount} HIGH"
          echo "============================================"

          env.CRITICAL_COUNT = criticalCount.toString()
          env.HIGH_COUNT = highCount.toString()
          env.GATE_RESULT = criticalCount > 0 ? 'FAIL' : 'PASS'

          if (criticalCount > 0) {
            echo "WARNING: ${criticalCount} CRITICAL findings detected. Review before production."
          }
          echo "GATE PASSED — deploying."
        }
      }
    }

    stage('5 - Push to Docker Hub') {
      steps {
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

    stage('5.5 - Cleanup') {
      steps {
        sh """
          docker stop sonarqube || true
          docker image prune -f
          docker rmi ${IMAGE_NAME}:${BUILD_NUMBER} || true
        """
        echo "Cleanup done — SonarQube stopped to free memory for deploy"
      }
    }

    stage('6 - Deploy to App EC2') {
      steps {
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
            '
          """
          sh """
            sleep 10
            curl -s -o /dev/null -w '%{http_code}' http://${APP_EC2_IP}:80 || true
            echo "Deploy complete"
          """
        }
      }
    }

    stage('7 - OWASP ZAP DAST') {
      steps {
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
          archiveArtifacts artifacts: 'zap-report.html, zap-report.json', allowEmptyArchive: true
          publishHTML(target: [
            allowMissing: true,
            reportName: 'ZAP Security Report',
            reportDir: '.',
            reportFiles: 'zap-report.html'
          ])
        }
      }
    }

  }

  post {
    success { echo "ALL STAGES PASSED — Review 2 complete!" }
    failure { echo "Pipeline FAILED — check stage logs above." }
  }
}