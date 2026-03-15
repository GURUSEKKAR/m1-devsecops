pipeline {
  agent any

  environment {
    IMAGE_NAME  = "YOURDOCKERHUBNAME/m1-app"
    APP_EC2_IP  = ""   // will be filled after terraform apply
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
              trivy image \
                --format json \
                --output trivy-report.json \
                --exit-code 0 \
                --severity CRITICAL,HIGH \
                ${IMAGE_NAME}:${BUILD_NUMBER}
            """
          }
          post {
            always { archiveArtifacts artifacts: 'trivy-report.json', allowEmptyArchive: true }
          }
        }

        stage('3B - OWASP DC') {
          steps {
            sh """
              dependency-check \
                --project m1-app \
                --scan . \
                --format JSON \
                --out . \
                --failOnCVSS 11 \
                --nvdApiDelay 4000 || true
              mv dependency-check-report.json owasp-dc-report.json || true
            """
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
                  -Dsonar.host.url=http://localhost:9000
              """
            }
          }
        }

      }
    }

    stage('4 - Decision Gate') {
      steps {
        script {
          def criticalCount = 0
          try {
            def trivyReport = readJSON file: 'trivy-report.json'
            trivyReport.Results?.each { result ->
              result.Vulnerabilities?.each { vuln ->
                if (vuln.Severity == 'CRITICAL') criticalCount++
              }
            }
          } catch (e) {
            echo "Could not parse trivy report: ${e.message}"
          }

          env.CRITICAL_COUNT = criticalCount.toString()
          echo "Critical vulnerabilities found: ${criticalCount}"

          if (criticalCount > 0) {
            error("GATE FAILED: ${criticalCount} CRITICAL vulnerabilities. Pipeline aborted.")
          }
          echo "Gate PASSED — continuing pipeline."
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
            echo $DOCKER_PASS | docker login -u $DOCKER_USER --password-stdin
            docker push ${IMAGE_NAME}:${BUILD_NUMBER}
            docker push ${IMAGE_NAME}:latest
            docker logout
          """
        }
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
            sleep 15
            curl --retry 5 --retry-delay 5 --retry-connrefused \
              http://${APP_EC2_IP}:80 > /dev/null
            echo "Health check PASSED - app is live"
          """
        }
      }
    }

    stage('7 - OWASP ZAP DAST') {
      steps {
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
      post {
        always {
          archiveArtifacts artifacts: 'zap-report.html, zap-report.json', allowEmptyArchive: true
          publishHTML(target: [
            allowMissing: true,
            reportName:   'ZAP Security Report',
            reportDir:    '.',
            reportFiles:  'zap-report.html'
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
