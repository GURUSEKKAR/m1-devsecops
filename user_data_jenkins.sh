#!/bin/bash
set -e
exec > /var/log/user-data.log 2>&1

# ── Part 1: System packages ──────────────────────
apt-get update -y
apt-get install -y openjdk-17-jdk git curl wget unzip gnupg2 docker.io

systemctl enable docker
systemctl start docker

# ── Part 2: Install Jenkins ──────────────────────
curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key \
  | tee /usr/share/keyrings/jenkins-keyring.asc > /dev/null

echo "deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] \
  https://pkg.jenkins.io/debian-stable binary/" \
  | tee /etc/apt/sources.list.d/jenkins.list > /dev/null

apt-get update -y
apt-get install -y jenkins

usermod -aG docker jenkins

# ── Part 3: Install Trivy ────────────────────────
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
  | gpg --dearmor | tee /usr/share/keyrings/trivy.gpg > /dev/null

echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] \
  https://aquasecurity.github.io/trivy-repo/deb generic main" \
  | tee /etc/apt/sources.list.d/trivy.list

apt-get update -y
apt-get install -y trivy

# ── Part 4: Install OWASP Dependency Check ───────
DC_VERSION="9.0.9"
wget -q "https://github.com/jeremylong/DependencyCheck/releases/download/v${dc_version}/dependency-check-${dc_version}-release.zip" \
  -O /tmp/dc.zip
unzip -q /tmp/dc.zip -d /opt/
chmod +x /opt/dependency-check/bin/dependency-check.sh
ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check

# ── Part 5: Install Jenkins plugins ─────────────
JENKINS_HOME=/var/lib/jenkins
mkdir -p $JENKINS_HOME

# Download plugin installation manager
wget -q https://github.com/jenkinsci/plugin-installation-manager-tool/releases/download/2.12.15/jenkins-plugin-manager-2.12.15.jar \
  -O /tmp/jenkins-plugin-manager.jar

# Wait for Jenkins to create its home directory
sleep 30

java -jar /tmp/jenkins-plugin-manager.jar \
  --war /usr/share/java/jenkins.war \
  --plugin-download-directory $JENKINS_HOME/plugins \
  --plugins \
    configuration-as-code:1810.v9b_c30a_249a_4c \
    docker-plugin:1.6.2 \
    docker-workflow:572.v950f58993843 \
    sonar:2.17.2 \
    ssh-agent:376.v8933585c73f9 \
    htmlpublisher:1.32 \
    github:1.39.0 \
    credentials-binding:677.vdc9d4f2f5d8e \
    email-ext:2.105 \
    git:5.2.2 \
    pipeline-stage-view:2.35 \
    workflow-aggregator:596.v8c21c963d92d

# ── Part 6: Download JCasC YAML ─────────────────
curl -o $JENKINS_HOME/jenkins-casc.yaml \
  "${github_casc_url}"

# ── Part 7: Set environment variables ────────────
cat >> /etc/environment <<EOF
CASC_JENKINS_CONFIG=$JENKINS_HOME/jenkins-casc.yaml
JENKINS_ADMIN_PASSWORD=${jenkins_admin_pass}
DOCKER_HUB_USER=${docker_hub_user}
DOCKER_HUB_PASS=${docker_hub_pass}
SONARQUBE_TOKEN=${sonarqube_token}
EC2_SSH_PRIVATE_KEY="${ec2_ssh_private_key}"
EOF

# Source the environment
export CASC_JENKINS_CONFIG=$JENKINS_HOME/jenkins-casc.yaml
export JENKINS_ADMIN_PASSWORD="${jenkins_admin_pass}"

# ── Part 8: Start SonarQube ──────────────────────
docker run -d \
  --name sonarqube \
  --restart unless-stopped \
  -p 9000:9000 \
  sonarqube:community

# ── Part 9: Start Jenkins ────────────────────────
chown -R jenkins:jenkins $JENKINS_HOME
systemctl enable jenkins
systemctl start jenkins

echo "SETUP COMPLETE" >> /var/log/user-data.log
