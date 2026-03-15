variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "key_pair_name" {
  description = "EC2 key pair name"
  type        = string
}

variable "docker_hub_user" {
  description = "Docker Hub username"
  type        = string
}

variable "docker_hub_pass" {
  description = "Docker Hub password"
  type        = string
  sensitive   = true
}

variable "jenkins_admin_pass" {
  description = "Jenkins admin password"
  type        = string
  sensitive   = true
}

variable "sonarqube_token" {
  description = "SonarQube auth token"
  type        = string
  sensitive   = true
  default     = ""
}

variable "ec2_ssh_private_key" {
  description = "Private key for App EC2 SSH"
  type        = string
  sensitive   = true
}
