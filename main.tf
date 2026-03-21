provider "aws" {
  region = var.aws_region
}

resource "aws_vpc" "m1_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags = { Name = "m1-vpc" }
}

resource "aws_internet_gateway" "m1_igw" {
  vpc_id = aws_vpc.m1_vpc.id
  tags   = { Name = "m1-igw" }
}

resource "aws_subnet" "m1_subnet" {
  vpc_id                  = aws_vpc.m1_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"
  tags = { Name = "m1-subnet" }
}

resource "aws_route_table" "m1_rt" {
  vpc_id = aws_vpc.m1_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.m1_igw.id
  }
  tags = { Name = "m1-rt" }
}

resource "aws_route_table_association" "m1_rta" {
  subnet_id      = aws_subnet.m1_subnet.id
  route_table_id = aws_route_table.m1_rt.id
}

resource "aws_security_group" "jenkins_sg" {
  name   = "m1-jenkins-sg"
  vpc_id = aws_vpc.m1_vpc.id

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 9000
    to_port     = 9000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "m1-jenkins-sg" }
}

resource "aws_security_group" "app_sg" {
  name   = "m1-app-sg"
  vpc_id = aws_vpc.m1_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.jenkins_sg.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "m1-app-sg" }
}

resource "aws_eip" "jenkins_eip" {
  domain   = "vpc"
  instance = aws_instance.jenkins_ec2.id
  tags     = { Name = "m1-jenkins-eip" }
}

resource "aws_instance" "jenkins_ec2" {
  ami                    = "ami-07216ac99dc46a187"
  instance_type = "t3.micro"
  key_name               = var.key_pair_name
  subnet_id              = aws_subnet.m1_subnet.id
  vpc_security_group_ids = [aws_security_group.jenkins_sg.id]

  root_block_device {
    volume_size = 20

  }

  user_data = templatefile("user_data_jenkins.sh", {
    docker_hub_user     = var.docker_hub_user
    docker_hub_pass     = var.docker_hub_pass
    jenkins_admin_pass  = var.jenkins_admin_pass
    sonarqube_token     = var.sonarqube_token
    ec2_ssh_private_key = var.ec2_ssh_private_key
    github_casc_url     = "https://raw.githubusercontent.com/GURUSEKKAR/m1-devsecops/main/jenkins-casc.yaml"
    dc_version          = "9.0.9"
  })

  tags = { Name = "m1-jenkins" }
}

resource "aws_instance" "app_ec2" {
  ami                    = "ami-07216ac99dc46a187"
  instance_type = "t3.micro"
  key_name               = var.key_pair_name
  subnet_id              = aws_subnet.m1_subnet.id
  vpc_security_group_ids = [aws_security_group.app_sg.id]

  user_data = <<-EOF
    #!/bin/bash
    apt-get update -y
    apt-get install -y docker.io
    systemctl enable docker
    systemctl start docker
    usermod -aG docker ubuntu
  EOF

  tags = { Name = "m1-app" }
}

output "jenkins_url" {
  value = "http://${aws_eip.jenkins_eip.public_ip}:8080"
}

output "app_ec2_ip" {
  value = aws_instance.app_ec2.public_ip
}

output "ssh_jenkins" {
  value = "ssh -i ~/.ssh/m1-key.pem ubuntu@${aws_eip.jenkins_eip.public_ip}"
}

output "ssh_app" {
  value = "ssh -i ~/.ssh/m1-key.pem ubuntu@${aws_instance.app_ec2.public_ip}"
}
