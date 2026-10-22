# ScanRelay hosted edition: one hardened relay per pilot tenant on AWS.
#
# Design goals
#  * Never an open relay: port 587 is reachable ONLY from var.allowed_cidrs
#    (the customer's office egress IPs), and the relay also enforces
#    SCANRELAY_ALLOW_IPS / SMTP AUTH itself.
#  * No secrets in Terraform state: the Graph client secret lives in an
#    existing Secrets Manager secret that you create out of band; Terraform
#    only references its ARN and grants the instance read access to it.
#  * No SSH: admin access is via SSM Session Manager. IMDSv2 only. Encrypted EBS.
#
# Cost (us-east-2, on-demand): t4g.small ~$12/mo + EIP ~$3.6/mo + secret $0.40/mo.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = "scanrelay"
      Tenant    = var.name
      ManagedBy = "terraform"
    }
  }
}

data "aws_ssm_parameter" "al2023_arm" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

data "aws_vpc" "default" {
  count   = var.vpc_id == "" ? 1 : 0
  default = true
}

data "aws_subnets" "default" {
  count = var.subnet_id == "" ? 1 : 0
  filter {
    name   = "vpc-id"
    values = [local.vpc_id]
  }
}

locals {
  vpc_id    = var.vpc_id != "" ? var.vpc_id : data.aws_vpc.default[0].id
  subnet_id = var.subnet_id != "" ? var.subnet_id : sort(data.aws_subnets.default[0].ids)[0]
  prefix    = "scanrelay-${var.name}"
}

resource "aws_security_group" "relay" {
  name        = local.prefix
  description = "ScanRelay ${var.name}: SMTP submission from customer IPs only"
  vpc_id      = local.vpc_id

  ingress {
    description = "SMTP submission (STARTTLS required) from customer egress IPs"
    from_port   = 587
    to_port     = 587
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }

  dynamic "ingress" {
    for_each = var.tls_hostname != "" ? [1] : []
    content {
      description = "ACME HTTP-01 for the relay's TLS certificate"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  egress {
    description = "HTTPS to Graph, Entra, Secrets Manager, SSM, package repos"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP for package mirrors"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "relay" {
  name               = local.prefix
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "secret" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.secret_arn]
  }
}

resource "aws_iam_role_policy" "secret" {
  name   = "read-relay-secret"
  role   = aws_iam_role.relay.id
  policy = data.aws_iam_policy_document.secret.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.relay.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "relay" {
  name = local.prefix
  role = aws_iam_role.relay.name
}

resource "aws_instance" "relay" {
  ami                         = data.aws_ssm_parameter.al2023_arm.value
  instance_type               = var.instance_type
  subnet_id                   = local.subnet_id
  vpc_security_group_ids      = [aws_security_group.relay.id]
  iam_instance_profile        = aws_iam_instance_profile.relay.name
  associate_public_ip_address = true
  user_data_replace_on_change = true

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    region        = var.region
    secret_arn    = var.secret_arn
    repo_url      = var.repo_url
    repo_ref      = var.repo_ref
    tls_hostname  = var.tls_hostname
    acme_email    = var.acme_email
    allowed_cidrs = join(",", var.allowed_cidrs)
  })

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size = 16
    volume_type = "gp3"
    encrypted   = true
  }

  tags = { Name = local.prefix }
}

resource "aws_eip" "relay" {
  domain   = "vpc"
  instance = aws_instance.relay.id
  tags     = { Name = local.prefix }
}
