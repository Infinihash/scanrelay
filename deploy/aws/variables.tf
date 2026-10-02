variable "name" {
  description = "Short tenant slug, e.g. acme-dental. Used in resource names."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,30}$", var.name))
    error_message = "name must be 2-31 chars of a-z, 0-9 and '-'."
  }
}

variable "region" {
  type    = string
  default = "us-east-2"
}

variable "allowed_cidrs" {
  description = "Customer office egress IPs/CIDRs allowed to reach port 587. Never 0.0.0.0/0."
  type        = list(string)
  validation {
    condition = length(var.allowed_cidrs) > 0 && alltrue([
      for c in var.allowed_cidrs : can(cidrhost(c, 0)) && !endswith(c, "/0")
    ])
    error_message = "allowed_cidrs must be a non-empty list of valid CIDRs and may not contain a /0."
  }
}

variable "secret_arn" {
  description = <<-EOT
    ARN of an existing Secrets Manager secret whose SecretString is a JSON object of
    SCANRELAY_* env vars (TENANT_ID, CLIENT_ID, CLIENT_SECRET, SENDER, USERS, ...).
    Create it out of band so the client secret never enters Terraform state.
  EOT
  type        = string
  validation {
    condition     = can(regex("^arn:aws:secretsmanager:", var.secret_arn))
    error_message = "secret_arn must be a Secrets Manager ARN."
  }
}

variable "tls_hostname" {
  description = "DNS name (A record -> the EIP) for a Let's Encrypt cert. Empty = self-signed cert."
  type        = string
  default     = ""
}

variable "acme_email" {
  description = "Contact email for Let's Encrypt (required when tls_hostname is set)."
  type        = string
  default     = ""
}

variable "instance_type" {
  type    = string
  default = "t4g.small"
}

variable "repo_url" {
  type    = string
  default = "https://github.com/Infinihash/scanrelay.git"
}

variable "repo_ref" {
  description = "Git tag or commit to build. Pin this in production."
  type        = string
  default     = "main"
}

variable "vpc_id" {
  description = "Empty = default VPC."
  type        = string
  default     = ""
}

variable "subnet_id" {
  description = "Public subnet. Empty = first default subnet."
  type        = string
  default     = ""
}
