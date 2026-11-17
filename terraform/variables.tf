# -----------------------------------------------------------------------------
# General
# -----------------------------------------------------------------------------
variable "aws_region" {
  description = "AWS region to deploy into. Prefix lists and security groups are regional; deploy once per region."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "cloudflare-prefix-sync"
}

variable "tags" {
  description = "Tags applied to every resource (for example Owner, Environment, CostCenter)."
  type        = map(string)
  default     = {}
}

# -----------------------------------------------------------------------------
# Mode (see docs/MODES.md)
# -----------------------------------------------------------------------------
variable "mode" {
  description = "discover | audit | sync | attach | enforce. IAM permissions are granted for this mode only."
  type        = string
  default     = "sync"

  validation {
    condition     = contains(["discover", "audit", "sync", "attach", "enforce"], var.mode)
    error_message = "mode must be one of: discover, audit, sync, attach, enforce."
  }
}

variable "dry_run" {
  description = "Preview every write instead of making it. Useful for a first deployment of attach or enforce."
  type        = bool
  default     = false
}

variable "schedule_expression" {
  description = "EventBridge schedule for the Lambda."
  type        = string
  default     = "rate(6 hours)"
}

# -----------------------------------------------------------------------------
# Prefix lists
# -----------------------------------------------------------------------------
variable "create_prefix_lists" {
  description = "Create the managed IPv4 and IPv6 Cloudflare prefix lists. Set false to manage existing lists instead."
  type        = bool
  default     = true
}

variable "existing_ipv4_prefix_list_id" {
  description = "When create_prefix_lists = false: an existing IPv4 prefix list that this tool will keep in sync."
  type        = string
  default     = ""
}

variable "existing_ipv6_prefix_list_id" {
  description = "When create_prefix_lists = false: an existing IPv6 prefix list that this tool will keep in sync."
  type        = string
  default     = ""
}

variable "compare_prefix_list_ids" {
  description = "Existing prefix lists to compare with Cloudflare and report on. Read-only; never modified."
  type        = list(string)
  default     = []
}

variable "initial_ipv4_max_entries" {
  description = "MaxEntries for a created IPv4 list. Each reference from a security group counts this many rules toward the SG quota."
  type        = number
  default     = 30
}

variable "initial_ipv6_max_entries" {
  description = "MaxEntries for a created IPv6 list."
  type        = number
  default     = 20
}

# -----------------------------------------------------------------------------
# Security groups
# -----------------------------------------------------------------------------
variable "security_group_ids" {
  description = "Existing security groups to audit, report on and back up. Read-only; never modified."
  type        = list(string)
  default     = []
}

variable "managed_security_group_ids" {
  description = "Security groups that attach/enforce mode may change."
  type        = list(string)
  default     = []
}

variable "managed_tag_key" {
  description = "Security groups with this tag are also in the attach/enforce scope. Empty string disables tag opt-in."
  type        = string
  default     = "cloudflare-prefix-sync"
}

variable "managed_tag_value" {
  description = "Tag value that opts a security group in."
  type        = string
  default     = "managed"
}

variable "terraform_attach_security_group_ids" {
  description = "Security groups that get static Cloudflare ingress rules created by Terraform (independent of mode). Do not also list them in managed_security_group_ids."
  type        = list(string)
  default     = []
}

variable "demo_vpc_id" {
  description = "Demo only: create a security group in this VPC that allows ingress_ports from the managed prefix lists, and tag the deployment's prefix lists and that group so scripts/demo.py may break them on purpose. Leave empty in real deployments. See docs/DEMO.md."
  type        = string
  default     = ""
}

variable "ingress_ports" {
  description = "TCP ports that must allow Cloudflare."
  type        = list(number)
  default     = [443]
}

variable "allowed_cidrs" {
  description = "Expected non-Cloudflare sources (for example a VPN egress CIDR). Never reported or revoked."
  type        = list(string)
  default     = []
}

variable "allowed_prefix_list_ids" {
  description = "Expected prefix lists. Never reported or revoked."
  type        = list(string)
  default     = []
}

variable "allowed_source_security_group_ids" {
  description = "Expected source security groups. Never reported or revoked."
  type        = list(string)
  default     = []
}

variable "revoke_private_cidrs" {
  description = "enforce: also revoke RFC1918 / internal CIDR sources."
  type        = bool
  default     = false
}

variable "revoke_security_group_sources" {
  description = "enforce: also revoke rules that reference other security groups."
  type        = bool
  default     = false
}

variable "max_revocations_per_run" {
  description = "enforce: refuse to revoke more rules than this in one run."
  type        = number
  default     = 25
}

# Deprecated (v1): kept so existing state keeps its rules. Prefer terraform_attach_security_group_ids.
variable "target_alb_security_group_id" {
  description = "DEPRECATED. Single security group to audit and optionally attach rules to."
  type        = string
  default     = ""
}

variable "auto_attach_to_alb_security_group" {
  description = "DEPRECATED. Attach Terraform-managed rules to target_alb_security_group_id."
  type        = bool
  default     = false
}

variable "alb_ingress_port" {
  description = "DEPRECATED. Port for the target_alb_security_group_id rules."
  type        = number
  default     = 443
}

# -----------------------------------------------------------------------------
# Audit and notifications
# -----------------------------------------------------------------------------
variable "audit_enabled" {
  description = "Run the read-only exposure audit on every invocation."
  type        = bool
  default     = true
}

variable "audit_all_load_balancers" {
  description = "Also audit every internet-facing ALB/NLB in the region."
  type        = bool
  default     = false
}

variable "notification_email" {
  description = "Optional email subscribed to the SNS topic (confirm the subscription email)."
  type        = string
  default     = ""
}

variable "notify_on" {
  description = "never | alerts | drift | always. See docs/NOTIFICATIONS.md."
  type        = string
  default     = "alerts"

  validation {
    condition     = contains(["never", "alerts", "drift", "always"], var.notify_on)
    error_message = "notify_on must be one of: never, alerts, drift, always."
  }
}

variable "notify_format" {
  description = "text (readable email) or json (for automation)."
  type        = string
  default     = "text"

  validation {
    condition     = contains(["text", "json"], var.notify_format)
    error_message = "notify_format must be text or json."
  }
}

# -----------------------------------------------------------------------------
# Safety and retention
# -----------------------------------------------------------------------------
variable "min_ipv4_cidrs" {
  description = "Refuse an update if Cloudflare returns fewer IPv4 ranges than this."
  type        = number
  default     = 10
}

variable "min_ipv6_cidrs" {
  description = "Refuse an update if Cloudflare returns fewer IPv6 ranges than this."
  type        = number
  default     = 5
}

variable "max_removal_ratio" {
  description = "Refuse to remove more than this fraction of a prefix list in one run."
  type        = string
  default     = "0.50"
}

variable "backup_retention_days" {
  description = "Days to keep pre-change backups in S3."
  type        = number
  default     = 365
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the Lambda."
  type        = number
  default     = 90
}
