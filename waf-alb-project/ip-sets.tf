# =============================================================================
# Standalone IP Sets — created independently of any WAF Web ACL
# These IP sets are shared across multiple WAF deployments.
# Reference them in other tfvars via *_ip_set_arn variables.
# =============================================================================

variable "ip_sets" {
  description = "Map of IP sets to create. Key = IP set name, value = list of CIDR blocks."
  type        = map(list(string))
  default     = {}
}

variable "ip_set_region" {
  description = "AWS region for IP sets"
  type        = string
  default     = "us-east-1"
}

variable "ip_set_tags" {
  description = "Tags to apply to all IP sets"
  type        = map(string)
  default     = {}
}

resource "aws_wafv2_ip_set" "named" {
  for_each = var.ip_sets

  name               = each.key
  description        = "Managed IP set: ${each.key}"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = each.value

  tags = merge(var.ip_set_tags, { Name = each.key })
}

output "ip_set_arns" {
  description = "ARNs of all created IP sets — use these in WAF tfvars"
  value       = { for name, res in aws_wafv2_ip_set.named : name => res.arn }
}

output "ip_set_ids" {
  description = "IDs of all created IP sets"
  value       = { for name, res in aws_wafv2_ip_set.named : name => res.id }
}
