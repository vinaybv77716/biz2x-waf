# =============================================================================
# MODULE OUTPUTS: WAF + ALB Association
# =============================================================================

output "web_acl_id" {
  description = "ID of the WAF Web ACL (null if create_waf = false)"
  value       = var.create_waf ? aws_wafv2_web_acl.this[0].id : null
}

output "web_acl_arn" {
  description = "ARN of the WAF Web ACL (null if create_waf = false)"
  value       = var.create_waf ? aws_wafv2_web_acl.this[0].arn : null
}

output "web_acl_name" {
  description = "Name of the WAF Web ACL (null if create_waf = false)"
  value       = var.create_waf ? aws_wafv2_web_acl.this[0].name : null
}

output "web_acl_capacity" {
  description = "Web ACL capacity units consumed (null if create_waf = false)"
  value       = var.create_waf ? floor(aws_wafv2_web_acl.this[0].capacity) : null
}

output "associated_alb_arns" {
  description = "List of ALB ARNs currently associated with the WAF"
  value       = var.associate_waf ? var.alb_arns : []
}

output "allowlist_ip_set_arn" {
  description = "ARN of the allowlist IP set (null if not created)"
  value       = var.create_waf && length(var.allowlist_ips) > 0 ? aws_wafv2_ip_set.allowlist[0].arn : null
}

output "blocklist_ip_set_arn" {
  description = "ARN of the blocklist IP set (null if not created)"
  value       = var.create_waf && length(var.blocklist_ips) > 0 ? aws_wafv2_ip_set.blocklist[0].arn : null
}
