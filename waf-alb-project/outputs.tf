# =============================================================================
# ROOT OUTPUTS
# =============================================================================

output "web_acl_id" {
  description = "ID of the WAF Web ACL"
  value       = module.waf.web_acl_id
}

output "web_acl_arn" {
  description = "ARN of the WAF Web ACL"
  value       = module.waf.web_acl_arn
}

output "web_acl_name" {
  description = "Name of the WAF Web ACL"
  value       = module.waf.web_acl_name
}

output "web_acl_capacity" {
  description = "Web ACL capacity units consumed"
  value       = module.waf.web_acl_capacity
}

output "associated_alb_arns" {
  description = "List of ALB ARNs associated with the WAF"
  value       = module.waf.associated_alb_arns
}

output "allowlist_ip_set_arn" {
  description = "ARN of the allowlist IP set"
  value       = module.waf.allowlist_ip_set_arn
}

output "blocklist_ip_set_arn" {
  description = "ARN of the blocklist IP set"
  value       = module.waf.blocklist_ip_set_arn
}
