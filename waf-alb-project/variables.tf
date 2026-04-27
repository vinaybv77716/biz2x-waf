# =============================================================================
# ROOT VARIABLES
# =============================================================================

variable "aws_region" {
  description = "AWS region where resources will be created"
  type        = string
  default     = "us-east-1"
}


variable "bucket" {
  description = "S3 bucket to store Terraform state"
  type        = string
}
 
variable "key" {
  description = "Path within the S3 bucket for Terraform state"
  type        = string
}
 
variable "region" {
  description = "AWS region of the S3 bucket"
  type        = string
}


variable "project" {
  description = "Project name (used in resource naming)"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# -----------------------------------------------------------------------------
# WAF Lifecycle
# -----------------------------------------------------------------------------

variable "create_waf" {
  description = "Whether to create a new WAF Web ACL"
  type        = bool
  default     = true
}

variable "existing_web_acl_arn" {
  description = "ARN of existing WAF Web ACL (required when create_waf = false)"
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# Association
# -----------------------------------------------------------------------------

variable "associate_waf" {
  description = "Whether to associate WAF with ALBs"
  type        = bool
  default     = false
}

variable "alb_arns" {
  description = "List of ALB ARNs to associate with the WAF"
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# WAF Rules
# -----------------------------------------------------------------------------

variable "default_action" {
  description = "Default action for requests that don't match any rule (allow or block)"
  type        = string
  default     = "allow"
  validation {
    condition     = contains(["allow", "block"], var.default_action)
    error_message = "Default action must be 'allow' or 'block'."
  }
}

variable "enable_aws_managed_rules" {
  description = "Enable AWS Managed Core Rule Set"
  type        = bool
  default     = true
}

variable "aws_managed_rules_priority" {
  description = "Priority for Core Rule Set rule"
  type        = number
  default     = 10
}

variable "aws_managed_rules_action" {
  description = "Action for AWS Managed Rules (block/count/allow)"
  type        = string
  default     = "block"
  validation {
    condition     = contains(["allow", "block", "count"], var.aws_managed_rules_action)
    error_message = "AWS Managed Rules action must be 'allow', 'block', or 'count'."
  }
}

variable "aws_managed_rules_rule_action_overrides" {
  description = "Per-sub-rule action overrides for AWSManagedRulesCommonRuleSet"
  type = list(object({
    name   = string
    action = string
  }))
  default = []
}

variable "enable_sql_injection_protection" {
  description = "Enable AWS Managed SQL Injection Rule Set"
  type        = bool
  default     = true
}

variable "sql_injection_priority" {
  description = "Priority for SQL Injection rule"
  type        = number
  default     = 20
}

variable "sql_injection_protection_action" {
  description = "Action for SQL Injection Protection (block/count/allow)"
  type        = string
  default     = "block"
  validation {
    condition     = contains(["allow", "block", "count"], var.sql_injection_protection_action)
    error_message = "SQL Injection Protection action must be 'allow', 'block', or 'count'."
  }
}

variable "sql_injection_rule_action_overrides" {
  description = "Per-sub-rule action overrides for AWSManagedRulesSQLiRuleSet"
  type = list(object({
    name   = string
    action = string
  }))
  default = []
}

variable "enable_rate_limiting" {
  description = "Enable rate-based blocking"
  type        = bool
  default     = false
}

variable "rate_limiting_priority" {
  description = "Priority for Rate Limiting rule"
  type        = number
  default     = 40
}

variable "rate_limiting_action" {
  description = "Action for Rate Limiting (block/count/allow)"
  type        = string
  default     = "block"
  validation {
    condition     = contains(["allow", "block", "count"], var.rate_limiting_action)
    error_message = "Rate Limiting action must be 'allow', 'block', or 'count'."
  }
}

variable "rate_limit_threshold" {
  description = "Maximum requests per 5-minute window per IP before blocking"
  type        = number
  default     = 2000
  validation {
    condition     = var.rate_limit_threshold >= 100 && var.rate_limit_threshold <= 20000000
    error_message = "Rate limit threshold must be between 100 and 20,000,000."
  }
}

# -----------------------------------------------------------------------------
# Additional AWS Managed Rules
# -----------------------------------------------------------------------------

variable "enable_known_bad_inputs" {
  description = "Enable AWS Managed Known Bad Inputs Rule Set"
  type        = bool
  default     = true
}

variable "known_bad_inputs_priority" {
  description = "Priority for Known Bad Inputs rule"
  type        = number
  default     = 15
}

variable "known_bad_inputs_action" {
  description = "Action for Known Bad Inputs (block/count/allow)"
  type        = string
  default     = "block"
  validation {
    condition     = contains(["allow", "block", "count"], var.known_bad_inputs_action)
    error_message = "Known Bad Inputs action must be 'block', 'count', or 'allow'."
  }
}

variable "known_bad_inputs_rule_action_overrides" {
  description = "Per-sub-rule action overrides for AWSManagedRulesKnownBadInputsRuleSet"
  type = list(object({
    name   = string
    action = string
  }))
  default = []
}

variable "enable_ip_reputation" {
  description = "Enable AWS Managed IP Reputation List"
  type        = bool
  default     = true
}

variable "ip_reputation_priority" {
  description = "Priority for IP Reputation rule"
  type        = number
  default     = 25
}

variable "ip_reputation_action" {
  description = "Action for IP Reputation List (block/count/allow)"
  type        = string
  default     = "block"
  validation {
    condition     = contains(["allow", "block", "count"], var.ip_reputation_action)
    error_message = "IP Reputation action must be 'block', 'count', or 'allow'."
  }
}

variable "ip_reputation_rule_action_overrides" {
  description = "Per-sub-rule action overrides for AWSManagedRulesAmazonIpReputationList"
  type = list(object({
    name   = string
    action = string
  }))
  default = []
}

variable "enable_anonymous_ip" {
  description = "Enable AWS Managed Anonymous IP List (blocks VPNs, proxies, Tor)"
  type        = bool
  default     = false
}

variable "anonymous_ip_priority" {
  description = "Priority for Anonymous IP rule"
  type        = number
  default     = 35
}

variable "anonymous_ip_action" {
  description = "Action for Anonymous IP List (block/count/allow)"
  type        = string
  default     = "block"
  validation {
    condition     = contains(["allow", "block", "count"], var.anonymous_ip_action)
    error_message = "Anonymous IP action must be 'block', 'count', or 'allow'."
  }
}

variable "enable_bot_control" {
  description = "Enable AWS Managed Bot Control Rule Set"
  type        = bool
  default     = false
}

variable "bot_control_priority" {
  description = "Priority for Bot Control rule"
  type        = number
  default     = 36
}

variable "bot_control_action" {
  description = "Action for Bot Control (block/count/allow)"
  type        = string
  default     = "block"
  validation {
    condition     = contains(["allow", "block", "count"], var.bot_control_action)
    error_message = "Bot Control action must be 'block', 'count', or 'allow'."
  }
}

variable "bot_control_inspection_level" {
  description = "Inspection level for Bot Control rule set (COMMON or TARGETED)"
  type        = string
  default     = "COMMON"
  validation {
    condition     = contains(["COMMON", "TARGETED"], var.bot_control_inspection_level)
    error_message = "Bot Control inspection level must be 'COMMON' or 'TARGETED'."
  }
}

variable "bot_control_rule_action_overrides" {
  description = "Per-sub-rule action overrides for AWSManagedRulesBotControlRuleSet"
  type = list(object({
    name   = string
    action = string
  }))
  default = []
}

variable "enable_anti_ddos" {
  description = "Enable AWS Managed Anti-DDoS Rule Set"
  type        = bool
  default     = false
}

variable "anti_ddos_priority" {
  description = "Priority for Anti-DDoS rule"
  type        = number
  default     = 37
}

variable "anti_ddos_action" {
  description = "Action for Anti-DDoS (block/count/allow)"
  type        = string
  default     = "block"
  validation {
    condition     = contains(["allow", "block", "count"], var.anti_ddos_action)
    error_message = "Anti-DDoS action must be 'block', 'count', or 'allow'."
  }
}

variable "anti_ddos_rule_action_overrides" {
  description = "Per-sub-rule action overrides for AWSManagedRulesAntiDDoSRuleSet"
  type = list(object({
    name   = string
    action = string
  }))
  default = []
}

variable "enable_linux_protection" {
  description = "Enable AWS Managed Linux Rule Set"
  type        = bool
  default     = false
}

variable "linux_protection_priority" {
  description = "Priority for Linux Protection rule"
  type        = number
  default     = 50
}

variable "linux_protection_action" {
  description = "Action for Linux Protection (block/count/allow)"
  type        = string
  default     = "block"
  validation {
    condition     = contains(["allow", "block", "count"], var.linux_protection_action)
    error_message = "Linux Protection action must be 'block', 'count', or 'allow'."
  }
}

variable "linux_protection_rule_action_overrides" {
  description = "Per-sub-rule action overrides for AWSManagedRulesLinuxRuleSet"
  type = list(object({
    name   = string
    action = string
  }))
  default = []
}

variable "enable_unix_protection" {
  description = "Enable AWS Managed Unix Rule Set"
  type        = bool
  default     = false
}

variable "unix_protection_priority" {
  description = "Priority for Unix Protection rule"
  type        = number
  default     = 55
}

variable "unix_protection_action" {
  description = "Action for Unix Protection (block/count/allow)"
  type        = string
  default     = "block"
  validation {
    condition     = contains(["allow", "block", "count"], var.unix_protection_action)
    error_message = "Unix Protection action must be 'block', 'count', or 'allow'."
  }
}

variable "unix_protection_rule_action_overrides" {
  description = "Per-sub-rule action overrides for AWSManagedRulesUnixRuleSet"
  type = list(object({
    name   = string
    action = string
  }))
  default = []
}

variable "enable_windows_protection" {
  description = "Enable AWS Managed Windows Rule Set"
  type        = bool
  default     = false
}

variable "windows_protection_priority" {
  description = "Priority for Windows Protection rule"
  type        = number
  default     = 60
}

variable "windows_protection_action" {
  description = "Action for Windows Protection (block/count/allow)"
  type        = string
  default     = "block"
  validation {
    condition     = contains(["allow", "block", "count"], var.windows_protection_action)
    error_message = "Windows Protection action must be 'block', 'count', or 'allow'."
  }
}

variable "windows_protection_rule_action_overrides" {
  description = "Per-sub-rule action overrides for AWSManagedRulesWindowsRuleSet"
  type = list(object({
    name   = string
    action = string
  }))
  default = []
}

variable "enable_php_protection" {
  description = "Enable AWS Managed PHP Rule Set"
  type        = bool
  default     = false
}

variable "php_protection_priority" {
  description = "Priority for PHP Protection rule"
  type        = number
  default     = 65
}

variable "php_protection_action" {
  description = "Action for PHP Protection (block/count/allow)"
  type        = string
  default     = "block"
  validation {
    condition     = contains(["allow", "block", "count"], var.php_protection_action)
    error_message = "PHP Protection action must be 'block', 'count', or 'allow'."
  }
}

variable "php_protection_rule_action_overrides" {
  description = "Per-sub-rule action overrides for AWSManagedRulesPHPRuleSet"
  type = list(object({
    name   = string
    action = string
  }))
  default = []
}

variable "enable_wordpress_protection" {
  description = "Enable AWS Managed WordPress Rule Set"
  type        = bool
  default     = false
}

variable "wordpress_protection_priority" {
  description = "Priority for WordPress Protection rule"
  type        = number
  default     = 70
}

variable "wordpress_protection_action" {
  description = "Action for WordPress Protection (block/count/allow)"
  type        = string
  default     = "block"
  validation {
    condition     = contains(["allow", "block", "count"], var.wordpress_protection_action)
    error_message = "WordPress Protection action must be 'block', 'count', or 'allow'."
  }
}

variable "wordpress_protection_rule_action_overrides" {
  description = "Per-sub-rule action overrides for AWSManagedRulesWordPressRuleSet"
  type = list(object({
    name   = string
    action = string
  }))
  default = []
}

# -----------------------------------------------------------------------------
# IP Lists
# -----------------------------------------------------------------------------

variable "allowlist_ips" {
  description = "List of IP CIDR blocks to always allow"
  type        = list(string)
  default     = []
}

variable "blocklist_ips" {
  description = "List of IP CIDR blocks to always block"
  type        = list(string)
  default     = []
}

variable "allowlist_priority" {
  description = "Priority for IP allowlist rule (must be unique across all rules)"
  type        = number
  default     = 5
}

variable "blocklist_priority" {
  description = "Priority for IP blocklist rule (must be unique across all rules)"
  type        = number
  default     = 30
}

# -----------------------------------------------------------------------------
# Custom Rules
# -----------------------------------------------------------------------------

variable "enable_block_admin" {
  description = "Block requests to admin paths"
  type        = bool
  default     = false
}

variable "block_admin_priority" {
  type    = number
  default = 75
}

variable "block_admin_paths" {
  description = "URI path prefixes to block as admin paths"
  type        = list(string)
  default     = ["/admin", "/wp-admin", "/administrator"]
}

variable "enable_block_git" {
  description = "Block requests to .git paths"
  type        = bool
  default     = false
}

variable "block_git_priority" {
  type    = number
  default = 76
}

variable "enable_block_specific_urls" {
  description = "Block requests matching specific URL paths"
  type        = bool
  default     = false
}

variable "block_specific_urls_priority" {
  type    = number
  default = 77
}

variable "blocked_urls" {
  description = "List of exact URI paths to block"
  type        = list(string)
  default     = []
}

variable "enable_block_extensions" {
  description = "Block requests for specific file extensions in URI path"
  type        = bool
  default     = false
}

variable "block_extensions_priority" {
  type    = number
  default = 78
}

variable "blocked_extensions" {
  description = "List of file extensions to block (e.g. .env, .bak, .sql)"
  type        = list(string)
  default     = [".env", ".bak", ".sql", ".log", ".conf", ".config"]
}

variable "enable_block_african_countries" {
  description = "Block requests from African countries"
  type        = bool
  default     = false
}

variable "block_african_countries_priority" {
  type    = number
  default = 80
}

variable "block_african_countries_priority_2" {
  type    = number
  default = 801
}

variable "african_country_codes_1" {
  description = "First batch of African country codes (max 50)"
  type        = list(string)
  default = [
    "DZ", "AO", "BJ", "BW", "BF", "BI", "CM", "CV", "CF", "TD",
    "KM", "CG", "CD", "CI", "DJ", "EG", "GQ", "ER", "ET", "GA",
    "GM", "GH", "GN", "GW", "KE", "LS", "LR", "LY", "MG", "MW",
    "ML", "MR", "MU", "MA", "MZ", "NA", "NE", "NG", "RW", "ST",
    "SN", "SL", "SO", "ZA", "SS", "SD", "SZ", "TZ", "TG", "TN"
  ]
}

variable "african_country_codes_2" {
  description = "Second batch of African country codes (overflow beyond 50)"
  type        = list(string)
  default     = ["UG", "ZM", "ZW"]
}

variable "enable_block_south_america" {
  description = "Block requests from South American countries"
  type        = bool
  default     = false
}

variable "block_south_america_priority" {
  type    = number
  default = 81
}

variable "south_america_country_codes" {
  description = "ISO 3166-1 alpha-2 country codes for South American countries to block"
  type        = list(string)
  default     = ["AR", "BO", "BR", "CL", "CO", "EC", "GY", "PY", "PE", "SR", "UY", "VE"]
}

variable "enable_block_selected_countries_1" {
  description = "Block requests from a custom list of countries (group 1)"
  type        = bool
  default     = false
}

variable "block_selected_countries_1_priority" {
  type    = number
  default = 82
}

variable "selected_country_codes_1" {
  description = "ISO 3166-1 alpha-2 country codes to block (group 1)"
  type        = list(string)
  default     = []
}

variable "enable_block_selected_countries_2" {
  description = "Block requests from a custom list of countries (group 2)"
  type        = bool
  default     = false
}

variable "block_selected_countries_2_priority" {
  type    = number
  default = 83
}

variable "selected_country_codes_2" {
  description = "ISO 3166-1 alpha-2 country codes to block (group 2)"
  type        = list(string)
  default     = []
}

variable "enable_allow_country_us" {
  description = "Allow only US traffic (block all other countries)"
  type        = bool
  default     = false
}

variable "allow_country_us_priority" {
  type    = number
  default = 84
}

variable "enable_allow_specific_urls" {
  description = "Allow specific URL paths, bypassing other rules"
  type        = bool
  default     = false
}

variable "allow_specific_urls_priority" {
  type    = number
  default = 3
}

variable "allowed_urls" {
  description = "List of URI path prefixes to explicitly allow"
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

variable "enable_waf_logging" {
  description = "Enable WAF logging to CloudWatch or S3"
  type        = bool
  default     = false
}

variable "log_destination_arn" {
  description = "ARN of CloudWatch Log Group or S3 bucket for WAF logs"
  type        = string
  default     = ""
}

