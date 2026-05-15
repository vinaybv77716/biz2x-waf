# =============================================================================
# test.tfvars — Test WAF deployment
# =============================================================================
# References existing shared IP sets by ARN (created by ip-list.tfvars).
# All IP data sourced from ip-list.tfvars — no new IP sets created.
# =============================================================================

project     = "test"
environment = "dev"
aws_region  = "us-east-1"

# Backend
bucket = "bizx2-rapyder-jenkins-waf-2026"
key    = "waf-alb/test.tfstate"
region = "us-east-1"

# WAF Lifecycle
create_waf           = true
create_ip_sets_only  = false
existing_web_acl_arn = ""

# ALB Association
associate_waf = false
alb_arns      = []

# Default action
default_action = "allow"

# Required — no default in variables.tf
allow_in_us_country_codes = ["IN", "US"]

# =============================================================================
# IP Set 1 — site-24and7-AllowIP (25 IPs) — Priority 0
# ARN: arn:aws:wafv2:us-east-1:892669526097:regional/ipset/site-24and7-AllowIP/16c758f2-5b6d-4082-80fd-cd2d3afa6c7e
# =============================================================================
vpn_allowlist_ips = [
  "45.33.65.221/32",
  "139.64.132.20/32",
  "123.63.212.74/32",
  "149.28.63.4/32",
  "156.77.0.0/16",
  "8.12.17.175/32",
  "50.116.57.114/32",
  "93.177.110.3/32",
  "111.93.242.74/32",
  "182.74.72.50/32",
  "162.210.173.104/32",
  "184.74.226.42/32",
  "162.210.173.201/32",
  "125.20.89.56/29",
  "23.92.18.184/32",
  "66.135.10.99/32",
  "198.74.62.39/32",
  "38.122.225.178/32",
  "45.56.110.193/32",
  "208.249.47.2/32",
  "45.76.0.57/32",
  "198.74.56.175/32",
  "125.20.89.58/32",
  "104.192.216.226/32",
  "172.104.208.130/32",
]
vpn_allowlist_ip_set_name = "site-24and7-AllowIP"
vpn_allowlist_ip_set_arn  = "arn:aws:wafv2:us-east-1:892669526097:regional/ipset/site-24and7-AllowIP/16c758f2-5b6d-4082-80fd-cd2d3afa6c7e"
vpn_allowlist_priority    = 3

# =============================================================================
# IP Set 2 — testing (1 IP) — Priority 0
# ARN: arn:aws:wafv2:us-east-1:892669526097:regional/ipset/testing/c0336499-a8e9-49fe-83fe-61a49c089ff3
# =============================================================================
allowlist_ips         = ["11.11.11.11/32"]
allowlist_ip_set_name = "testing"
allowlist_ip_set_arn  = "arn:aws:wafv2:us-east-1:892669526097:regional/ipset/testing/c0336499-a8e9-49fe-83fe-61a49c089ff3"
allowlist_priority    = 0

# =============================================================================
# IP Set 3 — keybank-Backend-Prod-AllowIP (26 IPs) — Priority 1
# ARN: arn:aws:wafv2:us-east-1:892669526097:regional/ipset/keybank-Backend-Prod-AllowIP/c0ced8e2-aa9e-4aa0-9d90-721e79df3927
# =============================================================================
frontend_allowlist_ips = [
  "139.64.132.20/32",
  "45.33.65.221/32",
  "123.63.212.74/32",
  "149.28.63.4/32",
  "144.121.234.242/32",
  "156.77.0.0/16",
  "50.116.57.114/32",
  "8.12.17.175/32",
  "93.177.110.3/32",
  "111.93.242.74/32",
  "182.74.72.50/32",
  "162.210.173.104/32",
  "184.74.226.42/32",
  "162.210.173.201/32",
  "125.20.89.56/29",
  "23.92.18.184/32",
  "66.135.10.99/32",
  "198.74.62.39/32",
  "38.122.225.178/32",
  "45.56.110.193/32",
  "208.249.47.2/32",
  "45.76.0.57/32",
  "125.20.89.58/32",
  "198.74.56.175/32",
  "104.192.216.226/32",
  "172.104.208.130/32",
]
frontend_allowlist_ip_set_name = "keybank-Backend-Prod-AllowIP"
frontend_allowlist_ip_set_arn  = "arn:aws:wafv2:us-east-1:892669526097:regional/ipset/keybank-Backend-Prod-AllowIP/c0ced8e2-aa9e-4aa0-9d90-721e79df3927"
frontend_allowlist_priority    = 1

# =============================================================================
# IP Set 4 — Keybank-Orchestrator-Prod-BlockIP (5 IPs) — Priority 30
# ARN: arn:aws:wafv2:us-east-1:892669526097:regional/ipset/ip-list-dev-blocklist/a4f7167f-fc91-4728-bd8e-2673fb33a8e3
# =============================================================================
blocklist_ips = [
  "3.6.25.60/32",
  "139.59.93.44/32",
  "139.59.95.50/32",
  "143.110.250.43/32",
  "3.7.148.225/32",
]
blocklist_priority = 30

# =============================================================================
# All WAF rules disabled
# =============================================================================
enable_bot_control                = false
bot_control_action                = "block"
bot_control_priority              = 10
bot_control_inspection_level      = "COMMON"
bot_control_version               = ""
bot_control_rule_action_overrides = []

enable_ip_reputation                = false
ip_reputation_action                = "block"
ip_reputation_priority              = 11
ip_reputation_rule_action_overrides = []

enable_anonymous_ip                = false
anonymous_ip_action                = "block"
anonymous_ip_priority              = 12
anonymous_ip_rule_action_overrides = []

enable_aws_managed_rules                = false
aws_managed_rules_action                = "block"
aws_managed_rules_priority              = 13
aws_managed_rules_version               = ""
aws_managed_rules_rule_action_overrides = []

enable_known_bad_inputs                = false
known_bad_inputs_action                = "block"
known_bad_inputs_priority              = 14
known_bad_inputs_version               = ""
known_bad_inputs_rule_action_overrides = []

enable_sql_injection_protection         = false
sql_injection_protection_action         = "block"
sql_injection_priority                  = 15
sql_injection_version                   = ""
sql_injection_rule_action_overrides     = []

enable_linux_protection                = false
linux_protection_action                = "block"
linux_protection_priority              = 16
linux_protection_version               = ""
linux_protection_rule_action_overrides = []

enable_unix_protection                = false
unix_protection_action                = "block"
unix_protection_priority              = 17
unix_protection_rule_action_overrides = []

enable_windows_protection                = false
windows_protection_action                = "block"
windows_protection_priority              = 18
windows_protection_rule_action_overrides = []

enable_php_protection                = false
php_protection_action                = "block"
php_protection_priority              = 19
php_protection_rule_action_overrides = []

enable_wordpress_protection                = false
wordpress_protection_action                = "block"
wordpress_protection_priority              = 20
wordpress_protection_rule_action_overrides = []

enable_anti_ddos                = false
anti_ddos_action                = "block"
anti_ddos_priority              = 21
anti_ddos_rule_action_overrides = []

enable_rate_limiting   = false
rate_limiting_action   = "count"
rate_limiting_priority = 40
rate_limit_threshold   = 2000

enable_block_admin   = false
block_admin_priority = 75
block_admin_paths    = ["/admin", "/wp-admin", "/administrator", "/phpmyadmin"]

enable_block_git   = false
block_git_priority = 76

enable_block_specific_urls   = false
block_specific_urls_priority = 77
blocked_urls                 = []

enable_block_extensions   = false
block_extensions_priority = 78
blocked_extensions        = []

enable_block_african_countries     = false
block_african_countries_priority   = 80
block_african_countries_priority_2 = 801
african_country_codes_1            = []
african_country_codes_2            = []

enable_block_south_america   = false
block_south_america_priority = 81
south_america_country_codes  = []

enable_block_europe     = false
block_europe_priority   = 82
europe_country_codes    = []
block_europe_priority_2 = 83
europe_country_codes_2  = []

enable_block_asia   = false
block_asia_priority = 84
asia_country_codes  = []

enable_block_oceania   = false
block_oceania_priority = 85
oceania_country_codes  = []

enable_block_selected_countries_1   = false
block_selected_countries_1_priority = 86
selected_country_codes_1            = []

enable_block_selected_countries_2   = false
block_selected_countries_2_priority = 87
selected_country_codes_2            = []

enable_allow_country_us   = false
allow_country_us_priority = 88

enable_allow_in_us        = false
allow_in_us_priority      = 89

enable_allow_specific_urls   = false
allow_specific_urls_priority = 90
allowed_urls                 = []

enable_waf_logging  = false
log_destination_arn = ""

tags = {
  Environment = "dev"
  ManagedBy   = "Terraform"
  Project     = "test"
  Purpose     = "Testing — IP data sourced from ip-list.tfvars"
}
