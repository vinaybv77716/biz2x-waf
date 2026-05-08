# =============================================================================
# biz2x — DEV WAF Configuration
# =============================================================================

project     = "biz2x"
environment = "dev"
aws_region  = "us-east-1"

# Backend
bucket = "bizx2-rapyder-jenkins-waf-2026"
key    = "waf-alb/terraform.tfstate"
region = "us-east-1"

# WAF Lifecycle
create_waf           = true
existing_web_acl_arn = ""

# ALB Association
associate_waf = true
alb_arns      = []

# Default action
default_action = "allow"

# =============================================================================
# AWS Managed Rule Groups
# =============================================================================

# 1. Core Rule Set (AWSManagedRulesCommonRuleSet) — WCU: 700
enable_aws_managed_rules   = true
aws_managed_rules_action   = "count"
aws_managed_rules_priority = 9

aws_managed_rules_rule_action_overrides = [
  { name = "NoUserAgent_HEADER",                  action = "count" },
  { name = "UserAgent_BadBots_HEADER",            action = "count" },
  { name = "SizeRestrictions_QUERYSTRING",        action = "count" },
  { name = "SizeRestrictions_Cookie_HEADER",      action = "count" },
  { name = "SizeRestrictions_BODY",               action = "count" },
  { name = "SizeRestrictions_URIPATH",            action = "block" },
  { name = "EC2MetaDataSSRF_BODY",                action = "count" },
  { name = "EC2MetaDataSSRF_COOKIE",              action = "count" },
  { name = "EC2MetaDataSSRF_URIPATH",             action = "block" },
  { name = "EC2MetaDataSSRF_QUERYARGUMENTS",      action = "block" },
  { name = "GenericLFI_QUERYARGUMENTS",           action = "block" },
  { name = "GenericLFI_URIPATH",                  action = "block" },
  { name = "GenericLFI_BODY",                     action = "block" },
  { name = "RestrictedExtensions_URIPATH",        action = "block" },
  { name = "RestrictedExtensions_QUERYARGUMENTS", action = "block" },
  { name = "GenericRFI_QUERYARGUMENTS",           action = "block" },
  { name = "GenericRFI_BODY",                     action = "block" },
  { name = "GenericRFI_URIPATH",                  action = "block" },
  { name = "CrossSiteScripting_COOKIE",           action = "block" },
  { name = "CrossSiteScripting_QUERYARGUMENTS",   action = "block" },
  { name = "CrossSiteScripting_BODY",             action = "block" },
  { name = "CrossSiteScripting_URIPATH",          action = "block" },
]

# 2. SQL Injection (AWSManagedRulesSQLiRuleSet) — WCU: 200
enable_sql_injection_protection = true
sql_injection_protection_action = "count"
sql_injection_priority          = 20

sql_injection_rule_action_overrides = [
  { name = "SQLiExtendedPatterns_QUERYARGUMENTS", action = "count" },
  { name = "SQLi_QUERYARGUMENTS",                 action = "allow" },
  { name = "SQLi_BODY",                           action = "count" },
  { name = "SQLi_COOKIE",                         action = "allow" },
  { name = "SQLi_URIPATH",                        action = "block" },
]

# 3. Known Bad Inputs (AWSManagedRulesKnownBadInputsRuleSet) — WCU: 200
enable_known_bad_inputs   = true
known_bad_inputs_action   = "count"
known_bad_inputs_priority = 15

known_bad_inputs_rule_action_overrides = [
  { name = "JavaDeserializationRCE_BODY",        action = "count" },
  { name = "JavaDeserializationRCE_URIPATH",     action = "allow" },
  { name = "JavaDeserializationRCE_QUERYSTRING", action = "count" },
  { name = "JavaDeserializationRCE_HEADER",      action = "allow" },
  { name = "Host_localhost_HEADER",              action = "count" },
  { name = "PROPFIND_METHOD",                    action = "allow" },
  { name = "ExploitablePaths_URIPATH",           action = "allow" },
  { name = "Log4JRCE_QUERYSTRING",               action = "allow" },
  { name = "Log4JRCE_BODY",                      action = "block" },
  { name = "Log4JRCE_URIPATH",                   action = "allow" },
  { name = "Log4JRCE_HEADER",                    action = "allow" },
  { name = "ReactJSRCE_BODY",                    action = "allow" },
]

# 4. IP Reputation (AWSManagedRulesAmazonIpReputationList) — WCU: 25
enable_ip_reputation   = true
ip_reputation_action   = "count"
ip_reputation_priority = 25

ip_reputation_rule_action_overrides = [
  { name = "AWSManagedIPReputationList",   action = "count" },
  { name = "AWSManagedReconnaissanceList", action = "count" },
  { name = "AWSManagedIPDDoSList",         action = "count" },
]

# 5. Anonymous IP (AWSManagedRulesAnonymousIpList) — WCU: 50
enable_anonymous_ip   = true
anonymous_ip_action   = "count"
anonymous_ip_priority = 35

# 6. Bot Control (AWSManagedRulesBotControlRuleSet) — WCU: 50
enable_bot_control           = false
bot_control_action           = "count"
bot_control_priority         = 36
bot_control_inspection_level = "COMMON"

bot_control_rule_action_overrides = [
  { name = "CategoryBots",              action = "count" },
  { name = "SignalNonBrowserUserAgent", action = "count" },
]

# 7. Anti-DDoS (AWSManagedRulesAntiDDoSRuleSet)
# NOTE: Disabled — requires ClientSideActionConfig not yet supported in Terraform provider.
enable_anti_ddos                = false
anti_ddos_action                = "count"
anti_ddos_priority              = 37
anti_ddos_rule_action_overrides = []

# 8. Linux Protection (AWSManagedRulesLinuxRuleSet) — WCU: 200
enable_linux_protection   = false
linux_protection_action   = "count"
linux_protection_priority = 50

linux_protection_rule_action_overrides = [
  { name = "LFI_URIPATH",     action = "count" },
  { name = "LFI_QUERYSTRING", action = "block" },
  { name = "LFI_HEADER",      action = "block" },
]

# 9. Unix Protection (AWSManagedRulesUnixRuleSet) — WCU: 100
enable_unix_protection   = false
unix_protection_action   = "count"
unix_protection_priority = 55

unix_protection_rule_action_overrides = [
  { name = "UNIXShellCommandsVariables_QUERYARGUMENTS", action = "allow" },
  { name = "UNIXShellCommandsVariables_BODY",           action = "allow" },
  { name = "UNIXShellCommandsVariables_COOKIE",         action = "allow" },
  { name = "UNIXShellCommandsVariables_URIPATH",        action = "allow" },
]

# 10. Windows Protection (AWSManagedRulesWindowsRuleSet) — WCU: 200
enable_windows_protection   = false
windows_protection_action   = "count"
windows_protection_priority = 60

windows_protection_rule_action_overrides = [
  { name = "WindowsShellCommands_COOKIE",         action = "count" },
  { name = "WindowsShellCommands_QUERYARGUMENTS", action = "count" },
  { name = "WindowsShellCommands_BODY",           action = "count" },
  { name = "WindowsShellCommands_URIPATH",        action = "count" },
  { name = "PowerShellCommands_COOKIE",           action = "allow" },
  { name = "PowerShellCommands_QUERYARGUMENTS",   action = "allow" },
  { name = "PowerShellCommands_BODY",             action = "allow" },
  { name = "PowerShellCommands_URIPATH",          action = "allow" },
]

# 11. PHP Protection (AWSManagedRulesPHPRuleSet) — WCU: 100
enable_php_protection   = false
php_protection_action   = "count"
php_protection_priority = 65

php_protection_rule_action_overrides = [
  { name = "PHPHighRiskMethodsVariables_QUERYARGUMENTS", action = "block" },
  { name = "PHPHighRiskMethodsVariables_BODY",           action = "block" },
  { name = "PHPHighRiskMethodsVariables_COOKIE",         action = "count" },
]

# 12. WordPress Protection (AWSManagedRulesWordPressRuleSet) — WCU: 100
enable_wordpress_protection   = false
wordpress_protection_action   = "count"
wordpress_protection_priority = 70

wordpress_protection_rule_action_overrides = [
  { name = "WordPressExploitableCommands_QUERYSTRING", action = "count" },
  { name = "WordPressExploitablePaths_URIPATH",        action = "block" },
]

# =============================================================================
# Custom Rules
# =============================================================================

# Restrict-Admin — block admin paths
enable_block_admin   = true
block_admin_priority = 75
block_admin_paths    = ["/admin", "/wp-admin", "/administrator", "/phpmyadmin"]

# block-git-access — block /.git exposure
enable_block_git   = false
block_git_priority = 76

# PROD-biz2credit-com-waf-BlockSpecificURL — block specific URLs
enable_block_specific_urls   = false
block_specific_urls_priority = 77
blocked_urls = [
  "/xmlrpc.php",
  "/.env",
  "/config.php",
  "/setup.php",
  "/install.php",
]

# BlockExtensions-UriPath — block dangerous file extensions
enable_block_extensions   = false
block_extensions_priority = 78
blocked_extensions = [
  ".env",
  ".bak",
  ".sql",
  ".log",
  ".conf",
  ".config",
  ".git",
  ".svn",
]

# Block-African-Countries-1 / Block-African-Countries-2
enable_block_african_countries     = false
block_african_countries_priority   = 80
block_african_countries_priority_2 = 801

african_country_codes_1 = [
  "DZ", "AO", "BJ", "BW", "BF", "BI", "CM", "CV", "CF", "TD",
  "KM", "CG", "CD", "CI", "DJ", "EG", "GQ", "ER", "ET", "GA",
  "GM", "GH", "GN", "GW", "KE", "LS", "LR", "LY", "MG", "MW",
  "ML", "MR", "MU", "MA", "MZ", "NA", "NE", "NG", "RW", "ST",
  "SN", "SL", "SO", "ZA", "SS", "SD", "SZ", "TZ", "TG", "TN"
]
african_country_codes_2 = ["UG", "ZM", "ZW"]

# Block-SouthAmerica-Countries
enable_block_south_america   = true
block_south_america_priority = 81
south_america_country_codes  = ["AR", "BO", "BR", "CL", "CO", "EC", "GY", "PY", "PE", "SR", "UY", "VE"]

# PROD-biz2credit-com-WAF-BlockSelectedCountries1
enable_block_selected_countries_1   = false
block_selected_countries_1_priority = 82
selected_country_codes_1            = ["CN", "RU", "KP", "IR", "SY", "CU"]

# PROD-biz2credit-com-WAF-BlockSelectedCountries2
enable_block_selected_countries_2   = false
block_selected_countries_2_priority = 83
selected_country_codes_2            = ["PK", "BD", "VN", "ID", "MM"]

# AllowCountryUS — block all non-US traffic
enable_allow_country_us   = false
allow_country_us_priority = 84

# Allow-URLS — allow specific URI prefixes (evaluated first)
enable_allow_specific_urls   = false
allow_specific_urls_priority = 3
allowed_urls = [
  "/health",
  "/ping",
  "/api/public",
]

# =============================================================================
# Rate Limiting
# =============================================================================
enable_rate_limiting   = true
rate_limiting_action   = "count"
rate_limiting_priority = 40
rate_limit_threshold   = 2000

# =============================================================================
# IP Allow / Block Lists (Allow-IPs / Block-IP)
# =============================================================================
allowlist_ips      = ["10.0.0.0/16"]
blocklist_ips      = ["20.0.0.0/16"]
allowlist_priority = 5
blocklist_priority = 30

# =============================================================================
# Logging
# =============================================================================
enable_waf_logging  = false
log_destination_arn = ""

# =============================================================================
# Tags
# =============================================================================
tags = {
  Environment = "dev"
  ManagedBy   = "Terraform"
  Project     = "myapp"
}
