
#sba-demo-ui# =============================================================================
# b2c-microservices-waf-orch — DEV WAF Configuration
# Rules: BotControl, IpReputation, AnonymousIp, CommonRuleSet,
#        KnownBadInputs, LinuxRuleSet, SQLiRuleSet
# =============================================================================

project     = "sba-demo-ui"
environment = "dev"
aws_region  = "us-east-1"

# Backend
bucket = "bizx2-rapyder-jenkins-waf-2026"
key    = "waf-alb/b2c-microservices-waf-orch.tfstate"
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

# 1. AWS-AWSManagedRulesBotControlRuleSet — WCU: 50
# Inspection: Common | Version: Default (Version_1.0)
enable_bot_control           = true
bot_control_action           = "block"
bot_control_priority         = 0
bot_control_inspection_level = "COMMON"
bot_control_version          = "Version_1.0"

bot_control_rule_action_overrides = [
  # Common rules
  { name = "CategoryAdvertising",        action = "block" },
  { name = "CategoryArchiver",           action = "block" },
  { name = "CategoryContentFetcher",     action = "block" },
  { name = "CategoryEmailClient",        action = "block" },
  { name = "CategoryHttpLibrary",        action = "block" },
  { name = "CategoryLinkChecker",        action = "block" },
  { name = "CategoryMiscellaneous",      action = "block" },
  { name = "CategoryMonitoring",         action = "block" },
  { name = "CategoryScrapingFramework",  action = "block" },
  { name = "CategorySearchEngine",       action = "block" },
  { name = "CategorySecurity",           action = "block" },
  { name = "CategorySeo",                action = "block" },
  { name = "CategorySocialMedia",        action = "block" },
  { name = "CategoryAI",                 action = "block" },
  { name = "SignalAutomatedBrowser",     action = "block" },
  { name = "SignalKnownBotDataCenter",   action = "block" },
  { name = "SignalNonBrowserUserAgent",  action = "block" },
  # Targeted rules
  { name = "TGT_VolumetricIpTokenAbsent",          action = "challenge" },
  { name = "TGT_VolumetricSession",                action = "captcha" },
  { name = "TGT_SignalAutomatedBrowser",           action = "captcha" },
  { name = "TGT_SignalBrowserInconsistency",       action = "captcha" },
  { name = "TGT_TokenReuseIp",                     action = "count" },
  { name = "TGT_ML_CoordinatedActivityMedium",     action = "count" },
  { name = "TGT_ML_CoordinatedActivityHigh",       action = "count" },
]

# 2. AWS-AWSManagedRulesAmazonIpReputationList — WCU: 25
enable_ip_reputation   = true
ip_reputation_action   = "block"
ip_reputation_priority = 1

ip_reputation_rule_action_overrides = [
  { name = "AWSManagedIPReputationList",  action = "block" },
  { name = "AWSManagedReconnaissanceList", action = "block" },
  { name = "AWSManagedIPDDoSList",        action = "count" },
]

# 3. AWS-AWSManagedRulesAnonymousIpList — WCU: 50
enable_anonymous_ip   = true
anonymous_ip_action   = "block"
anonymous_ip_priority = 2

anonymous_ip_rule_action_overrides = [
  { name = "AnonymousIPList",        action = "block" },
  { name = "HostingProviderIPList",  action = "block" },
]

# 4. AWS-AWSManagedRulesCommonRuleSet — WCU: 700
enable_aws_managed_rules   = true
aws_managed_rules_action   = "block"
aws_managed_rules_priority = 3
aws_managed_rules_version  = "Version_1.20"

aws_managed_rules_rule_action_overrides = [
  { name = "NoUserAgent_HEADER",                   action = "block" },
  { name = "UserAgent_BadBots_HEADER",             action = "block" },
  { name = "SizeRestrictions_QUERYSTRING",         action = "block" },
  { name = "SizeRestrictions_Cookie_HEADER",       action = "block" },
  { name = "SizeRestrictions_BODY",                action = "block" },
  { name = "SizeRestrictions_URIPATH",             action = "block" },
  { name = "EC2MetaDataSSRF_BODY",                 action = "block" },
  { name = "EC2MetaDataSSRF_COOKIE",               action = "block" },
  { name = "EC2MetaDataSSRF_URIPATH",              action = "block" },
  { name = "EC2MetaDataSSRF_QUERYARGUMENTS",       action = "block" },
  { name = "GenericLFI_QUERYARGUMENTS",            action = "block" },
  { name = "GenericLFI_URIPATH",                   action = "block" },
  { name = "GenericLFI_BODY",                      action = "block" },
  { name = "RestrictedExtensions_URIPATH",         action = "block" },
  { name = "RestrictedExtensions_QUERYARGUMENTS",  action = "block" },
  { name = "GenericRFI_QUERYARGUMENTS",            action = "block" },
  { name = "GenericRFI_BODY",                      action = "block" },
  { name = "GenericRFI_URIPATH",                   action = "block" },
  { name = "CrossSiteScripting_COOKIE",            action = "block" },
  { name = "CrossSiteScripting_QUERYARGUMENTS",    action = "block" },
  { name = "CrossSiteScripting_BODY",              action = "block" },
  { name = "CrossSiteScripting_URIPATH",           action = "block" },
]

# 5. AWS-AWSManagedRulesKnownBadInputsRuleSet — WCU: 200
enable_known_bad_inputs   = true
known_bad_inputs_action   = "block"
known_bad_inputs_priority = 4
known_bad_inputs_version  = "Version_1.25"

known_bad_inputs_rule_action_overrides = [
  { name = "JavaDeserializationRCE_BODY",        action = "block" },
  { name = "JavaDeserializationRCE_URIPATH",     action = "block" },
  { name = "JavaDeserializationRCE_QUERYSTRING", action = "block" },
  { name = "JavaDeserializationRCE_HEADER",      action = "block" },
  { name = "Host_localhost_HEADER",              action = "block" },
  { name = "PROPFIND_METHOD",                    action = "block" },
  { name = "ExploitablePaths_URIPATH",           action = "block" },
  { name = "Log4JRCE_QUERYSTRING",               action = "block" },
  { name = "Log4JRCE_BODY",                      action = "block" },
  { name = "Log4JRCE_URIPATH",                   action = "block" },
  { name = "Log4JRCE_HEADER",                    action = "block" },
  { name = "ReactJSRCE_BODY",                    action = "block" },
]

# 6. AWS-AWSManagedRulesLinuxRuleSet — WCU: 200
enable_linux_protection   = true
linux_protection_action   = "block"
linux_protection_priority = 5
linux_protection_version  = "Version_2.6"

linux_protection_rule_action_overrides = [
  { name = "LFI_URIPATH",      action = "block" },
  { name = "LFI_QUERYSTRING",  action = "block" },
  { name = "LFI_HEADER",       action = "block" },
]

# 7. AWS-AWSManagedRulesSQLiRuleSet — WCU: 200
enable_sql_injection_protection = true
sql_injection_protection_action = "block"
sql_injection_priority          = 6
sql_injection_version           = "Version_1.3"

sql_injection_rule_action_overrides = [
  { name = "SQLi_QUERYARGUMENTS",              action = "block" },
  { name = "SQLi_BODY",                        action = "block" },
  { name = "SQLi_COOKIE",                      action = "block" },
  { name = "SQLiExtendedPatterns_QUERYARGUMENTS", action = "block" },
  { name = "SQLiExtendedPatterns_BODY",        action = "allow" },
]

# =============================================================================
# Custom Rules (disabled by default — enable as needed)
# =============================================================================

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

enable_block_selected_countries_1   = false
block_selected_countries_1_priority = 82
selected_country_codes_1            = []

enable_block_selected_countries_2   = false
block_selected_countries_2_priority = 83
selected_country_codes_2            = []

enable_allow_country_us   = false
allow_country_us_priority = 84

enable_allow_in_us        = true
allow_in_us_priority      = 7
allow_in_us_country_codes = ["IN", "US", "AF"]

enable_allow_specific_urls   = false
allow_specific_urls_priority = 3
allowed_urls                 = []

# =============================================================================
# Rate Limiting
# =============================================================================
enable_rate_limiting   = false
rate_limiting_action   = "count"
rate_limiting_priority = 40
rate_limit_threshold   = 2000

# =============================================================================
# IP Allow / Block Lists
# =============================================================================
allowlist_ips      = []
blocklist_ips      = []
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
  Project     = "b2c-microservices-waf-orch"
}
