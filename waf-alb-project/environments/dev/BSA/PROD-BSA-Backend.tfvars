# =============================================================================
# REFERENCE TFVARS — Complete WAF Configuration Template
# =============================================================================
# This file contains EVERY available variable with all rules disabled (false).
# Use this as a copy-paste starting point for any new WAF deployment.
#
# To enable a rule:
#   1. Set enable_* = true
#   2. Adjust the priority (must be unique across all enabled rules)
#   3. Set the desired sub-rule action overrides
#
# Priority guide (suggested spacing):
#   0-9   : IP allow/block lists
#   10-19 : Bot Control, IP Reputation, Anonymous IP
#   20-29 : Common Rule Set, Known Bad Inputs
#   30-39 : SQLi, Linux, Anti-DDoS
#   40-49 : Rate Limiting
#   50-89 : Geo rules, Custom rules
# =============================================================================

# -----------------------------------------------------------------------------
# Project Identity (REQUIRED — no defaults)
# -----------------------------------------------------------------------------
project     = "PROD-BSA-Backend"
environment = "dev"
aws_region  = "us-east-1"

# -----------------------------------------------------------------------------
# Backend (used by pipeline — not a Terraform variable)
# -----------------------------------------------------------------------------
bucket = "bizx2-rapyder-jenkins-waf-2026"
key    = "waf-alb/your-project-name.tfstate"
region = "us-east-1"

# -----------------------------------------------------------------------------
# WAF Lifecycle
# -----------------------------------------------------------------------------
create_waf           = true
existing_web_acl_arn = ""   # Set when create_waf = false

# -----------------------------------------------------------------------------
# ALB Association
# -----------------------------------------------------------------------------
associate_waf = false
alb_arns      = []
# alb_arns = [
#   "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc123"
# ]

# -----------------------------------------------------------------------------
# Default Action
# -----------------------------------------------------------------------------
default_action = "allow"   # allow | block

# =============================================================================
# AWS MANAGED RULE GROUPS
# =============================================================================

# -----------------------------------------------------------------------------
# 1. AWSManagedRulesBotControlRuleSet — WCU: 50
# Detects and blocks bots. Supports COMMON and TARGETED inspection levels.
# TARGETED requires additional WCU and enables ML-based detection.
# -----------------------------------------------------------------------------
enable_bot_control           = false
bot_control_action           = "block"
bot_control_priority         = 0
bot_control_inspection_level = "COMMON"   # COMMON | TARGETED
bot_control_version          = "Version_1.0"

bot_control_rule_action_overrides = [
  # ── COMMON inspection level rules ──────────────────────────────────────────
  { name = "CategoryAdvertising",       action = "block" },   # Ad crawlers
  { name = "CategoryArchiver",          action = "block" },   # Web archivers (Wayback Machine etc.)
  { name = "CategoryContentFetcher",    action = "block" },   # Content scrapers
  { name = "CategoryEmailClient",       action = "block" },   # Email link checkers
  { name = "CategoryHttpLibrary",       action = "allow" },   # curl, python-requests — allow for APIs
  { name = "CategoryLinkChecker",       action = "block" },   # Link validation bots
  { name = "CategoryMiscellaneous",     action = "block" },   # Uncategorised bots
  { name = "CategoryMonitoring",        action = "block" },   # Uptime monitors
  { name = "CategoryScrapingFramework", action = "block" },   # Scrapy, Puppeteer etc.
  { name = "CategorySearchEngine",      action = "block" },   # Google, Bing — block if not needed
  { name = "CategorySecurity",          action = "block" },   # Security scanners
  { name = "CategorySeo",               action = "block" },   # SEO crawlers
  { name = "CategorySocialMedia",       action = "block" },   # Facebook, Twitter link preview bots
  { name = "CategoryAI",                action = "block" },   # AI training crawlers (GPTBot etc.)
  { name = "SignalAutomatedBrowser",    action = "block" },   # Headless browser signals
  { name = "SignalKnownBotDataCenter",  action = "block" },   # Bots from known DC IPs
  { name = "SignalNonBrowserUserAgent", action = "allow" },   # Non-browser UA — allow for mobile/API
  # ── TARGETED inspection level rules (only when inspection_level = TARGETED) ─
  { name = "TGT_VolumetricIpTokenAbsent",      action = "challenge" },  # High volume, no token
  { name = "TGT_VolumetricSession",            action = "captcha" },    # Session-level volumetric
  { name = "TGT_SignalAutomatedBrowser",       action = "captcha" },    # Automated browser signals
  { name = "TGT_SignalBrowserInconsistency",   action = "captcha" },    # Browser fingerprint mismatch
  { name = "TGT_TokenReuseIp",                 action = "count" },      # Token reuse across IPs
  { name = "TGT_ML_CoordinatedActivityMedium", action = "count" },      # ML: medium coordinated activity
  { name = "TGT_ML_CoordinatedActivityHigh",   action = "count" },      # ML: high coordinated activity
]

# -----------------------------------------------------------------------------
# 2. AWSManagedRulesAmazonIpReputationList — WCU: 25
# Blocks IPs associated with bots, DDoS, and threat intelligence feeds.
# -----------------------------------------------------------------------------
enable_ip_reputation   = false
ip_reputation_action   = "block"
ip_reputation_priority = 1

ip_reputation_rule_action_overrides = [
  { name = "AWSManagedIPReputationList",   action = "block" },  # Known malicious IPs
  { name = "AWSManagedReconnaissanceList", action = "block" },  # Scanning/recon IPs
  { name = "AWSManagedIPDDoSList",         action = "block" },  # DDoS source IPs
]

# -----------------------------------------------------------------------------
# 3. AWSManagedRulesAnonymousIpList — WCU: 50
# Blocks requests from VPNs, Tor exit nodes, and hosting providers.
# -----------------------------------------------------------------------------
enable_anonymous_ip   = false
anonymous_ip_action   = "block"
anonymous_ip_priority = 2

anonymous_ip_rule_action_overrides = [
  { name = "AnonymousIPList",       action = "block" },  # VPN, Tor, proxies
  { name = "HostingProviderIPList", action = "block" },  # Cloud/hosting provider IPs
]

# -----------------------------------------------------------------------------
# 4. AWSManagedRulesCommonRuleSet — WCU: 700
# Core OWASP rules: XSS, LFI, RFI, SSRF, bad user agents, size restrictions.
# -----------------------------------------------------------------------------
enable_aws_managed_rules   = false
aws_managed_rules_action   = "block"
aws_managed_rules_priority = 3
aws_managed_rules_version  = ""   # e.g. "Version_1.21" — leave empty for latest

aws_managed_rules_rule_action_overrides = [
  # ── User Agent rules ────────────────────────────────────────────────────────
  { name = "NoUserAgent_HEADER",                  action = "block" },  # Requests with no User-Agent
  { name = "UserAgent_BadBots_HEADER",            action = "block" },  # Known bad bot user agents
  # ── Size restriction rules ──────────────────────────────────────────────────
  { name = "SizeRestrictions_QUERYSTRING",        action = "allow" },  # Large query strings — allow for APIs
  { name = "SizeRestrictions_Cookie_HEADER",      action = "block" },  # Oversized cookies
  { name = "SizeRestrictions_BODY",               action = "allow" },  # Large bodies — allow for file uploads
  { name = "SizeRestrictions_URIPATH",            action = "block" },  # Oversized URI paths
  # ── EC2 Metadata SSRF rules ─────────────────────────────────────────────────
  { name = "EC2MetaDataSSRF_BODY",                action = "allow" },  # SSRF in body — allow if app uses metadata
  { name = "EC2MetaDataSSRF_COOKIE",              action = "block" },  # SSRF in cookies
  { name = "EC2MetaDataSSRF_URIPATH",             action = "block" },  # SSRF in URI
  { name = "EC2MetaDataSSRF_QUERYARGUMENTS",      action = "block" },  # SSRF in query args
  # ── Local File Inclusion (LFI) rules ────────────────────────────────────────
  { name = "GenericLFI_QUERYARGUMENTS",           action = "block" },
  { name = "GenericLFI_URIPATH",                  action = "block" },
  { name = "GenericLFI_BODY",                     action = "block" },
  # ── Remote File Inclusion (RFI) rules ───────────────────────────────────────
  { name = "GenericRFI_QUERYARGUMENTS",           action = "block" },
  { name = "GenericRFI_BODY",                     action = "block" },
  { name = "GenericRFI_URIPATH",                  action = "block" },
  # ── Restricted extensions ────────────────────────────────────────────────────
  { name = "RestrictedExtensions_URIPATH",        action = "block" },  # .php, .asp etc. in URI
  { name = "RestrictedExtensions_QUERYARGUMENTS", action = "block" },  # .php, .asp etc. in query
  # ── Cross-Site Scripting (XSS) rules ────────────────────────────────────────
  { name = "CrossSiteScripting_COOKIE",           action = "block" },
  { name = "CrossSiteScripting_QUERYARGUMENTS",   action = "block" },
  { name = "CrossSiteScripting_BODY",             action = "allow" },  # Allow in body for rich text editors
  { name = "CrossSiteScripting_URIPATH",          action = "block" },
]

# -----------------------------------------------------------------------------
# 5. AWSManagedRulesKnownBadInputsRuleSet — WCU: 200
# Blocks known exploits: Log4j, Java deserialization, PROPFIND, localhost.
# -----------------------------------------------------------------------------
enable_known_bad_inputs   = false
known_bad_inputs_action   = "block"
known_bad_inputs_priority = 4
known_bad_inputs_version  = ""   # e.g. "Version_1.25"

known_bad_inputs_rule_action_overrides = [
  # ── Java Deserialization RCE ─────────────────────────────────────────────────
  { name = "JavaDeserializationRCE_BODY",        action = "block" },
  { name = "JavaDeserializationRCE_URIPATH",     action = "block" },
  { name = "JavaDeserializationRCE_QUERYSTRING", action = "block" },
  { name = "JavaDeserializationRCE_HEADER",      action = "block" },
  # ── Misc bad inputs ──────────────────────────────────────────────────────────
  { name = "Host_localhost_HEADER",              action = "block" },  # localhost in Host header
  { name = "PROPFIND_METHOD",                    action = "block" },  # WebDAV PROPFIND
  { name = "ExploitablePaths_URIPATH",           action = "block" },  # Known exploit paths
  # ── Log4j RCE (Log4Shell) ────────────────────────────────────────────────────
  { name = "Log4JRCE_QUERYSTRING",               action = "block" },
  { name = "Log4JRCE_BODY",                      action = "block" },
  { name = "Log4JRCE_URIPATH",                   action = "block" },
  { name = "Log4JRCE_HEADER",                    action = "block" },
  # ── ReactJS RCE ──────────────────────────────────────────────────────────────
  { name = "ReactJSRCE_BODY",                    action = "block" },
]

# -----------------------------------------------------------------------------
# 6. AWSManagedRulesSQLiRuleSet — WCU: 200
# Blocks SQL injection patterns in query args, body, cookies, URI.
# -----------------------------------------------------------------------------
enable_sql_injection_protection = false
sql_injection_protection_action = "block"
sql_injection_priority          = 5
sql_injection_version           = ""   # e.g. "Version_2.0"

sql_injection_rule_action_overrides = [
  { name = "SQLi_QUERYARGUMENTS",                 action = "block" },  # SQLi in query string
  { name = "SQLi_BODY",                           action = "allow" },  # SQLi in body — allow for search APIs
  { name = "SQLi_COOKIE",                         action = "block" },  # SQLi in cookies
  { name = "SQLiExtendedPatterns_QUERYARGUMENTS", action = "block" },  # Extended SQLi patterns in query
  { name = "SQLiExtendedPatterns_BODY",           action = "block" },  # Extended SQLi patterns in body
]

# -----------------------------------------------------------------------------
# 7. AWSManagedRulesLinuxRuleSet — WCU: 200
# Blocks Linux-specific LFI attacks targeting /etc/passwd, /proc etc.
# -----------------------------------------------------------------------------
enable_linux_protection   = false
linux_protection_action   = "block"
linux_protection_priority = 6
linux_protection_version  = ""   # e.g. "Version_2.6"

linux_protection_rule_action_overrides = [
  { name = "LFI_URIPATH",     action = "block" },  # Linux path traversal in URI
  { name = "LFI_QUERYSTRING", action = "block" },  # Linux path traversal in query
  { name = "LFI_HEADER",      action = "block" },  # Linux path traversal in headers
]

# -----------------------------------------------------------------------------
# 8. AWSManagedRulesUnixRuleSet — WCU: 100
# Blocks Unix-specific command injection attacks.
# -----------------------------------------------------------------------------
enable_unix_protection   = false
unix_protection_action   = "block"
unix_protection_priority = 7

unix_protection_rule_action_overrides = [
  { name = "UNIXShellCommandsVariables_QUERYARGUMENTS", action = "block" },
  { name = "UNIXShellCommandsVariables_BODY",           action = "block" },
]

# -----------------------------------------------------------------------------
# 9. AWSManagedRulesWindowsRuleSet — WCU: 200
# Blocks Windows-specific attacks: PowerShell injection, path traversal.
# -----------------------------------------------------------------------------
enable_windows_protection   = false
windows_protection_action   = "block"
windows_protection_priority = 8

windows_protection_rule_action_overrides = [
  { name = "WindowsShellCommands_COOKIE",          action = "block" },
  { name = "WindowsShellCommands_QUERYARGUMENTS",  action = "block" },
  { name = "WindowsShellCommands_BODY",            action = "block" },
  { name = "PowerShellCommands_COOKIE",            action = "block" },
  { name = "PowerShellCommands_QUERYARGUMENTS",    action = "block" },
  { name = "PowerShellCommands_BODY",              action = "block" },
]

# -----------------------------------------------------------------------------
# 10. AWSManagedRulesPHPRuleSet — WCU: 100
# Blocks PHP-specific injection attacks.
# -----------------------------------------------------------------------------
enable_php_protection   = false
php_protection_action   = "block"
php_protection_priority = 9

php_protection_rule_action_overrides = [
  { name = "PHPHighRiskMethodsVariables_QUERYARGUMENTS", action = "block" },
  { name = "PHPHighRiskMethodsVariables_BODY",           action = "block" },
]

# -----------------------------------------------------------------------------
# 11. AWSManagedRulesWordPressRuleSet — WCU: 100
# Blocks WordPress-specific exploits and vulnerability probes.
# -----------------------------------------------------------------------------
enable_wordpress_protection   = false
wordpress_protection_action   = "block"
wordpress_protection_priority = 10

wordpress_protection_rule_action_overrides = [
  { name = "WordPressExploitableCommands_QUERYARGUMENTS", action = "block" },
  { name = "WordPressExploitableCommands_BODY",           action = "block" },
]

# -----------------------------------------------------------------------------
# 12. AWSManagedRulesAntiDDoSRuleSet — WCU: 100
# Mitigates DDoS attacks using rate-based and volumetric detection.
# -----------------------------------------------------------------------------
enable_anti_ddos   = false
anti_ddos_action   = "block"
anti_ddos_priority = 11

anti_ddos_rule_action_overrides = [
  { name = "ChallengeAllDDoSRequests", action = "block" },
]

# =============================================================================
# RATE LIMITING
# =============================================================================
# Blocks or counts IPs exceeding the threshold within a 5-minute window.
# -----------------------------------------------------------------------------
enable_rate_limiting   = false
rate_limiting_action   = "block"   # block | count
rate_limiting_priority = 40
rate_limit_threshold   = 2000      # requests per 5 minutes per IP (100–20,000,000)

# =============================================================================
# IP ALLOW / BLOCK LISTS
# =============================================================================
# Referencing shared IP sets created by ip-list.tfvars — no IPs listed here.

# keybank-Backend-Prod-AllowIP — Priority 0
allowlist_ips         = []
allowlist_ip_set_name = "keybank-Backend-Prod-AllowIP"
allowlist_ip_set_arn  = "arn:aws:wafv2:us-east-1:892669526097:regional/ipset/keybank-Backend-Prod-AllowIP/c0ced8e2-aa9e-4aa0-9d90-721e79df3927"
allowlist_priority    = 0

# site-24and7-AllowIP — Priority 1
vpn_allowlist_ips         = []
vpn_allowlist_ip_set_name = "site-24and7-AllowIP"
vpn_allowlist_ip_set_arn  = "arn:aws:wafv2:us-east-1:892669526097:regional/ipset/site-24and7-AllowIP/16c758f2-5b6d-4082-80fd-cd2d3afa6c7e"
vpn_allowlist_priority    = 1

# Keybank-Orchestrator-Prod-BlockIP — Priority 30
blocklist_ips      = []
blocklist_priority = 30

# =============================================================================
# GEO RESTRICTION RULES
# =============================================================================

# ── Block African Countries (split into 2 rules — AWS max 50 codes per rule) ─
enable_block_african_countries     = false
block_african_countries_priority   = 50
block_african_countries_priority_2 = 51
african_country_codes_1            = [
  "DZ", "AO", "BJ", "BW", "BF", "BI", "CM", "CV", "CF", "TD",
  "KM", "CG", "CD", "CI", "DJ", "EG", "GQ", "ER", "ET", "GA",
  "GM", "GH", "GN", "GW", "KE", "LS", "LR", "LY", "MG", "MW",
  "ML", "MR", "MU", "MA", "MZ", "NA", "NE", "NG", "RW", "ST",
  "SN", "SL", "SO", "ZA", "SS", "SD", "SZ", "TZ", "TG", "TN"
]
african_country_codes_2            = ["UG", "ZM", "ZW"]

# ── Block South American Countries ───────────────────────────────────────────
enable_block_south_america   = false
block_south_america_priority = 52
south_america_country_codes  = [
  "AR", "BO", "BR", "CL", "CO", "EC", "GY", "PY", "PE", "SR", "UY", "VE"
]

# ── Block European Countries ─────────────────────────────────────────────────
enable_block_europe   = false
block_europe_priority = 53
europe_country_codes  = [
  "AL", "AD", "AT", "BY", "BE", "BA", "BG", "HR", "CY", "CZ",
  "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IS", "IE", "IT",
  "XK", "LV", "LI", "LT", "LU", "MT", "MD", "MC", "ME", "NL",
  "MK", "NO", "PL", "PT", "RO", "RU", "SM", "RS", "SK", "SI",
  "ES", "SE", "CH", "UA", "GB", "VA"
]

# ── Block Asian Countries ─────────────────────────────────────────────────────
enable_block_asia   = false
block_asia_priority = 54
asia_country_codes  = [
  "AF", "AM", "AZ", "BH", "BD", "BT", "BN", "KH", "CN", "GE",
  "IN", "ID", "IR", "IQ", "IL", "JP", "JO", "KZ", "KW", "KG",
  "LA", "LB", "MY", "MV", "MN", "MM", "NP", "KP", "OM", "PK",
  "PS", "PH", "QA", "SA", "SG", "LK", "SY", "TW", "TJ", "TH",
  "TL", "TR", "TM", "AE", "UZ", "VN", "YE"
]

# ── Block Oceania Countries ───────────────────────────────────────────────────
enable_block_oceania   = false
block_oceania_priority = 55
oceania_country_codes  = [
  "AU", "FJ", "KI", "MH", "FM", "NR", "NZ", "PW", "PG", "WS", "SB", "TO", "TV", "VU"
]

# ── Block Selected Countries — Group 1 (custom list) ─────────────────────────
enable_block_selected_countries_1   = false
block_selected_countries_1_priority = 56
selected_country_codes_1            = []   # Add ISO 3166-1 alpha-2 codes

# ── Block Selected Countries — Group 2 (custom list) ─────────────────────────
enable_block_selected_countries_2   = false
block_selected_countries_2_priority = 57
selected_country_codes_2            = []   # Add ISO 3166-1 alpha-2 codes

# ── Allow US Only (blocks all non-US traffic) ─────────────────────────────────
enable_allow_country_us   = false
allow_country_us_priority = 58

# ── Allow IN + US (allow India and United States, block everything else) ──────
enable_allow_in_us        = false
allow_in_us_priority      = 59
allow_in_us_country_codes = ["IN", "US"]   # REQUIRED — no default in variables.tf

# =============================================================================
# CUSTOM BYTE-MATCH RULES
# =============================================================================

# ── Block Admin Paths ─────────────────────────────────────────────────────────
enable_block_admin   = false
block_admin_priority = 75
block_admin_paths    = ["/admin", "/wp-admin", "/administrator", "/phpmyadmin"]

# ── Block .git Access ─────────────────────────────────────────────────────────
enable_block_git   = false
block_git_priority = 76

# ── Block Specific URLs (exact URI path match) ────────────────────────────────
enable_block_specific_urls   = false
block_specific_urls_priority = 77
blocked_urls                 = []
# blocked_urls = ["/old-login", "/debug", "/test"]

# ── Block File Extensions ─────────────────────────────────────────────────────
enable_block_extensions   = false
block_extensions_priority = 78
blocked_extensions        = [".env", ".bak", ".sql", ".log", ".conf", ".config"]

# ── Allow Specific URLs (bypass all other rules) ──────────────────────────────
enable_allow_specific_urls   = false
allow_specific_urls_priority = 79
allowed_urls                 = []
# allowed_urls = ["/api/health", "/api/webhook"]

# =============================================================================
# LOGGING
# =============================================================================
enable_waf_logging  = false
log_destination_arn = ""
# log_destination_arn = "arn:aws:logs:us-east-1:123456789012:log-group:aws-waf-logs-my-project"

# =============================================================================
# TAGS
# =============================================================================
tags = {
  Environment = "dev"
  ManagedBy   = "Terraform"
  Project     = "your-project-name"
}
