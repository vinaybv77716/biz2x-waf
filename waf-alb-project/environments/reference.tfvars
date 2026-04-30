# =============================================================================
# REFERENCE TFVARS — Template for all WAF configurations
# =============================================================================
# HOW TO USE:
#   1. Copy this file to environments/dev/<your-project>.tfvars
#   2. Update project, environment, bucket, key values
#   3. Enable the rules you need (set enable_* = true)
#   4. Adjust priorities, versions, and rule_action_overrides as needed
#
# RULE PRIORITY GUIDE (lower number = evaluated first):
#   0-9   : IP allowlists / VPN allowlists / geo allow rules
#   10-19 : Bot control, IP reputation
#   20-29 : Anonymous IP, managed rule groups
#   30-39 : Rate limiting, blocklists
#   40+   : Custom geo blocks, admin/git/URL blocks
#
# All rules are DISABLED by default. Enable only what you need.
# =============================================================================

# -----------------------------------------------------------------------------
# Project Identity
# -----------------------------------------------------------------------------
project     = "your-project-name"
environment = "dev"           # dev | staging | prod
aws_region  = "us-east-1"

# -----------------------------------------------------------------------------
# Backend (S3 state)
# -----------------------------------------------------------------------------
bucket = "bizx2-rapyder-jenkins-waf-2026"
key    = "waf-alb/your-project-name.tfstate"
region = "us-east-1"

# -----------------------------------------------------------------------------
# WAF Lifecycle
# -----------------------------------------------------------------------------
create_waf           = true
existing_web_acl_arn = ""     # Set if create_waf = false

# -----------------------------------------------------------------------------
# ALB Association
# -----------------------------------------------------------------------------
associate_waf = false
alb_arns      = []            # e.g. ["arn:aws:elasticloadbalancing:..."]

# -----------------------------------------------------------------------------
# Default Action (for requests not matching any rule)
# -----------------------------------------------------------------------------
default_action = "allow"      # allow | block

# =============================================================================
# AWS MANAGED RULE GROUPS
# =============================================================================

# -----------------------------------------------------------------------------
# 1. BotControl — WCU: 50
#    Protects against automated bots
#    Versions: Version_1.0 (COMMON), Version_1.0 (TARGETED)
# -----------------------------------------------------------------------------
enable_bot_control           = false
bot_control_action           = "block"   # block | count
bot_control_priority         = 0
bot_control_inspection_level = "COMMON"  # COMMON | TARGETED
bot_control_version          = ""        # e.g. "Version_1.0" — empty = latest

bot_control_rule_action_overrides = [
  # --- Common inspection level rules ---
  { name = "CategoryAdvertising",       action = "block" },
  { name = "CategoryArchiver",          action = "block" },
  { name = "CategoryContentFetcher",    action = "block" },
  { name = "CategoryEmailClient",       action = "block" },
  { name = "CategoryHttpLibrary",       action = "allow" },  # allow for API clients
  { name = "CategoryLinkChecker",       action = "block" },
  { name = "CategoryMiscellaneous",     action = "block" },
  { name = "CategoryMonitoring",        action = "block" },
  { name = "CategoryScrapingFramework", action = "block" },
  { name = "CategorySearchEngine",      action = "block" },
  { name = "CategorySecurity",          action = "block" },
  { name = "CategorySeo",               action = "block" },
  { name = "CategorySocialMedia",       action = "block" },
  { name = "CategoryAI",                action = "block" },
  { name = "SignalAutomatedBrowser",    action = "block" },
  { name = "SignalKnownBotDataCenter",  action = "block" },
  { name = "SignalNonBrowserUserAgent", action = "allow" },  # allow for mobile/API
  # --- Targeted inspection level rules (only when inspection_level = TARGETED) ---
  { name = "TGT_VolumetricIpTokenAbsent",      action = "challenge" },
  { name = "TGT_VolumetricSession",            action = "captcha" },
  { name = "TGT_SignalAutomatedBrowser",       action = "captcha" },
  { name = "TGT_SignalBrowserInconsistency",   action = "captcha" },
  { name = "TGT_TokenReuseIp",                 action = "count" },
  { name = "TGT_ML_CoordinatedActivityMedium", action = "count" },
  { name = "TGT_ML_CoordinatedActivityHigh",   action = "count" },
]

# -----------------------------------------------------------------------------
# 2. IP Reputation List — WCU: 25
#    Blocks IPs with known bad reputation (botnets, scanners, DDoS)
# -----------------------------------------------------------------------------
enable_ip_reputation   = false
ip_reputation_action   = "block"   # block | count
ip_reputation_priority = 1

ip_reputation_rule_action_overrides = [
  { name = "AWSManagedIPReputationList",   action = "block" },
  { name = "AWSManagedReconnaissanceList", action = "block" },
  { name = "AWSManagedIPDDoSList",         action = "count" },  # count to avoid false positives
]

# -----------------------------------------------------------------------------
# 3. Anonymous IP List — WCU: 50
#    Blocks VPNs, proxies, Tor exit nodes, hosting providers
# -----------------------------------------------------------------------------
enable_anonymous_ip   = false
anonymous_ip_action   = "block"   # block | count
anonymous_ip_priority = 2

anonymous_ip_rule_action_overrides = [
  { name = "AnonymousIPList",       action = "block" },
  { name = "HostingProviderIPList", action = "count" },  # count to avoid blocking cloud users
]

# -----------------------------------------------------------------------------
# 4. Common Rule Set (CRS) — WCU: 700
#    OWASP Top 10 protections: XSS, LFI, RFI, SSRF, size restrictions
#    Versions: Version_1.6, Version_1.20, etc.
# -----------------------------------------------------------------------------
enable_aws_managed_rules   = false
aws_managed_rules_action   = "block"   # block | count
aws_managed_rules_priority = 3
aws_managed_rules_version  = ""        # e.g. "Version_1.6" — empty = latest

aws_managed_rules_rule_action_overrides = [
  { name = "NoUserAgent_HEADER",                  action = "block" },
  { name = "UserAgent_BadBots_HEADER",            action = "block" },
  { name = "SizeRestrictions_QUERYSTRING",        action = "allow" },  # allow large query strings
  { name = "SizeRestrictions_Cookie_HEADER",      action = "block" },
  { name = "SizeRestrictions_BODY",               action = "allow" },  # allow large request bodies
  { name = "SizeRestrictions_URIPATH",            action = "block" },
  { name = "EC2MetaDataSSRF_BODY",                action = "allow" },  # allow if app uses EC2 metadata
  { name = "EC2MetaDataSSRF_COOKIE",              action = "block" },
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
  { name = "CrossSiteScripting_BODY",             action = "allow" },  # allow if app uses rich text
  { name = "CrossSiteScripting_URIPATH",          action = "block" },
]

# -----------------------------------------------------------------------------
# 5. Known Bad Inputs — WCU: 200
#    Blocks Log4Shell, Java deserialization, exploitable paths
#    Versions: Version_1.17, Version_1.25, etc.
# -----------------------------------------------------------------------------
enable_known_bad_inputs   = false
known_bad_inputs_action   = "block"   # block | count
known_bad_inputs_priority = 4
known_bad_inputs_version  = ""        # e.g. "Version_1.17" — empty = latest

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

# -----------------------------------------------------------------------------
# 6. Linux Rule Set — WCU: 200
#    Blocks LFI attacks targeting Linux systems
#    Versions: Version_2.1, Version_2.6, etc.
# -----------------------------------------------------------------------------
enable_linux_protection   = false
linux_protection_action   = "block"   # block | count
linux_protection_priority = 5
linux_protection_version  = ""        # e.g. "Version_2.1" — empty = latest

linux_protection_rule_action_overrides = [
  { name = "LFI_URIPATH",     action = "block" },
  { name = "LFI_QUERYSTRING", action = "block" },
  { name = "LFI_HEADER",      action = "block" },
]

# -----------------------------------------------------------------------------
# 7. SQLi Rule Set — WCU: 200
#    Blocks SQL injection attacks
#    Versions: Version_2.0, Version_1.3, etc.
# -----------------------------------------------------------------------------
enable_sql_injection_protection = false
sql_injection_protection_action = "block"   # block | count
sql_injection_priority          = 6
sql_injection_version           = ""        # e.g. "Version_2.0" — empty = latest

sql_injection_rule_action_overrides = [
  { name = "SQLi_QUERYARGUMENTS",                 action = "block" },
  { name = "SQLi_BODY",                           action = "allow" },  # allow if app uses SQL-like syntax in body
  { name = "SQLi_COOKIE",                         action = "block" },
  { name = "SQLiExtendedPatterns_QUERYARGUMENTS", action = "block" },
  { name = "SQLiExtendedPatterns_BODY",           action = "allow" },
]

# -----------------------------------------------------------------------------
# 8. Unix Rule Set — WCU: 100
#    Blocks attacks targeting Unix/Linux command injection
# -----------------------------------------------------------------------------
enable_unix_protection   = false
unix_protection_action   = "block"   # block | count
unix_protection_priority = 55

unix_protection_rule_action_overrides = []

# -----------------------------------------------------------------------------
# 9. Windows Rule Set — WCU: 200
#    Blocks attacks targeting Windows systems (PowerShell injection, etc.)
# -----------------------------------------------------------------------------
enable_windows_protection   = false
windows_protection_action   = "block"   # block | count
windows_protection_priority = 60

windows_protection_rule_action_overrides = []

# -----------------------------------------------------------------------------
# 10. PHP Rule Set — WCU: 100
#     Blocks PHP-specific attacks (code injection, dangerous functions)
# -----------------------------------------------------------------------------
enable_php_protection   = false
php_protection_action   = "block"   # block | count
php_protection_priority = 65

php_protection_rule_action_overrides = []

# -----------------------------------------------------------------------------
# 11. WordPress Rule Set — WCU: 100
#     Blocks WordPress-specific attacks
# -----------------------------------------------------------------------------
enable_wordpress_protection   = false
wordpress_protection_action   = "block"   # block | count
wordpress_protection_priority = 70

wordpress_protection_rule_action_overrides = []

# -----------------------------------------------------------------------------
# 12. Anti-DDoS Rule Set — WCU: 50
#     Protects against volumetric DDoS attacks
# -----------------------------------------------------------------------------
enable_anti_ddos   = false
anti_ddos_action   = "block"   # block | count
anti_ddos_priority = 37

anti_ddos_rule_action_overrides = []

# =============================================================================
# CUSTOM RULES
# =============================================================================

# -----------------------------------------------------------------------------
# Rate Limiting
#    Blocks IPs exceeding request threshold per 5-minute window
# -----------------------------------------------------------------------------
enable_rate_limiting   = false
rate_limiting_action   = "block"   # block | count
rate_limiting_priority = 40
rate_limit_threshold   = 2000      # requests per 5 min per IP (100–20,000,000)

# -----------------------------------------------------------------------------
# IP Allow List (keybank-frontend-prod-allowIP)
#    Always allow traffic from specific IPs — evaluated before all block rules
#    Option A: Provide IPs directly (Terraform creates the IP set)
#    Option B: Provide ARN of existing IP set
# -----------------------------------------------------------------------------
allowlist_ips         = []         # e.g. ["1.2.3.4/32", "10.0.0.0/8"]
allowlist_ip_set_name = ""         # custom name for the IP set — empty = auto-generated
allowlist_ip_set_arn  = ""         # ARN of existing IP set — if set, allowlist_ips is ignored
allowlist_priority    = 0

# -----------------------------------------------------------------------------
# VPN Allow List (VPN-AllowIp)
#    Always allow traffic from VPN/office IPs
#    Option A: Provide IPs directly (Terraform creates the IP set)
#    Option B: Provide ARN of existing IP set
# -----------------------------------------------------------------------------
vpn_allowlist_ips         = []     # e.g. ["5.6.7.8/32"]
vpn_allowlist_ip_set_name = ""     # custom name for the IP set — empty = auto-generated
vpn_allowlist_ip_set_arn  = ""     # ARN of existing IP set — if set, vpn_allowlist_ips is ignored
vpn_allowlist_priority    = 1

# -----------------------------------------------------------------------------
# IP Block List
#    Always block traffic from specific IPs
# -----------------------------------------------------------------------------
blocklist_ips      = []            # e.g. ["1.2.3.4/32"]
blocklist_priority = 30

# -----------------------------------------------------------------------------
# Geo Allow — IN-US
#    Allow traffic only from specified countries (action = allow)
# -----------------------------------------------------------------------------
enable_allow_in_us        = false
allow_in_us_priority      = 7
allow_in_us_country_codes = ["IN", "US"]  # add/remove country codes as needed

# -----------------------------------------------------------------------------
# Geo Allow — US Only
#    Blocks all traffic NOT from the US
# -----------------------------------------------------------------------------
enable_allow_country_us   = false
allow_country_us_priority = 84

# -----------------------------------------------------------------------------
# Geo Block — Africa (GEORestrictionAfrica)
#    Blocks traffic from African countries (split into 2 rules due to 50-code limit)
# -----------------------------------------------------------------------------
enable_block_african_countries     = false
block_african_countries_priority   = 2
block_african_countries_priority_2 = 21
african_country_codes_1            = [
  "DZ","AO","BJ","BW","BF","BI","CV","CM","CF","TD",
  "KM","CG","CD","DJ","EG","GQ","ER","SZ","ET","GA",
  "GM","GH","GN","GW","CI","KE","LS","LR","LY","MG",
  "MW","ML","MR","MU","MA","MZ","NA","NE","NG","RW",
  "ST","SN","SL","SO","ZA","SS","SD","TZ","TG","TN"
]
african_country_codes_2            = ["UG","ZM","ZW"]

# -----------------------------------------------------------------------------
# Geo Block — Europe (GEORestriction-Europe)
# -----------------------------------------------------------------------------
enable_block_europe   = false
block_europe_priority = 3
europe_country_codes  = [
  "AX","AL","AD","AT","BY","BE","BA","BG","HR","CZ",
  "DK","EE","FO","FI","FR","DE","GI","GR","GG","VA",
  "HU","IS","IM","IT","JE","XK","LV","LI","LT","LU",
  "MT","MD","MC","ME","NL","NO","PL","PT","RO","RU",
  "SM","RS","SK","SI","ES","SJ","SE","CH","UA","GB"
]

# -----------------------------------------------------------------------------
# Geo Block — Asia (GEORestriction-Asia)
# -----------------------------------------------------------------------------
enable_block_asia   = false
block_asia_priority = 4
asia_country_codes  = [
  "AF","AM","AZ","BH","BD","BT","BN","KH","CN","CY",
  "GE","IN","ID","IR","IQ","IL","JP","JO","KZ","KW",
  "KG","LA","LB","MY","MV","MN","MM","NP","KP","OM",
  "PK","PH","QA","SA","SG","KR","LK","SY","TW","TJ",
  "TH","TR","TM","AE","UZ","VN","YE"
]

# -----------------------------------------------------------------------------
# Geo Block — Oceania (GEORestriction-Oceania)
# -----------------------------------------------------------------------------
enable_block_oceania   = false
block_oceania_priority = 5
oceania_country_codes  = [
  "AS","AU","CK","FJ","FM","GU","KI","MH","MP","NC",
  "NF","NZ","NU","PG","PN","PW","SB","TK","TO","TV",
  "VU","WF","WS"
]

# -----------------------------------------------------------------------------
# Geo Block — South America
# -----------------------------------------------------------------------------
enable_block_south_america   = false
block_south_america_priority = 81
south_america_country_codes  = ["AR","BO","BR","CL","CO","EC","GY","PY","PE","SR","UY","VE"]

# -----------------------------------------------------------------------------
# Geo Block — Selected Countries Group 1 (custom list)
# -----------------------------------------------------------------------------
enable_block_selected_countries_1   = false
block_selected_countries_1_priority = 82
selected_country_codes_1            = []  # e.g. ["CN","RU","KP"]

# -----------------------------------------------------------------------------
# Geo Block — Selected Countries Group 2 (custom list)
# -----------------------------------------------------------------------------
enable_block_selected_countries_2   = false
block_selected_countries_2_priority = 83
selected_country_codes_2            = []

# -----------------------------------------------------------------------------
# Block Admin Paths
#    Blocks access to common admin/CMS paths
# -----------------------------------------------------------------------------
enable_block_admin   = false
block_admin_priority = 75
block_admin_paths    = ["/admin", "/wp-admin", "/administrator", "/phpmyadmin"]

# -----------------------------------------------------------------------------
# Block Git Access
#    Blocks access to .git directories
# -----------------------------------------------------------------------------
enable_block_git   = false
block_git_priority = 76

# -----------------------------------------------------------------------------
# Block Specific URLs
#    Blocks exact URI path matches
# -----------------------------------------------------------------------------
enable_block_specific_urls   = false
block_specific_urls_priority = 77
blocked_urls                 = []  # e.g. ["/old-login", "/debug"]

# -----------------------------------------------------------------------------
# Block File Extensions
#    Blocks requests for sensitive file extensions in URI path
# -----------------------------------------------------------------------------
enable_block_extensions   = false
block_extensions_priority = 78
blocked_extensions        = [".env", ".bak", ".sql", ".log", ".conf", ".config"]

# -----------------------------------------------------------------------------
# Allow Specific URLs
#    Bypasses all other rules for specified URI prefixes
# -----------------------------------------------------------------------------
enable_allow_specific_urls   = false
allow_specific_urls_priority = 3
allowed_urls                 = []  # e.g. ["/health", "/api/public"]

# =============================================================================
# LOGGING
# =============================================================================
enable_waf_logging  = false
log_destination_arn = ""   # ARN of CloudWatch Log Group or S3 bucket

# =============================================================================
# TAGS
# =============================================================================
tags = {
  Environment = "dev"
  ManagedBy   = "Terraform"
  Project     = "your-project-name"
}
