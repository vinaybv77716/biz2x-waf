# WAF Rules Reference

All rules are configured per environment via `.tfvars` files in `environments/dev/`.
Each rule has an `enable_*` toggle, an `action` (`block` | `count` | `allow`), and a `priority`.

---

## Rule Actions

| Action | Behavior |
|--------|----------|
| `block` | Blocks the request — returns HTTP 403 |
| `count` | Logs the match but allows the request through — use for monitoring/tuning |
| `allow` | Disables the rule entirely — saves WCU |

Sub-rule overrides let you override individual rules within a group regardless of the group-level action.

---

## AWS Managed Rule Groups

### AWSManagedRulesCommonRuleSet (Core)
Protects against OWASP Top 10: XSS, LFI, RFI, SSRF, size restrictions, command injection.
```hcl
enable_aws_managed_rules   = true
aws_managed_rules_action   = "block"
aws_managed_rules_priority = 11
aws_managed_rules_version  = "Version_1.19"
aws_managed_rules_rule_action_overrides = [
  { name = "NoUserAgent_HEADER",                   action = "block" },
  { name = "UserAgent_BadBots_HEADER",             action = "block" },
  { name = "SizeRestrictions_QUERYSTRING",         action = "allow" },  # allow for APIs
  { name = "SizeRestrictions_Cookie_HEADER",       action = "block" },
  { name = "SizeRestrictions_BODY",                action = "allow" },  # allow for file uploads
  { name = "SizeRestrictions_URIPATH",             action = "block" },
  { name = "EC2MetaDataSSRF_BODY",                 action = "allow" },  # allow if app uses metadata
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
  { name = "CrossSiteScripting_BODY",              action = "allow" },  # allow for rich text editors
  { name = "CrossSiteScripting_URIPATH",           action = "block" },
]
```

### AWSManagedRulesSQLiRuleSet
Detects SQL injection patterns across query args, body, cookies, and URI path.
```hcl
enable_sql_injection_protection = true
sql_injection_protection_action = "block"
sql_injection_priority          = 13
sql_injection_version           = "Version_1.3"
sql_injection_rule_action_overrides = [
  { name = "SQLi_QUERYARGUMENTS",                 action = "block" },
  { name = "SQLi_BODY",                           action = "allow" },  # allow for search APIs
  { name = "SQLi_COOKIE",                         action = "block" },
  { name = "SQLiExtendedPatterns_QUERYARGUMENTS", action = "block" },
  { name = "SQLiExtendedPatterns_BODY",           action = "block" },
]
```

### AWSManagedRulesKnownBadInputsRuleSet
Blocks known CVE exploit payloads — Log4Shell, Java deserialization, ReactJS RCE, WebDAV.
```hcl
enable_known_bad_inputs   = true
known_bad_inputs_action   = "block"
known_bad_inputs_priority = 12
known_bad_inputs_version  = "Version_1.22"
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
```

### AWSManagedRulesAmazonIpReputationList
Blocks IPs from AWS threat intelligence — known attackers, scanners, DDoS sources.
```hcl
enable_ip_reputation   = true
ip_reputation_action   = "block"
ip_reputation_priority = 9
ip_reputation_rule_action_overrides = [
  { name = "AWSManagedIPReputationList",   action = "block" },
  { name = "AWSManagedReconnaissanceList", action = "block" },
  { name = "AWSManagedIPDDoSList",         action = "block" },
]
```

### AWSManagedRulesAnonymousIpList
Blocks VPNs, Tor exit nodes, proxies, and hosting providers. High false-positive risk — start with `count`.
```hcl
enable_anonymous_ip   = true
anonymous_ip_action   = "block"
anonymous_ip_priority = 8
anonymous_ip_rule_action_overrides = [
  { name = "AnonymousIPList",       action = "block" },
  { name = "HostingProviderIPList", action = "count" },  # count to avoid blocking cloud users
]
```

### AWSManagedRulesBotControlRuleSet
Detects and manages bot traffic. Supports `COMMON` (standard) and `TARGETED` (ML-based) inspection levels.
```hcl
enable_bot_control           = true
bot_control_action           = "block"
bot_control_priority         = 10
bot_control_inspection_level = "COMMON"   # COMMON | TARGETED
bot_control_version          = "Version_1.0"
bot_control_rule_action_overrides = [
  # Common inspection level rules
  { name = "CategoryAdvertising",       action = "block" },
  { name = "CategoryArchiver",          action = "block" },
  { name = "CategoryContentFetcher",    action = "block" },
  { name = "CategoryEmailClient",       action = "block" },
  { name = "CategoryHttpLibrary",       action = "allow" },  # allow curl/python-requests for APIs
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
  { name = "SignalNonBrowserUserAgent", action = "allow" },  # allow mobile/API clients
  # Targeted inspection level rules (only active when inspection_level = "TARGETED")
  { name = "TGT_VolumetricIpTokenAbsent",      action = "challenge" },
  { name = "TGT_VolumetricSession",            action = "captcha" },
  { name = "TGT_SignalAutomatedBrowser",       action = "captcha" },
  { name = "TGT_SignalBrowserInconsistency",   action = "captcha" },
  { name = "TGT_TokenReuseIp",                 action = "count" },
  { name = "TGT_ML_CoordinatedActivityMedium", action = "count" },
  { name = "TGT_ML_CoordinatedActivityHigh",   action = "count" },
]
```

### AWSManagedRulesAntiDDoSRuleSet
Detects and mitigates DDoS attack patterns.
```hcl
enable_anti_ddos   = false
anti_ddos_action   = "block"
anti_ddos_priority = 37
anti_ddos_rule_action_overrides = [
  { name = "ChallengeAllDDoSRequests", action = "block" },
]
```

### AWSManagedRulesLinuxRuleSet
Protects against Linux-specific LFI, path traversal, and shell injection. Enable for Linux backends.
```hcl
enable_linux_protection   = true
linux_protection_action   = "block"
linux_protection_priority = 5
linux_protection_version  = "Version_2.6"
linux_protection_rule_action_overrides = [
  { name = "LFI_URIPATH",     action = "block" },
  { name = "LFI_QUERYSTRING", action = "block" },
  { name = "LFI_HEADER",      action = "block" },
]
```

### AWSManagedRulesUnixRuleSet
Blocks Unix/BSD shell metacharacters and command injection patterns.
```hcl
enable_unix_protection   = false
unix_protection_action   = "block"
unix_protection_priority = 55
unix_protection_rule_action_overrides = [
  { name = "UNIXShellCommandsVariables_QUERYARGUMENTS", action = "block" },
  { name = "UNIXShellCommandsVariables_BODY",           action = "block" },
]
```

### AWSManagedRulesWindowsRuleSet
Blocks Windows shell commands and PowerShell injection. Enable only for Windows backends.
```hcl
enable_windows_protection   = false
windows_protection_action   = "block"
windows_protection_priority = 60
windows_protection_rule_action_overrides = [
  { name = "WindowsShellCommands_COOKIE",         action = "block" },
  { name = "WindowsShellCommands_QUERYARGUMENTS", action = "block" },
  { name = "WindowsShellCommands_BODY",           action = "block" },
  { name = "PowerShellCommands_COOKIE",           action = "block" },
  { name = "PowerShellCommands_QUERYARGUMENTS",   action = "block" },
  { name = "PowerShellCommands_BODY",             action = "block" },
]
```

### AWSManagedRulesPHPRuleSet
Blocks dangerous PHP function calls (`eval`, `exec`, `system`). Enable for PHP-based apps.
```hcl
enable_php_protection   = false
php_protection_action   = "block"
php_protection_priority = 65
php_protection_rule_action_overrides = [
  { name = "PHPHighRiskMethodsVariables_QUERYARGUMENTS", action = "block" },
  { name = "PHPHighRiskMethodsVariables_BODY",           action = "block" },
]
```

### AWSManagedRulesWordPressRuleSet
Blocks WordPress-specific exploits and known vulnerable paths. Enable only for WordPress sites.
```hcl
enable_wordpress_protection   = false
wordpress_protection_action   = "block"
wordpress_protection_priority = 70
wordpress_protection_rule_action_overrides = [
  { name = "WordPressExploitableCommands_QUERYARGUMENTS", action = "block" },
  { name = "WordPressExploitableCommands_BODY",           action = "block" },
]
```

---

## Custom Rules

### Restrict-Admin
Blocks requests to admin paths (e.g. `/admin`, `/wp-admin`). Add paths to `block_admin_paths`. Requires at least 2 entries.
```hcl
enable_block_admin   = false
block_admin_priority = 75
block_admin_paths    = ["/admin", "/wp-admin", "/administrator", "/phpmyadmin"]
```

### block-git-access
Blocks any request with a URI starting with `/.git` to prevent source code exposure.
```hcl
enable_block_git   = false
block_git_priority = 76
```

### PROD-biz2credit-com-waf-BlockSpecificURL
Blocks exact URI paths. Add paths to `blocked_urls`. Requires at least 2 entries.
```hcl
enable_block_specific_urls   = false
block_specific_urls_priority = 77
blocked_urls                 = ["/xmlrpc.php", "/.env", "/config.php"]
```

### BlockExtensions-UriPath
Blocks requests for sensitive file extensions in the URI path (`.env`, `.bak`, `.sql`, etc.). Requires at least 2 entries.
```hcl
enable_block_extensions   = false
block_extensions_priority = 78
blocked_extensions        = [".env", ".bak", ".sql", ".log"]
```

### Block-African-Countries-1 / Block-African-Countries-2
Geo-blocks African countries. Split into two rules because AWS limits geo rules to 50 country codes each.
```hcl
enable_block_african_countries     = false
block_african_countries_priority   = 80
block_african_countries_priority_2 = 801
african_country_codes_1            = ["DZ", "AO", ...]  # first 50
african_country_codes_2            = ["UG", "ZM", "ZW"] # remainder
```

### Block-SouthAmerica-Countries
Geo-blocks all South American countries.
```hcl
enable_block_south_america   = false
block_south_america_priority = 81
south_america_country_codes  = ["AR", "BO", "BR", ...]
```

### GEORestriction-Europe / GEORestriction-Europe-2
Geo-blocks European countries. Split into two rules to handle more than 50 country codes.
```hcl
enable_block_europe     = false
block_europe_priority   = 53
europe_country_codes    = ["AL", "AD", "AT", "BY", "BE", "BA", "BG", "HR", "CZ", "DK",
                           "EE", "FO", "FI", "FR", "DE", "GI", "GR", "GL", "GG", "HU",
                           "IS", "IE", "IM", "IT", "JE", "XK", "LV", "LI", "LT", "LU",
                           "MT", "MD", "MC", "ME", "NL", "MK", "NO", "PL", "PT", "RO",
                           "RU", "SM", "RS", "SK", "SI", "ES", "SJ", "SE", "CH", "TR"]
block_europe_priority_2 = 54
europe_country_codes_2  = ["UA", "GB", "VA"]  # overflow batch
```

### GEORestriction-Asia
Geo-blocks Asian countries.
```hcl
enable_block_asia   = false
block_asia_priority = 55
asia_country_codes  = ["AF", "AM", "AZ", "BH", "BD", "BT", "BN", "KH", "CN", "GE",
                       "IN", "ID", "IR", "IQ", "IL", "JP", "JO", "KZ", "KW", "KG",
                       "LA", "LB", "MY", "MV", "MN", "MM", "NP", "KP", "OM", "PK",
                       "PS", "PH", "QA", "SA", "SG", "LK", "SY", "TW", "TJ", "TH",
                       "TL", "TR", "TM", "AE", "UZ", "VN", "YE"]
```

### GEORestriction-Oceania
Geo-blocks Oceania countries.
```hcl
enable_block_oceania   = false
block_oceania_priority = 56
oceania_country_codes  = ["AU", "FJ", "KI", "MH", "FM", "NR", "NZ", "PW", "PG",
                          "WS", "SB", "TO", "TV", "VU"]
```

### PROD-biz2credit-com-WAF-BlockSelectedCountries1
Geo-blocks a custom group of countries (group 1). Edit `selected_country_codes_1` with ISO 3166-1 alpha-2 codes.
```hcl
enable_block_selected_countries_1   = false
block_selected_countries_1_priority = 82
selected_country_codes_1            = ["CN", "RU", "KP", "IR"]
```

### PROD-biz2credit-com-WAF-BlockSelectedCountries2
Geo-blocks a second custom group of countries (group 2).
```hcl
enable_block_selected_countries_2   = false
block_selected_countries_2_priority = 83
selected_country_codes_2            = ["PK", "BD", "VN"]
```

### AllowCountryUS
Blocks all traffic that is NOT from the United States. Set `enable_allow_country_us = true` to enforce US-only access.
```hcl
enable_allow_country_us   = false
allow_country_us_priority = 84
```

### IN-US (Allow India + United States)
Allows traffic from India and the United States, blocking all other countries. Useful for apps serving only IN/US users.
```hcl
enable_allow_in_us        = false
allow_in_us_priority      = 7
allow_in_us_country_codes = ["IN", "US"]   # REQUIRED — no default value
```

### Allow-URLS
Explicitly allows specific URI prefixes, bypassing all other rules. Evaluated first (low priority number). Requires at least 2 entries.
```hcl
enable_allow_specific_urls   = false
allow_specific_urls_priority = 3
allowed_urls                 = ["/health", "/ping", "/api/public"]
```

### Allow-IPs (IP Allowlist — keybank-frontend-prod-allowIP)
Allows specific IP CIDRs, bypassing all WAF rules. Can create a new IP set from `allowlist_ips` or reference an existing one via `allowlist_ip_set_arn`.
```hcl
allowlist_ips         = ["203.0.113.0/24"]
allowlist_ip_set_name = "my-allowlist"       # custom name for the IP set
allowlist_ip_set_arn  = ""                   # set to reuse an existing IP set ARN
allowlist_priority    = 0
```

### VPN-AllowIp (VPN Allowlist — site-24and7-AllowIP)
Allows VPN and office IPs, bypassing all WAF rules. Separate from the main allowlist so VPN and application IPs are managed independently.
```hcl
vpn_allowlist_ips         = ["45.33.65.221/32"]
vpn_allowlist_ip_set_name = "site-24and7-AllowIP"
vpn_allowlist_ip_set_arn  = ""               # set to reuse an existing IP set ARN
vpn_allowlist_priority    = 1
```

### keybank-frontend-PROD-AllowIP (Frontend Allowlist)
A third IP allowlist slot for frontend-specific IPs. References an existing IP set by ARN.
```hcl
frontend_allowlist_ips         = []
frontend_allowlist_ip_set_name = "keybank-frontend-PROD-AllowIP"
frontend_allowlist_ip_set_arn  = "arn:aws:wafv2:us-east-1:..."
frontend_allowlist_priority    = 2
```

### Block-IP (IP Blocklist)
Always blocks specific IP CIDRs regardless of other rules. Supports a custom name for the IP set.
```hcl
blocklist_ips         = ["192.168.1.100/32"]
blocklist_ip_set_name = "Keybank-Prchestrator-Prod-BlockIP"  # custom name
blocklist_priority    = 30
```

### RateLimit
Blocks IPs that exceed a request threshold in a 5-minute rolling window. Protects against DDoS, brute force, and scraping.
```hcl
enable_rate_limiting   = true
rate_limiting_action   = "block"
rate_limiting_priority = 40
rate_limit_threshold   = 2000  # requests per IP per 5 minutes
```

---

## Priority Order

| Priority | Rule |
|----------|------|
| 0 | VPN-AllowIp (site-24and7-AllowIP) |
| 1 | Allow-IPs (keybank-Backend-Prod-AllowIP) |
| 2 | keybank-frontend-PROD-AllowIP |
| 3 | Allow-URLS |
| 7 | IN-US (Allow India + US) |
| 9 | Core Rule Set |
| 15 | Known Bad Inputs |
| 20 | SQL Injection |
| 25 | IP Reputation |
| 30 | Block-IP (Blocklist) |
| 35 | Anonymous IP |
| 36 | Bot Control |
| 37 | Anti-DDoS |
| 40 | RateLimit |
| 50 | Linux Protection |
| 53 | GEORestriction-Europe |
| 54 | GEORestriction-Europe-2 |
| 55 | GEORestriction-Asia / Unix Protection |
| 56 | GEORestriction-Oceania |
| 60 | Windows Protection |
| 65 | PHP Protection |
| 70 | WordPress Protection |
| 75 | Restrict-Admin |
| 76 | block-git-access |
| 77 | BlockSpecificURL |
| 78 | BlockExtensions-UriPath |
| 80 | Block-African-Countries-1 |
| 801 | Block-African-Countries-2 |
| 81 | Block-SouthAmerica-Countries |
| 82 | BlockSelectedCountries1 |
| 83 | BlockSelectedCountries2 |
| 84 | AllowCountryUS |

---

## WCU Budget

AWS hard limit is **1,500 WCU per Web ACL**.

| Rule | WCU |
|------|-----|
| Core Rule Set | 700 |
| SQL Injection | 200 |
| Known Bad Inputs | 200 |
| Linux / Windows Protection | 200 each |
| Unix / PHP / WordPress Protection | 100 each |
| Anonymous IP / Bot Control | 50 each |
| IP Reputation | 25 |
| Rate Limiting + Custom rules | ~7 |

Core + SQLi + Known Bad + IP Reputation + Rate Limit = **1,127 WCU**.
Adding Linux = **1,327 WCU** — still within limit.
Do not enable all rules simultaneously — exceeds 1,500 WCU.
