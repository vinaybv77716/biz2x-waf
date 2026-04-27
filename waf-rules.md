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
aws_managed_rules_action   = "count"  # block | count | allow
aws_managed_rules_priority = 9
aws_managed_rules_rule_action_overrides = [
  { name = "NoUserAgent_HEADER", action = "block" },
]
```

### AWSManagedRulesSQLiRuleSet
Detects SQL injection patterns across query args, body, cookies, and URI path.
```hcl
enable_sql_injection_protection = true
sql_injection_protection_action = "count"
sql_injection_priority          = 20
```

### AWSManagedRulesKnownBadInputsRuleSet
Blocks known CVE exploit payloads — Log4Shell, Java deserialization, ReactJS RCE, WebDAV.
```hcl
enable_known_bad_inputs   = true
known_bad_inputs_action   = "count"
known_bad_inputs_priority = 15
```

### AWSManagedRulesAmazonIpReputationList
Blocks IPs from AWS threat intelligence — known attackers, scanners, DDoS sources.
```hcl
enable_ip_reputation   = true
ip_reputation_action   = "count"
ip_reputation_priority = 25
```

### AWSManagedRulesAnonymousIpList
Blocks VPNs, Tor exit nodes, proxies, and hosting providers. High false-positive risk — start with `count`.
```hcl
enable_anonymous_ip   = false
anonymous_ip_action   = "count"
anonymous_ip_priority = 35
```

### AWSManagedRulesBotControlRuleSet
Detects and manages bot traffic. Requires `bot_control_inspection_level = "COMMON"` or `"TARGETED"`.
```hcl
enable_bot_control           = false
bot_control_action           = "count"
bot_control_priority         = 36
bot_control_inspection_level = "COMMON"
```

### AWSManagedRulesAntiDDoSRuleSet
Detects and mitigates DDoS attack patterns.
> **Note:** Currently disabled — requires `ClientSideActionConfig` not yet supported as native HCL in the Terraform AWS provider.
```hcl
enable_anti_ddos   = false
anti_ddos_action   = "count"
anti_ddos_priority = 37
```

### AWSManagedRulesLinuxRuleSet
Protects against Linux-specific LFI, path traversal, and shell injection. Enable for Linux backends.
```hcl
enable_linux_protection   = false
linux_protection_action   = "count"
linux_protection_priority = 50
```

### AWSManagedRulesUnixRuleSet
Blocks Unix/BSD shell metacharacters and command injection patterns.
```hcl
enable_unix_protection   = false
unix_protection_action   = "count"
unix_protection_priority = 55
```

### AWSManagedRulesWindowsRuleSet
Blocks Windows shell commands and PowerShell injection. Enable only for Windows backends.
```hcl
enable_windows_protection   = false
windows_protection_action   = "count"
windows_protection_priority = 60
```

### AWSManagedRulesPHPRuleSet
Blocks dangerous PHP function calls (`eval`, `exec`, `system`). Enable for PHP-based apps.
```hcl
enable_php_protection   = false
php_protection_action   = "count"
php_protection_priority = 65
```

### AWSManagedRulesWordPressRuleSet
Blocks WordPress-specific exploits and known vulnerable paths. Enable only for WordPress sites.
```hcl
enable_wordpress_protection   = false
wordpress_protection_action   = "count"
wordpress_protection_priority = 70
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

### Allow-URLS
Explicitly allows specific URI prefixes, bypassing all other rules. Evaluated first (low priority number). Requires at least 2 entries.
```hcl
enable_allow_specific_urls   = false
allow_specific_urls_priority = 3
allowed_urls                 = ["/health", "/ping", "/api/public"]
```

### Allow-IPs (IP Allowlist)
Allows specific IP CIDRs, bypassing all WAF rules. Evaluated at priority 5.
```hcl
allowlist_ips      = ["203.0.113.0/24"]
allowlist_priority = 5
```

### Block-IP (IP Blocklist)
Always blocks specific IP CIDRs regardless of other rules.
```hcl
blocklist_ips      = ["192.168.1.100/32"]
blocklist_priority = 30
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
| 3 | Allow-URLS |
| 5 | Allow-IPs |
| 9 | Core Rule Set |
| 15 | Known Bad Inputs |
| 20 | SQL Injection |
| 25 | IP Reputation |
| 30 | Block-IP |
| 35 | Anonymous IP |
| 36 | Bot Control |
| 37 | Anti-DDoS |
| 40 | RateLimit |
| 50 | Linux Protection |
| 55 | Unix Protection |
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
