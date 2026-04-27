# =============================================================================
# ROOT MODULE — WAF + ALB Management
# =============================================================================

terraform {
  required_version = ">= 1.3.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.tags
  }
}

# -----------------------------------------------------------------------------
# WAF Module
# -----------------------------------------------------------------------------
module "waf" {
  source = "./modules/waf"

  # Project metadata
  project     = var.project
  environment = var.environment
  tags        = var.tags

  # WAF lifecycle flags
  create_waf           = var.create_waf
  existing_web_acl_arn = var.existing_web_acl_arn

  # Association control
  associate_waf = var.associate_waf
  alb_arns      = var.alb_arns

  # WAF rules configuration
  default_action                             = var.default_action
  enable_aws_managed_rules                   = var.enable_aws_managed_rules
  aws_managed_rules_action                   = var.aws_managed_rules_action
  aws_managed_rules_priority                 = var.aws_managed_rules_priority
  aws_managed_rules_rule_action_overrides    = var.aws_managed_rules_rule_action_overrides
  enable_sql_injection_protection            = var.enable_sql_injection_protection
  sql_injection_protection_action            = var.sql_injection_protection_action
  sql_injection_priority                     = var.sql_injection_priority
  sql_injection_rule_action_overrides        = var.sql_injection_rule_action_overrides
  enable_known_bad_inputs                    = var.enable_known_bad_inputs
  known_bad_inputs_action                    = var.known_bad_inputs_action
  known_bad_inputs_priority                  = var.known_bad_inputs_priority
  known_bad_inputs_rule_action_overrides     = var.known_bad_inputs_rule_action_overrides
  enable_ip_reputation                       = var.enable_ip_reputation
  ip_reputation_action                       = var.ip_reputation_action
  ip_reputation_priority                     = var.ip_reputation_priority
  ip_reputation_rule_action_overrides        = var.ip_reputation_rule_action_overrides
  enable_anonymous_ip                        = var.enable_anonymous_ip
  anonymous_ip_action                        = var.anonymous_ip_action
  anonymous_ip_priority                      = var.anonymous_ip_priority
  enable_bot_control                         = var.enable_bot_control
  bot_control_action                         = var.bot_control_action
  bot_control_priority                       = var.bot_control_priority
  bot_control_inspection_level               = var.bot_control_inspection_level
  bot_control_rule_action_overrides          = var.bot_control_rule_action_overrides
  enable_anti_ddos                           = var.enable_anti_ddos
  anti_ddos_action                           = var.anti_ddos_action
  anti_ddos_priority                         = var.anti_ddos_priority
  anti_ddos_rule_action_overrides            = var.anti_ddos_rule_action_overrides
  enable_linux_protection                    = var.enable_linux_protection
  linux_protection_action                    = var.linux_protection_action
  linux_protection_priority                  = var.linux_protection_priority
  linux_protection_rule_action_overrides     = var.linux_protection_rule_action_overrides
  enable_unix_protection                     = var.enable_unix_protection
  unix_protection_action                     = var.unix_protection_action
  unix_protection_priority                   = var.unix_protection_priority
  unix_protection_rule_action_overrides      = var.unix_protection_rule_action_overrides
  enable_windows_protection                  = var.enable_windows_protection
  windows_protection_action                  = var.windows_protection_action
  windows_protection_priority                = var.windows_protection_priority
  windows_protection_rule_action_overrides   = var.windows_protection_rule_action_overrides
  enable_php_protection                      = var.enable_php_protection
  php_protection_action                      = var.php_protection_action
  php_protection_priority                    = var.php_protection_priority
  php_protection_rule_action_overrides       = var.php_protection_rule_action_overrides
  enable_wordpress_protection                = var.enable_wordpress_protection
  wordpress_protection_action                = var.wordpress_protection_action
  wordpress_protection_priority              = var.wordpress_protection_priority
  wordpress_protection_rule_action_overrides = var.wordpress_protection_rule_action_overrides
  enable_rate_limiting                       = var.enable_rate_limiting
  rate_limiting_action                       = var.rate_limiting_action
  rate_limiting_priority                     = var.rate_limiting_priority
  rate_limit_threshold                       = var.rate_limit_threshold

  # IP lists
  allowlist_ips      = var.allowlist_ips
  blocklist_ips      = var.blocklist_ips
  allowlist_priority = var.allowlist_priority
  blocklist_priority = var.blocklist_priority

  # Custom rules
  enable_block_admin                  = var.enable_block_admin
  block_admin_priority                = var.block_admin_priority
  block_admin_paths                   = var.block_admin_paths
  enable_block_git                    = var.enable_block_git
  block_git_priority                  = var.block_git_priority
  enable_block_specific_urls          = var.enable_block_specific_urls
  block_specific_urls_priority        = var.block_specific_urls_priority
  blocked_urls                        = var.blocked_urls
  enable_block_extensions             = var.enable_block_extensions
  block_extensions_priority           = var.block_extensions_priority
  blocked_extensions                  = var.blocked_extensions
  enable_block_african_countries      = var.enable_block_african_countries
  block_african_countries_priority    = var.block_african_countries_priority
  block_african_countries_priority_2  = var.block_african_countries_priority_2
  african_country_codes_1             = var.african_country_codes_1
  african_country_codes_2             = var.african_country_codes_2
  enable_block_south_america          = var.enable_block_south_america
  block_south_america_priority        = var.block_south_america_priority
  south_america_country_codes         = var.south_america_country_codes
  enable_block_selected_countries_1   = var.enable_block_selected_countries_1
  block_selected_countries_1_priority = var.block_selected_countries_1_priority
  selected_country_codes_1            = var.selected_country_codes_1
  enable_block_selected_countries_2   = var.enable_block_selected_countries_2
  block_selected_countries_2_priority = var.block_selected_countries_2_priority
  selected_country_codes_2            = var.selected_country_codes_2
  enable_allow_country_us             = var.enable_allow_country_us
  allow_country_us_priority           = var.allow_country_us_priority
  enable_allow_specific_urls          = var.enable_allow_specific_urls
  allow_specific_urls_priority        = var.allow_specific_urls_priority
  allowed_urls                        = var.allowed_urls

  # Logging
  enable_waf_logging  = var.enable_waf_logging
  log_destination_arn = var.log_destination_arn
}
