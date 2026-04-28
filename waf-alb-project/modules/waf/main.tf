# =============================================================================
# MODULE: WAF (Web ACL) + ALB Association
# Supports: Create/Delete WAF | Associate/Disassociate WAF with ALB
# =============================================================================

locals {
  name_prefix = "${var.project}-${var.environment}"
  
  # Determine the actual WAF ARN to use
  # Priority: created WAF > existing WAF ARN
  web_acl_arn = var.create_waf && length(aws_wafv2_web_acl.this) > 0 ? aws_wafv2_web_acl.this[0].arn : var.existing_web_acl_arn
}

# -----------------------------------------------------------------------------
# IP Sets (optional - used in rules)
# -----------------------------------------------------------------------------
resource "aws_wafv2_ip_set" "allowlist" {
  count              = var.create_waf && length(var.allowlist_ips) > 0 ? 1 : 0
  name               = "${local.name_prefix}-allowlist"
  description        = "Allowlisted IPs for ${local.name_prefix}"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.allowlist_ips

  tags = merge(var.tags, { Name = "${local.name_prefix}-allowlist" })
}

resource "aws_wafv2_ip_set" "blocklist" {
  count              = var.create_waf && length(var.blocklist_ips) > 0 ? 1 : 0
  name               = "${local.name_prefix}-blocklist"
  description        = "Blocklisted IPs for ${local.name_prefix}"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.blocklist_ips

  tags = merge(var.tags, { Name = "${local.name_prefix}-blocklist" })
}

# -----------------------------------------------------------------------------
# Rule change tracker — forces WAF replacement when rule config changes
# Workaround for AWS provider bug: https://github.com/hashicorp/terraform-provider-aws/issues/23992
# -----------------------------------------------------------------------------
resource "terraform_data" "waf_rules_hash" {
  count = var.create_waf ? 1 : 0

  input = sha256(jsonencode({
    default_action                             = var.default_action
    enable_aws_managed_rules                   = var.enable_aws_managed_rules
    aws_managed_rules_action                   = var.aws_managed_rules_action
    aws_managed_rules_priority                 = var.aws_managed_rules_priority
    aws_managed_rules_version                  = var.aws_managed_rules_version
    aws_managed_rules_rule_action_overrides    = var.aws_managed_rules_rule_action_overrides
    enable_sql_injection_protection            = var.enable_sql_injection_protection
    sql_injection_protection_action            = var.sql_injection_protection_action
    sql_injection_priority                     = var.sql_injection_priority
    sql_injection_version                      = var.sql_injection_version
    sql_injection_rule_action_overrides        = var.sql_injection_rule_action_overrides
    enable_known_bad_inputs                    = var.enable_known_bad_inputs
    known_bad_inputs_action                    = var.known_bad_inputs_action
    known_bad_inputs_priority                  = var.known_bad_inputs_priority
    known_bad_inputs_version                   = var.known_bad_inputs_version
    known_bad_inputs_rule_action_overrides     = var.known_bad_inputs_rule_action_overrides
    enable_ip_reputation                       = var.enable_ip_reputation
    ip_reputation_action                       = var.ip_reputation_action
    ip_reputation_priority                     = var.ip_reputation_priority
    ip_reputation_rule_action_overrides        = var.ip_reputation_rule_action_overrides
    enable_anonymous_ip                        = var.enable_anonymous_ip
    anonymous_ip_action                        = var.anonymous_ip_action
    anonymous_ip_priority                      = var.anonymous_ip_priority
    anonymous_ip_rule_action_overrides         = var.anonymous_ip_rule_action_overrides
    enable_bot_control                         = var.enable_bot_control
    bot_control_action                         = var.bot_control_action
    bot_control_priority                       = var.bot_control_priority
    bot_control_version                        = var.bot_control_version
    bot_control_rule_action_overrides          = var.bot_control_rule_action_overrides
    enable_linux_protection                    = var.enable_linux_protection
    linux_protection_action                    = var.linux_protection_action
    linux_protection_priority                  = var.linux_protection_priority
    linux_protection_version                   = var.linux_protection_version
    linux_protection_rule_action_overrides     = var.linux_protection_rule_action_overrides
    enable_allow_in_us                         = var.enable_allow_in_us
    allow_in_us_priority                       = var.allow_in_us_priority
    allow_in_us_country_codes                  = var.allow_in_us_country_codes
    allowlist_ips                              = var.allowlist_ips
    blocklist_ips                              = var.blocklist_ips
  }))
}

# -----------------------------------------------------------------------------
# WAF Web ACL
# Only manages lifecycle when explicitly told to create or destroy
# -----------------------------------------------------------------------------
resource "aws_wafv2_web_acl" "this" {
  count       = var.create_waf ? 1 : 0
  name        = "${local.name_prefix}-web-acl"
  description = "WAF Web ACL for ${local.name_prefix}"
  scope       = "REGIONAL"

  default_action {
    dynamic "allow" {
      for_each = var.default_action == "allow" ? [1] : []
      content {}
    }
    dynamic "block" {
      for_each = var.default_action == "block" ? [1] : []
      content {}
    }
  }

  # Workaround for AWS provider bug with aws_wafv2_web_acl set-based rule hashing:
  # https://github.com/hashicorp/terraform-provider-aws/issues/23992
  # ignore_changes prevents the inconsistent plan error.
  # terraform_data.waf_rules_hash triggers replacement when rules actually change.
  lifecycle {
    prevent_destroy       = false
    create_before_destroy = false
    ignore_changes        = [rule]
    replace_triggered_by  = [terraform_data.waf_rules_hash[0]]
  }

  # ---- AWS Managed Rules ----
  dynamic "rule" {
    for_each = var.enable_aws_managed_rules && var.aws_managed_rules_action != "allow" ? [1] : []
    content {
      name     = "AWSManagedRulesCommonRuleSet"
      priority = var.aws_managed_rules_priority

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesCommonRuleSet"
          vendor_name = "AWS"
          version     = var.aws_managed_rules_version != "" ? var.aws_managed_rules_version : null

          # Per-sub-rule action overrides (e.g. force a specific sub-rule to count)
          dynamic "rule_action_override" {
            for_each = var.aws_managed_rules_rule_action_overrides
            content {
              name = rule_action_override.value.name
              action_to_use {
                dynamic "allow" {
                  for_each = rule_action_override.value.action == "allow" ? [1] : []
                  content {}
                }
                dynamic "block" {
                  for_each = rule_action_override.value.action == "block" ? [1] : []
                  content {}
                }
                dynamic "count" {
                  for_each = rule_action_override.value.action == "count" ? [1] : []
                  content {}
                }
                dynamic "captcha" {
                  for_each = rule_action_override.value.action == "captcha" ? [1] : []
                  content {}
                }
                dynamic "challenge" {
                  for_each = rule_action_override.value.action == "challenge" ? [1] : []
                  content {}
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-common-rules"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- AWS SQL Injection Rules ----
  dynamic "rule" {
    for_each = var.enable_sql_injection_protection && var.sql_injection_protection_action != "allow" ? [1] : []
    content {
      name     = "AWSManagedRulesSQLiRuleSet"
      priority = var.sql_injection_priority

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesSQLiRuleSet"
          vendor_name = "AWS"
          version     = var.sql_injection_version != "" ? var.sql_injection_version : null

          dynamic "rule_action_override" {
            for_each = var.sql_injection_rule_action_overrides
            content {
              name = rule_action_override.value.name
              action_to_use {
                dynamic "allow" {
                  for_each = rule_action_override.value.action == "allow" ? [1] : []
                  content {}
                }
                dynamic "block" {
                  for_each = rule_action_override.value.action == "block" ? [1] : []
                  content {}
                }
                dynamic "count" {
                  for_each = rule_action_override.value.action == "count" ? [1] : []
                  content {}
                }
                dynamic "captcha" {
                  for_each = rule_action_override.value.action == "captcha" ? [1] : []
                  content {}
                }
                dynamic "challenge" {
                  for_each = rule_action_override.value.action == "challenge" ? [1] : []
                  content {}
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-sqli-rules"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Known Bad Inputs Rule ----
  dynamic "rule" {
    for_each = var.enable_known_bad_inputs && var.known_bad_inputs_action != "allow" ? [1] : []
    content {
      name     = "AWSManagedRulesKnownBadInputsRuleSet"
      priority = var.known_bad_inputs_priority

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesKnownBadInputsRuleSet"
          vendor_name = "AWS"
          version     = var.known_bad_inputs_version != "" ? var.known_bad_inputs_version : null

          dynamic "rule_action_override" {
            for_each = var.known_bad_inputs_rule_action_overrides
            content {
              name = rule_action_override.value.name
              action_to_use {
                dynamic "allow" {
                  for_each = rule_action_override.value.action == "allow" ? [1] : []
                  content {}
                }
                dynamic "block" {
                  for_each = rule_action_override.value.action == "block" ? [1] : []
                  content {}
                }
                dynamic "count" {
                  for_each = rule_action_override.value.action == "count" ? [1] : []
                  content {}
                }
                dynamic "captcha" {
                  for_each = rule_action_override.value.action == "captcha" ? [1] : []
                  content {}
                }
                dynamic "challenge" {
                  for_each = rule_action_override.value.action == "challenge" ? [1] : []
                  content {}
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-known-bad-inputs"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- IP Reputation List Rule ----
  dynamic "rule" {
    for_each = var.enable_ip_reputation && var.ip_reputation_action != "allow" ? [1] : []
    content {
      name     = "AWSManagedRulesAmazonIpReputationList"
      priority = var.ip_reputation_priority

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesAmazonIpReputationList"
          vendor_name = "AWS"

          dynamic "rule_action_override" {
            for_each = var.ip_reputation_rule_action_overrides
            content {
              name = rule_action_override.value.name
              action_to_use {
                dynamic "allow" {
                  for_each = rule_action_override.value.action == "allow" ? [1] : []
                  content {}
                }
                dynamic "block" {
                  for_each = rule_action_override.value.action == "block" ? [1] : []
                  content {}
                }
                dynamic "count" {
                  for_each = rule_action_override.value.action == "count" ? [1] : []
                  content {}
                }
                dynamic "captcha" {
                  for_each = rule_action_override.value.action == "captcha" ? [1] : []
                  content {}
                }
                dynamic "challenge" {
                  for_each = rule_action_override.value.action == "challenge" ? [1] : []
                  content {}
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-ip-reputation"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Anonymous IP List Rule ----
  dynamic "rule" {
    for_each = var.enable_anonymous_ip && var.anonymous_ip_action != "allow" ? [1] : []
    content {
      name     = "AWSManagedRulesAnonymousIpList"
      priority = var.anonymous_ip_priority

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesAnonymousIpList"
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-anonymous-ip"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Bot Control Rule ----
  dynamic "rule" {
    for_each = var.enable_bot_control && var.bot_control_action != "allow" ? [1] : []
    content {
      name     = "AWSManagedRulesBotControlRuleSet"
      priority = var.bot_control_priority

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesBotControlRuleSet"
          vendor_name = "AWS"
          version     = var.bot_control_version != "" ? var.bot_control_version : null

          managed_rule_group_configs {
            aws_managed_rules_bot_control_rule_set {
              inspection_level = var.bot_control_inspection_level
            }
          }

          dynamic "rule_action_override" {
            for_each = var.bot_control_rule_action_overrides
            content {
              name = rule_action_override.value.name
              action_to_use {
                dynamic "allow" {
                  for_each = rule_action_override.value.action == "allow" ? [1] : []
                  content {}
                }
                dynamic "block" {
                  for_each = rule_action_override.value.action == "block" ? [1] : []
                  content {}
                }
                dynamic "count" {
                  for_each = rule_action_override.value.action == "count" ? [1] : []
                  content {}
                }
                dynamic "captcha" {
                  for_each = rule_action_override.value.action == "captcha" ? [1] : []
                  content {}
                }
                dynamic "challenge" {
                  for_each = rule_action_override.value.action == "challenge" ? [1] : []
                  content {}
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-bot-control"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Anti-DDoS Rule ----
  dynamic "rule" {
    for_each = var.enable_anti_ddos && var.anti_ddos_action != "allow" ? [1] : []
    content {
      name     = "AWSManagedRulesAntiDDoSRuleSet"
      priority = var.anti_ddos_priority

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesAntiDDoSRuleSet"
          vendor_name = "AWS"

          dynamic "rule_action_override" {
            for_each = var.anti_ddos_rule_action_overrides
            content {
              name = rule_action_override.value.name
              action_to_use {
                dynamic "allow" {
                  for_each = rule_action_override.value.action == "allow" ? [1] : []
                  content {}
                }
                dynamic "block" {
                  for_each = rule_action_override.value.action == "block" ? [1] : []
                  content {}
                }
                dynamic "count" {
                  for_each = rule_action_override.value.action == "count" ? [1] : []
                  content {}
                }
                dynamic "captcha" {
                  for_each = rule_action_override.value.action == "captcha" ? [1] : []
                  content {}
                }
                dynamic "challenge" {
                  for_each = rule_action_override.value.action == "challenge" ? [1] : []
                  content {}
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-anti-ddos"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Linux Protection Rule ----
  dynamic "rule" {
    for_each = var.enable_linux_protection && var.linux_protection_action != "allow" ? [1] : []
    content {
      name     = "AWSManagedRulesLinuxRuleSet"
      priority = var.linux_protection_priority

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesLinuxRuleSet"
          vendor_name = "AWS"
          version     = var.linux_protection_version != "" ? var.linux_protection_version : null

          dynamic "rule_action_override" {
            for_each = var.linux_protection_rule_action_overrides
            content {
              name = rule_action_override.value.name
              action_to_use {
                dynamic "allow" {
                  for_each = rule_action_override.value.action == "allow" ? [1] : []
                  content {}
                }
                dynamic "block" {
                  for_each = rule_action_override.value.action == "block" ? [1] : []
                  content {}
                }
                dynamic "count" {
                  for_each = rule_action_override.value.action == "count" ? [1] : []
                  content {}
                }
                dynamic "captcha" {
                  for_each = rule_action_override.value.action == "captcha" ? [1] : []
                  content {}
                }
                dynamic "challenge" {
                  for_each = rule_action_override.value.action == "challenge" ? [1] : []
                  content {}
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-linux-protection"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Unix Protection Rule ----
  dynamic "rule" {
    for_each = var.enable_unix_protection && var.unix_protection_action != "allow" ? [1] : []
    content {
      name     = "AWSManagedRulesUnixRuleSet"
      priority = var.unix_protection_priority

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesUnixRuleSet"
          vendor_name = "AWS"

          dynamic "rule_action_override" {
            for_each = var.unix_protection_rule_action_overrides
            content {
              name = rule_action_override.value.name
              action_to_use {
                dynamic "allow" {
                  for_each = rule_action_override.value.action == "allow" ? [1] : []
                  content {}
                }
                dynamic "block" {
                  for_each = rule_action_override.value.action == "block" ? [1] : []
                  content {}
                }
                dynamic "count" {
                  for_each = rule_action_override.value.action == "count" ? [1] : []
                  content {}
                }
                dynamic "captcha" {
                  for_each = rule_action_override.value.action == "captcha" ? [1] : []
                  content {}
                }
                dynamic "challenge" {
                  for_each = rule_action_override.value.action == "challenge" ? [1] : []
                  content {}
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-unix-protection"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Windows Protection Rule ----
  dynamic "rule" {
    for_each = var.enable_windows_protection && var.windows_protection_action != "allow" ? [1] : []
    content {
      name     = "AWSManagedRulesWindowsRuleSet"
      priority = var.windows_protection_priority

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesWindowsRuleSet"
          vendor_name = "AWS"

          dynamic "rule_action_override" {
            for_each = var.windows_protection_rule_action_overrides
            content {
              name = rule_action_override.value.name
              action_to_use {
                dynamic "allow" {
                  for_each = rule_action_override.value.action == "allow" ? [1] : []
                  content {}
                }
                dynamic "block" {
                  for_each = rule_action_override.value.action == "block" ? [1] : []
                  content {}
                }
                dynamic "count" {
                  for_each = rule_action_override.value.action == "count" ? [1] : []
                  content {}
                }
                dynamic "captcha" {
                  for_each = rule_action_override.value.action == "captcha" ? [1] : []
                  content {}
                }
                dynamic "challenge" {
                  for_each = rule_action_override.value.action == "challenge" ? [1] : []
                  content {}
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-windows-protection"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- PHP Protection Rule ----
  dynamic "rule" {
    for_each = var.enable_php_protection && var.php_protection_action != "allow" ? [1] : []
    content {
      name     = "AWSManagedRulesPHPRuleSet"
      priority = var.php_protection_priority

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesPHPRuleSet"
          vendor_name = "AWS"

          dynamic "rule_action_override" {
            for_each = var.php_protection_rule_action_overrides
            content {
              name = rule_action_override.value.name
              action_to_use {
                dynamic "allow" {
                  for_each = rule_action_override.value.action == "allow" ? [1] : []
                  content {}
                }
                dynamic "block" {
                  for_each = rule_action_override.value.action == "block" ? [1] : []
                  content {}
                }
                dynamic "count" {
                  for_each = rule_action_override.value.action == "count" ? [1] : []
                  content {}
                }
                dynamic "captcha" {
                  for_each = rule_action_override.value.action == "captcha" ? [1] : []
                  content {}
                }
                dynamic "challenge" {
                  for_each = rule_action_override.value.action == "challenge" ? [1] : []
                  content {}
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-php-protection"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- WordPress Protection Rule ----
  dynamic "rule" {
    for_each = var.enable_wordpress_protection && var.wordpress_protection_action != "allow" ? [1] : []
    content {
      name     = "AWSManagedRulesWordPressRuleSet"
      priority = var.wordpress_protection_priority

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesWordPressRuleSet"
          vendor_name = "AWS"

          dynamic "rule_action_override" {
            for_each = var.wordpress_protection_rule_action_overrides
            content {
              name = rule_action_override.value.name
              action_to_use {
                dynamic "allow" {
                  for_each = rule_action_override.value.action == "allow" ? [1] : []
                  content {}
                }
                dynamic "block" {
                  for_each = rule_action_override.value.action == "block" ? [1] : []
                  content {}
                }
                dynamic "count" {
                  for_each = rule_action_override.value.action == "count" ? [1] : []
                  content {}
                }
                dynamic "captcha" {
                  for_each = rule_action_override.value.action == "captcha" ? [1] : []
                  content {}
                }
                dynamic "challenge" {
                  for_each = rule_action_override.value.action == "challenge" ? [1] : []
                  content {}
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-wordpress-protection"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- IP Blocklist Rule ----
  dynamic "rule" {
    for_each = var.create_waf && length(var.blocklist_ips) > 0 ? [1] : []
    content {
      name     = "Block-IP"
      priority = var.blocklist_priority

      action {
        block {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.blocklist[0].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "Block-IP"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- IP Allowlist Rule ----
  dynamic "rule" {
    for_each = var.create_waf && length(var.allowlist_ips) > 0 ? [1] : []
    content {
      name     = "Allow-IPs"
      priority = var.allowlist_priority

      action {
        allow {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.allowlist[0].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "Allow-IPs"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Block Admin Paths ----
  dynamic "rule" {
    for_each = var.enable_block_admin && length(var.block_admin_paths) >= 2 ? [1] : []
    content {
      name     = "Restrict-Admin"
      priority = var.block_admin_priority

      action {
        block {}
      }

      statement {
        or_statement {
          dynamic "statement" {
            for_each = var.block_admin_paths
            content {
              byte_match_statement {
                search_string         = statement.value
                positional_constraint = "STARTS_WITH"
                field_to_match {
                  uri_path {}
                }
                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "Restrict-Admin"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Block Git Access ----
  dynamic "rule" {
    for_each = var.enable_block_git ? [1] : []
    content {
      name     = "block-git-access"
      priority = var.block_git_priority

      action {
        block {}
      }

      statement {
        byte_match_statement {
          search_string         = "/.git"
          positional_constraint = "STARTS_WITH"
          field_to_match {
            uri_path {}
          }
          text_transformation {
            priority = 0
            type     = "LOWERCASE"
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "block-git-access"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Block Specific URLs ----
  dynamic "rule" {
    for_each = var.enable_block_specific_urls && length(var.blocked_urls) >= 2 ? [1] : []
    content {
      name     = "PROD-biz2credit-com-waf-BlockSpecificURL"
      priority = var.block_specific_urls_priority

      action {
        block {}
      }

      statement {
        or_statement {
          dynamic "statement" {
            for_each = var.blocked_urls
            content {
              byte_match_statement {
                search_string         = statement.value
                positional_constraint = "EXACTLY"
                field_to_match {
                  uri_path {}
                }
                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "PROD-biz2credit-com-waf-BlockSpecificURL"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Block File Extensions ----
  dynamic "rule" {
    for_each = var.enable_block_extensions && length(var.blocked_extensions) >= 2 ? [1] : []
    content {
      name     = "BlockExtensions-UriPath"
      priority = var.block_extensions_priority

      action {
        block {}
      }

      statement {
        or_statement {
          dynamic "statement" {
            for_each = var.blocked_extensions
            content {
              byte_match_statement {
                search_string         = statement.value
                positional_constraint = "ENDS_WITH"
                field_to_match {
                  uri_path {}
                }
                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "BlockExtensions-UriPath"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Block African Countries (Part 1) ----
  dynamic "rule" {
    for_each = var.enable_block_african_countries && length(var.african_country_codes_1) > 0 ? [1] : []
    content {
      name     = "Block-African-Countries-1"
      priority = var.block_african_countries_priority

      action {
        block {}
      }

      statement {
        geo_match_statement {
          country_codes = var.african_country_codes_1
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "Block-African-Countries-1"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Block African Countries (Part 2) ----
  dynamic "rule" {
    for_each = var.enable_block_african_countries && length(var.african_country_codes_2) > 0 ? [1] : []
    content {
      name     = "Block-African-Countries-2"
      priority = var.block_african_countries_priority_2

      action {
        block {}
      }

      statement {
        geo_match_statement {
          country_codes = var.african_country_codes_2
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "Block-African-Countries-2"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Block South American Countries ----
  dynamic "rule" {
    for_each = var.enable_block_south_america && length(var.south_america_country_codes) > 0 ? [1] : []
    content {
      name     = "Block-SouthAmerica-Countries"
      priority = var.block_south_america_priority

      action {
        block {}
      }

      statement {
        geo_match_statement {
          country_codes = var.south_america_country_codes
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "Block-SouthAmerica-Countries"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Block Selected Countries Group 1 ----
  dynamic "rule" {
    for_each = var.enable_block_selected_countries_1 && length(var.selected_country_codes_1) > 0 ? [1] : []
    content {
      name     = "PROD-biz2credit-com-WAF-BlockSelectedCountries1"
      priority = var.block_selected_countries_1_priority

      action {
        block {}
      }

      statement {
        geo_match_statement {
          country_codes = var.selected_country_codes_1
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "PROD-biz2credit-com-WAF-BlockSelectedCountries1"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Block Selected Countries Group 2 ----
  dynamic "rule" {
    for_each = var.enable_block_selected_countries_2 && length(var.selected_country_codes_2) > 0 ? [1] : []
    content {
      name     = "PROD-biz2credit-com-WAF-BlockSelectedCountries2"
      priority = var.block_selected_countries_2_priority

      action {
        block {}
      }

      statement {
        geo_match_statement {
          country_codes = var.selected_country_codes_2
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "PROD-biz2credit-com-WAF-BlockSelectedCountries2"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Allow Country US (block all non-US) ----
  dynamic "rule" {
    for_each = var.enable_allow_country_us ? [1] : []
    content {
      name     = "AllowCountryUS"
      priority = var.allow_country_us_priority

      action {
        block {}
      }

      statement {
        not_statement {
          statement {
            geo_match_statement {
              country_codes = ["US"]
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "AllowCountryUS"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Allow IN-US (allow traffic from India and United States) ----
  dynamic "rule" {
    for_each = var.enable_allow_in_us ? [1] : []
    content {
      name     = "IN-US"
      priority = var.allow_in_us_priority

      action {
        allow {}
      }

      statement {
        geo_match_statement {
          country_codes = var.allow_in_us_country_codes
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "IN-US"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Allow Specific URLs ----
  dynamic "rule" {
    for_each = var.enable_allow_specific_urls && length(var.allowed_urls) >= 2 ? [1] : []
    content {
      name     = "Allow-URLS"
      priority = var.allow_specific_urls_priority

      action {
        allow {}
      }

      statement {
        or_statement {
          dynamic "statement" {
            for_each = var.allowed_urls
            content {
              byte_match_statement {
                search_string         = statement.value
                positional_constraint = "STARTS_WITH"
                field_to_match {
                  uri_path {}
                }
                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "Allow-URLS"
        sampled_requests_enabled   = true
      }
    }
  }

  # ---- Rate Limiting Rule ----
  dynamic "rule" {
    for_each = var.enable_rate_limiting && var.rate_limiting_action != "allow" ? [1] : []
    content {
      name     = "RateLimit"
      priority = var.rate_limiting_priority

      action {
        dynamic "block" {
          for_each = var.rate_limiting_action == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = var.rate_limiting_action == "count" ? [1] : []
          content {}
        }
      }

      statement {
        rate_based_statement {
          limit              = var.rate_limit_threshold
          aggregate_key_type = "IP"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "RateLimit"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name_prefix}-web-acl"
    sampled_requests_enabled   = true
  }

  tags = merge(var.tags, { Name = "${local.name_prefix}-web-acl" })
}

# -----------------------------------------------------------------------------
# WAF Logging Configuration (optional)
# -----------------------------------------------------------------------------
resource "aws_wafv2_web_acl_logging_configuration" "this" {
  count                   = var.create_waf && var.enable_waf_logging && var.log_destination_arn != "" ? 1 : 0
  log_destination_configs = [var.log_destination_arn]
  resource_arn            = aws_wafv2_web_acl.this[0].arn
}

# -----------------------------------------------------------------------------
# WAF <-> ALB Association
# Manages associations independently of WAF creation
# -----------------------------------------------------------------------------
resource "aws_wafv2_web_acl_association" "this" {
  # Create associations when:
  # 1. associate_waf is true
  # 2. We have ALB ARNs to associate
  # 3. We have a valid WAF ARN (either from creation or existing)
  for_each = var.associate_waf && length(var.alb_arns) > 0 ? toset(var.alb_arns) : toset([])

  resource_arn = each.value
  # Use the determined WAF ARN from locals
  web_acl_arn = local.web_acl_arn

  # Depend on WAF resource if we're creating it
  # Note: depends_on must be a static list, so we include it always
  # but it only matters when create_waf=true
  depends_on = [aws_wafv2_web_acl.this]
}

# Validation: Ensure existing_web_acl_arn is provided when not creating WAF
resource "null_resource" "validate_web_acl_arn" {
  count = !var.create_waf && var.associate_waf && var.existing_web_acl_arn == "" ? 1 : 0

  provisioner "local-exec" {
    command = "echo 'ERROR: existing_web_acl_arn must be provided when create_waf=false and associate_waf=true' && exit 1"
  }
}
