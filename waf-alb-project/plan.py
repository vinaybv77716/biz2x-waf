#!/usr/bin/env python3
"""
Terraform WAF Plan Analyzer
============================
Reads a terraform plan JSON and prints a clean ASCII table report to stdout.
Designed for Jenkins console output — NO HTML, NO files, pure text.

Covers:
  - Project / environment metadata
  - ALB ARNs (associated / planned)
  - WAF Web ACL overview
  - AWS Managed Rule Groups + sub-rule overrides
  - Custom rules: Restrict-Admin, block-git-access, BlockSpecificURL,
    BlockExtensions, geo-block rules, AllowCountryUS, Allow-URLS
  - IP allowlist / blocklist
  - Rate limiting
  - Bot Control (with inspection level)
  - Anti-DDoS
  - WCU budget summary
  - Before vs After diffs when resource_changes are present

Usage:
    python3 plan.py plan.json
    python3 plan.py before.json after.json
"""

import json, sys, os, argparse
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# WCU reference table
# ─────────────────────────────────────────────────────────────
WCU_MAP = {
    "AWSManagedRulesCommonRuleSet":        700,
    "AWSManagedRulesSQLiRuleSet":          200,
    "AWSManagedRulesKnownBadInputsRuleSet":200,
    "AWSManagedRulesLinuxRuleSet":         200,
    "AWSManagedRulesWindowsRuleSet":       200,
    "AWSManagedRulesUnixRuleSet":          100,
    "AWSManagedRulesPHPRuleSet":           100,
    "AWSManagedRulesWordPressRuleSet":      100,
    "AWSManagedRulesAnonymousIpList":       50,
    "AWSManagedRulesBotControlRuleSet":     50,
    "AWSManagedRulesAntiDDoSRuleSet":      100,
    "AWSManagedRulesAmazonIpReputationList":25,
    "RateLimit":                             2,
    "Restrict-Admin":                        1,
    "block-git-access":                      1,
    "PROD-biz2credit-com-waf-BlockSpecificURL": 1,
    "BlockExtensions-UriPath":               1,
    "GEORestrictionAfrica":                  1,
    "Block-African-Countries-1":             1,
    "Block-African-Countries-2":             1,
    "Block-SouthAmerica-Countries":          1,
    "GEORestriction-Europe":                 1,
    "GEORestriction-Asia":                   1,
    "GEORestriction-Oceania":                1,
    "PROD-biz2credit-com-WAF-BlockSelectedCountries1": 1,
    "PROD-biz2credit-com-WAF-BlockSelectedCountries2": 1,
    "AllowCountryUS":                        1,
    "IN-US":                                 1,
    "Allow-URLS":                            1,
    "keybank-frontend-prod-allowIP":         1,
    "Allow-IPs":                             1,
    "VPN-AllowIp":                           1,
    "Block-IP":                              1,
}
WCU_LIMIT = 1500

# ─────────────────────────────────────────────────────────────
# TABLE DRAWING  (pure ASCII)
# ─────────────────────────────────────────────────────────────
SEP = "+"
H   = "-"
V   = "|"
NL  = "\n"

def make_divider(widths):
    return SEP + SEP.join(H * (w + 2) for w in widths) + SEP

def make_row(values, widths):
    return V + V.join(" {:<{}} ".format(str(v), w) for v, w in zip(values, widths)) + V

def make_table(headers, rows):
    if not rows:
        widths = [len(h) for h in headers]
        div = make_divider(widths)
        hdr = make_row(headers, widths)
        empty = V + "  (no data)  ".center(sum(w + 3 for w in widths) - 1) + V
        return NL.join([div, hdr, div, empty, div])
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    lines = [make_divider(widths), make_row(headers, widths), make_divider(widths)]
    for row in rows:
        lines.append(make_row([str(c) for c in row], widths))
    lines.append(make_divider(widths))
    return NL.join(lines)

def section(title):
    bar = "=" * 80
    return "\n{}\n  {}\n{}".format(bar, title, bar)

def subsection(title):
    bar = "-" * 60
    return "\n{}\n  {}\n{}".format(bar, title, bar)

# ─────────────────────────────────────────────────────────────
# ACTION EXTRACTION
# ─────────────────────────────────────────────────────────────
ACTION_TYPES = ["block", "count", "allow", "captcha", "challenge"]

def action_from_item(item):
    for a in ACTION_TYPES:
        val = item.get(a)
        if isinstance(val, list) and len(val) > 0:
            return a
    return "unknown"

def action_from_list(action_to_use):
    for item in action_to_use:
        a = action_from_item(item)
        if a != "unknown":
            return a
    return "unknown"

def override_action_from_rule(rule):
    for item in rule.get("override_action", []):
        for a in ["count", "none"]:
            val = item.get(a)
            if isinstance(val, list) and len(val) > 0:
                return a
    return None

def rule_action_from_rule(rule):
    for item in rule.get("action", []):
        a = action_from_item(item)
        if a != "unknown":
            return a
    return None

def effective_action(rule):
    ra = rule_action_from_rule(rule)
    oa = override_action_from_rule(rule)
    return ra or oa or "unknown"

def extract_subrules(rule):
    subs = {}
    for stmt in rule.get("statement", []):
        for mg in stmt.get("managed_rule_group_statement", []):
            for ov in mg.get("rule_action_override", []):
                name   = ov.get("name", "?")
                action = action_from_list(ov.get("action_to_use", []))
                subs[name] = action
    return subs

def extract_rate_limit(rule):
    for stmt in rule.get("statement", []):
        for rb in stmt.get("rate_based_statement", []):
            return str(rb.get("limit", "?"))
    return "N/A"

def extract_geo_countries(rule):
    """Extract country codes from geo_match_statement."""
    for stmt in rule.get("statement", []):
        for geo in stmt.get("geo_match_statement", []):
            return geo.get("country_codes", [])
        # not_statement wrapping geo (AllowCountryUS)
        for ns in stmt.get("not_statement", []):
            for inner in ns.get("statement", []):
                for geo in inner.get("geo_match_statement", []):
                    return ["NOT " + c for c in geo.get("country_codes", [])]
    return []

def extract_byte_match_strings(rule):
    """Extract search strings from byte_match / or_statement."""
    strings = []
    for stmt in rule.get("statement", []):
        for bm in stmt.get("byte_match_statement", []):
            strings.append(bm.get("search_string", "?"))
        for os_ in stmt.get("or_statement", []):
            for inner in os_.get("statement", []):
                for bm in inner.get("byte_match_statement", []):
                    strings.append(bm.get("search_string", "?"))
    return strings

def extract_bot_inspection_level(rule):
    for stmt in rule.get("statement", []):
        for mg in stmt.get("managed_rule_group_statement", []):
            for cfg in mg.get("managed_rule_group_configs", []):
                for bc in cfg.get("aws_managed_rules_bot_control_rule_set", []):
                    return bc.get("inspection_level", "N/A")
    return "N/A"

# ─────────────────────────────────────────────────────────────
# RULE EXTRACTION from resource_changes or planned_values
# ─────────────────────────────────────────────────────────────
def rules_from_list(rule_list):
    result = {}
    for rule in (rule_list or []):
        name = rule.get("name", "UNKNOWN")
        result[name] = {
            "priority":          rule.get("priority"),
            "effective_action":  effective_action(rule),
            "rule_action":       rule_action_from_rule(rule),
            "override_action":   override_action_from_rule(rule),
            "subrules":          extract_subrules(rule),
            "rate_limit":        extract_rate_limit(rule),
            "geo_countries":     extract_geo_countries(rule),
            "byte_strings":      extract_byte_match_strings(rule),
            "bot_inspect_level": extract_bot_inspection_level(rule),
        }
    return result

def rules_from_state(state_values):
    for mod in state_values.get("root_module", {}).get("child_modules", []):
        for res in mod.get("resources", []):
            if res.get("type") == "aws_wafv2_web_acl":
                return rules_from_list(res.get("values", {}).get("rule", []))
    return {}

def rules_from_changes(plan):
    for ch in plan.get("resource_changes", []):
        if ch.get("type") == "aws_wafv2_web_acl":
            b = rules_from_list((ch.get("change", {}).get("before") or {}).get("rule", []))
            a = rules_from_list((ch.get("change", {}).get("after")  or {}).get("rule", []))
            return b, a
    return {}, {}

# ─────────────────────────────────────────────────────────────
# VARIABLES-BASED EXTRACTION  (fallback when no state)
# ─────────────────────────────────────────────────────────────
VAR_PREFIX_TO_AWS = {
    "aws_managed_rules":    "AWSManagedRulesCommonRuleSet",
    "known_bad_inputs":     "AWSManagedRulesKnownBadInputsRuleSet",
    "sql_injection":        "AWSManagedRulesSQLiRuleSet",
    "ip_reputation":        "AWSManagedRulesAmazonIpReputationList",
    "linux_protection":     "AWSManagedRulesLinuxRuleSet",
    "unix_protection":      "AWSManagedRulesUnixRuleSet",
    "windows_protection":   "AWSManagedRulesWindowsRuleSet",
    "php_protection":       "AWSManagedRulesPHPRuleSet",
    "wordpress_protection": "AWSManagedRulesWordPressRuleSet",
    "anonymous_ip":         "AWSManagedRulesAnonymousIpList",
    "bot_control":          "AWSManagedRulesBotControlRuleSet",
    "anti_ddos":            "AWSManagedRulesAntiDDoSRuleSet",
}

# Custom rule variable prefix -> display name
CUSTOM_RULES = [
    ("block_admin",               "Restrict-Admin",                          "block_admin_priority"),
    ("block_git",                 "block-git-access",                        "block_git_priority"),
    ("block_specific_urls",       "PROD-biz2credit-com-waf-BlockSpecificURL","block_specific_urls_priority"),
    ("block_extensions",          "BlockExtensions-UriPath",                 "block_extensions_priority"),
    ("block_african_countries",   "GEORestrictionAfrica",                    "block_african_countries_priority"),
    ("block_african_countries",   "Block-African-Countries-2",               "block_african_countries_priority_2"),
    ("block_south_america",       "Block-SouthAmerica-Countries",            "block_south_america_priority"),
    ("block_europe",              "GEORestriction-Europe",                   "block_europe_priority"),
    ("block_asia",                "GEORestriction-Asia",                     "block_asia_priority"),
    ("block_oceania",             "GEORestriction-Oceania",                  "block_oceania_priority"),
    ("block_selected_countries_1","PROD-biz2credit-com-WAF-BlockSelectedCountries1","block_selected_countries_1_priority"),
    ("block_selected_countries_2","PROD-biz2credit-com-WAF-BlockSelectedCountries2","block_selected_countries_2_priority"),
    ("allow_country_us",          "AllowCountryUS",                          "allow_country_us_priority"),
    ("allow_in_us",               "IN-US",                                   "allow_in_us_priority"),
    ("allow_specific_urls",       "Allow-URLS",                              "allow_specific_urls_priority"),
]

def rules_from_variables(plan):
    vars_ = {k: v.get("value") for k, v in plan.get("variables", {}).items()}
    result = {}

    # AWS Managed rules with sub-rule overrides
    for key, val in vars_.items():
        if not key.endswith("_rule_action_overrides"):
            continue
        prefix   = key[: -len("_rule_action_overrides")]
        aws_name = VAR_PREFIX_TO_AWS.get(prefix, prefix)
        priority = vars_.get("{}_priority".format(prefix), "N/A")
        action   = vars_.get("{}_action".format(prefix), "N/A")
        enabled  = vars_.get("enable_{}".format(prefix), "N/A")
        overrides = val or []
        subrules = {ov["name"]: ov["action"] for ov in overrides
                    if "name" in ov and "action" in ov}
        extra = {}
        if prefix == "bot_control":
            extra["bot_inspect_level"] = vars_.get("bot_control_inspection_level", "N/A")
        result[aws_name] = {
            "priority": priority, "effective_action": action,
            "rule_action": None, "override_action": action,
            "subrules": subrules, "rate_limit": "N/A",
            "geo_countries": [], "byte_strings": [],
            "bot_inspect_level": extra.get("bot_inspect_level", "N/A"),
            "enabled": enabled,
        }

    # Anonymous IP (no sub-rules)
    if "anonymous_ip_priority" in vars_:
        result["AWSManagedRulesAnonymousIpList"] = {
            "priority": vars_.get("anonymous_ip_priority", "N/A"),
            "effective_action": vars_.get("anonymous_ip_action", "N/A"),
            "rule_action": None, "override_action": vars_.get("anonymous_ip_action", "N/A"),
            "subrules": {}, "rate_limit": "N/A",
            "geo_countries": [], "byte_strings": [], "bot_inspect_level": "N/A",
            "enabled": vars_.get("enable_anonymous_ip", "N/A"),
        }

    # Bot Control (may not have overrides var but still needs entry)
    if "bot_control_priority" in vars_ and "AWSManagedRulesBotControlRuleSet" not in result:
        result["AWSManagedRulesBotControlRuleSet"] = {
            "priority": vars_.get("bot_control_priority", "N/A"),
            "effective_action": vars_.get("bot_control_action", "N/A"),
            "rule_action": None, "override_action": vars_.get("bot_control_action", "N/A"),
            "subrules": {}, "rate_limit": "N/A",
            "geo_countries": [], "byte_strings": [],
            "bot_inspect_level": vars_.get("bot_control_inspection_level", "N/A"),
            "enabled": vars_.get("enable_bot_control", "N/A"),
        }

    # Anti-DDoS
    if "anti_ddos_priority" in vars_:
        result["AWSManagedRulesAntiDDoSRuleSet"] = {
            "priority": vars_.get("anti_ddos_priority", "N/A"),
            "effective_action": vars_.get("anti_ddos_action", "N/A"),
            "rule_action": None, "override_action": vars_.get("anti_ddos_action", "N/A"),
            "subrules": {}, "rate_limit": "N/A",
            "geo_countries": [], "byte_strings": [], "bot_inspect_level": "N/A",
            "enabled": vars_.get("enable_anti_ddos", "N/A"),
        }

    # Rate Limiting
    if "rate_limiting_priority" in vars_:
        result["RateLimit"] = {
            "priority": vars_.get("rate_limiting_priority", "N/A"),
            "effective_action": vars_.get("rate_limiting_action", "N/A"),
            "rule_action": vars_.get("rate_limiting_action", "N/A"),
            "override_action": None, "subrules": {},
            "rate_limit": str(vars_.get("rate_limit_threshold", "N/A")),
            "geo_countries": [], "byte_strings": [], "bot_inspect_level": "N/A",
            "enabled": vars_.get("enable_rate_limiting", "N/A"),
        }

    # IP Allowlist / Blocklist — always include even if empty, so diffs are detected
    result["keybank-frontend-prod-allowIP"] = {
        "priority": vars_.get("allowlist_priority", "N/A"),
        "effective_action": "allow", "rule_action": "allow",
        "override_action": None, "subrules": {},
        "rate_limit": "N/A", "geo_countries": [],
        "byte_strings": vars_.get("allowlist_ips") or [],
        "bot_inspect_level": "N/A",
        "enabled": bool(vars_.get("allowlist_ips") or vars_.get("allowlist_ip_set_arn")),
        "ip_set_name": vars_.get("allowlist_ip_set_name", ""),
        "ip_set_arn":  vars_.get("allowlist_ip_set_arn", ""),
    }
    result["VPN-AllowIp"] = {
        "priority": vars_.get("vpn_allowlist_priority", "N/A"),
        "effective_action": "allow", "rule_action": "allow",
        "override_action": None, "subrules": {},
        "rate_limit": "N/A", "geo_countries": [],
        "byte_strings": vars_.get("vpn_allowlist_ips") or [],
        "bot_inspect_level": "N/A",
        "enabled": bool(vars_.get("vpn_allowlist_ips") or vars_.get("vpn_allowlist_ip_set_arn")),
        "ip_set_name": vars_.get("vpn_allowlist_ip_set_name", ""),
        "ip_set_arn":  vars_.get("vpn_allowlist_ip_set_arn", ""),
    }
    result["Allow-IPs"] = {
        "priority": vars_.get("allowlist_priority", "N/A"),
        "effective_action": "allow", "rule_action": "allow",
        "override_action": None, "subrules": {},
        "rate_limit": "N/A", "geo_countries": [],
        "byte_strings": vars_.get("allowlist_ips") or [],
        "bot_inspect_level": "N/A",
        "enabled": bool(vars_.get("allowlist_ips")),
    }
    result["Block-IP"] = {
        "priority": vars_.get("blocklist_priority", "N/A"),
        "effective_action": "block", "rule_action": "block",
        "override_action": None, "subrules": {},
        "rate_limit": "N/A", "geo_countries": [],
        "byte_strings": vars_.get("blocklist_ips") or [],
        "bot_inspect_level": "N/A",
        "enabled": bool(vars_.get("blocklist_ips")),
    }

    # Custom rules
    for enable_key, display_name, prio_key in CUSTOM_RULES:
        enabled = vars_.get("enable_{}".format(enable_key), False)
        priority = vars_.get(prio_key, "N/A")
        # geo rules
        geo = []
        if "african" in enable_key:
            if "2" in prio_key:
                geo = vars_.get("african_country_codes_2", [])
            else:
                geo = vars_.get("african_country_codes_1", [])
        elif "south_america" in enable_key:
            geo = vars_.get("south_america_country_codes", [])
        elif "block_europe" in enable_key:
            geo = vars_.get("europe_country_codes", [])
        elif "block_asia" in enable_key:
            geo = vars_.get("asia_country_codes", [])
        elif "block_oceania" in enable_key:
            geo = vars_.get("oceania_country_codes", [])
        elif "selected_countries_1" in enable_key:
            geo = vars_.get("selected_country_codes_1", [])
        elif "selected_countries_2" in enable_key:
            geo = vars_.get("selected_country_codes_2", [])
        elif "allow_country_us" in enable_key:
            geo = ["NOT US (blocks all non-US)"]
        elif "allow_in_us" in enable_key:
            geo = vars_.get("allow_in_us_country_codes", [])
        # byte match rules
        byte_strings = []
        if "block_admin" in enable_key:
            byte_strings = vars_.get("block_admin_paths", [])
        elif "block_git" in enable_key:
            byte_strings = ["/.git"]
        elif "block_specific_urls" in enable_key:
            byte_strings = vars_.get("blocked_urls", [])
        elif "block_extensions" in enable_key:
            byte_strings = vars_.get("blocked_extensions", [])
        elif "allow_specific_urls" in enable_key:
            byte_strings = vars_.get("allowed_urls", [])

        is_allow = "allow_country_us" in enable_key or "allow_in_us" in enable_key or "allow_specific_urls" in enable_key
        result[display_name] = {
            "priority": priority,
            "effective_action": "allow" if is_allow else "block",
            "rule_action": "allow" if is_allow else "block",
            "override_action": None, "subrules": {},
            "rate_limit": "N/A", "geo_countries": geo,
            "byte_strings": byte_strings, "bot_inspect_level": "N/A",
            "enabled": enabled,
        }

    return result

# ─────────────────────────────────────────────────────────────
# ALB & WAF ARN EXTRACTION
# ─────────────────────────────────────────────────────────────
def extract_albs(plan):
    result = {"before": [], "after": []}
    vars_ = {k: v.get("value") for k, v in plan.get("variables", {}).items()}
    alb_var = vars_.get("alb_arns", [])
    if alb_var:
        result["after"] = alb_var
    oc = plan.get("output_changes", {})
    if "associated_alb_arns" in oc:
        b = oc["associated_alb_arns"].get("before") or []
        a = oc["associated_alb_arns"].get("after")  or []
        if b: result["before"] = b if isinstance(b, list) else [b]
        if a: result["after"]  = a if isinstance(a, list) else [a]
    pv_albs = (plan.get("planned_values", {})
                   .get("outputs", {})
                   .get("associated_alb_arns", {})
                   .get("value"))
    if pv_albs:
        result["after"] = pv_albs if isinstance(pv_albs, list) else [pv_albs]
    for ch in plan.get("resource_changes", []):
        if ch.get("type") == "aws_wafv2_web_acl_association":
            b_arn = (ch.get("change", {}).get("before") or {}).get("resource_arn")
            a_arn = (ch.get("change", {}).get("after")  or {}).get("resource_arn")
            if b_arn and b_arn not in result["before"]: result["before"].append(b_arn)
            if a_arn and a_arn not in result["after"]:  result["after"].append(a_arn)
    return result

def extract_waf_arn(plan):
    result = {"before": "N/A", "after": "N/A"}
    oc = plan.get("output_changes", {})
    if "web_acl_arn" in oc:
        result["before"] = oc["web_acl_arn"].get("before") or "N/A"
        result["after"]  = oc["web_acl_arn"].get("after")  or "N/A"
    pv = (plan.get("planned_values", {})
              .get("outputs", {})
              .get("web_acl_arn", {})
              .get("value"))
    if pv:
        result["after"] = pv
    return result

def extract_metadata(plan):
    vars_ = {k: v.get("value") for k, v in plan.get("variables", {}).items()}
    return {
        "project":        vars_.get("project",        "N/A"),
        "environment":    vars_.get("environment",    "N/A"),
        "aws_region":     vars_.get("aws_region",     "N/A"),
        "default_action": vars_.get("default_action", "N/A"),
        "create_waf":     vars_.get("create_waf",     "N/A"),
        "associate_waf":  vars_.get("associate_waf",  "N/A"),
        "tf_version":     plan.get("terraform_version", "N/A"),
        "timestamp":      plan.get("timestamp",        "N/A"),
        "applyable":      plan.get("applyable",        "N/A"),
    }

# ─────────────────────────────────────────────────────────────
# IP SET CHANGES  (aws_wafv2_ip_set is a separate resource)
# ─────────────────────────────────────────────────────────────
def extract_ip_set_changes(plan):
    """Return list of dicts describing ip_set resource changes."""
    changes = []
    for ch in plan.get("resource_changes", []):
        if ch.get("type") != "aws_wafv2_ip_set":
            continue
        actions = ch.get("change", {}).get("actions", [])
        before  = ch.get("change", {}).get("before") or {}
        after   = ch.get("change", {}).get("after")  or {}
        name    = after.get("name") or before.get("name") or ch.get("name", "?")
        b_addrs = sorted(before.get("addresses", []) or [])
        a_addrs = sorted(after.get("addresses",  []) or [])
        if "no-op" in actions and b_addrs == a_addrs:
            continue
        changes.append({
            "name":    name,
            "actions": actions,
            "before":  b_addrs,
            "after":   a_addrs,
        })
    return changes

def print_ip_set_changes(ip_changes):
    print(section("IP SET CHANGES  (aws_wafv2_ip_set)"))
    if not ip_changes:
        print("\n  No IP set changes detected.\n")
        return
    for entry in ip_changes:
        print(subsection("{} — {}".format(entry["name"], ", ".join(entry["actions"]))))
        b_set = set(entry["before"])
        a_set = set(entry["after"])
        added   = sorted(a_set - b_set)
        removed = sorted(b_set - a_set)
        kept    = sorted(b_set & a_set)
        rows = []
        for ip in added:   rows.append([ip, "---",    ip,  "ADDED"])
        for ip in removed: rows.append([ip, ip,    "---",  "REMOVED"])
        for ip in kept:    rows.append([ip, ip,      ip,   "NO CHANGE"])
        print(make_table(["CIDR", "BEFORE", "AFTER", "STATUS"], rows))
def priority_sort_key(name, before, after):
    r = (after or {}).get(name) or (before or {}).get(name) or {}
    p = r.get("priority", 999)
    try:
        return int(str(p).replace("N/A", "999"))
    except Exception:
        return 999

def diff_rules(before, after):
    changes = []
    all_names = sorted(
        set(list(before.keys()) + list(after.keys())),
        key=lambda n: priority_sort_key(n, before, after)
    )
    for name in all_names:
        b = before.get(name)
        a = after.get(name)
        if b is None:
            changes.append(dict(rule=name, sub_rule="---", field="rule",
                                before_val="ABSENT", after_val="ADDED", status="ADDED"))
            continue
        if a is None:
            changes.append(dict(rule=name, sub_rule="---", field="rule",
                                before_val="PRESENT", after_val="REMOVED", status="REMOVED"))
            continue
        if str(b["priority"]) != str(a["priority"]):
            changes.append(dict(rule=name, sub_rule="---", field="priority",
                                before_val=b["priority"], after_val=a["priority"], status="CHANGED"))
        if b["effective_action"] != a["effective_action"]:
            changes.append(dict(rule=name, sub_rule="---", field="override_action",
                                before_val=b["effective_action"], after_val=a["effective_action"], status="CHANGED"))
        if (b.get("rate_limit") != a.get("rate_limit")
                and b.get("rate_limit") not in (None, "N/A")):
            changes.append(dict(rule=name, sub_rule="---", field="rate_limit",
                                before_val=b["rate_limit"], after_val=a["rate_limit"], status="CHANGED"))
        # Geo country diffs
        b_geo = sorted(b.get("geo_countries", []))
        a_geo = sorted(a.get("geo_countries", []))
        if b_geo != a_geo:
            b_set = set(b_geo)
            a_set = set(a_geo)
            for c in sorted(a_set - b_set):
                changes.append(dict(rule=name, sub_rule="---", field="country_code",
                                    before_val="---", after_val=c, status="ADDED"))
            for c in sorted(b_set - a_set):
                changes.append(dict(rule=name, sub_rule="---", field="country_code",
                                    before_val=c, after_val="---", status="REMOVED"))
        # IP / CIDR diffs
        b_ips = sorted(b.get("byte_strings", []))
        a_ips = sorted(a.get("byte_strings", []))
        if b_ips != a_ips:
            b_set = set(b_ips)
            a_set = set(a_ips)
            for ip in sorted(a_set - b_set):
                changes.append(dict(rule=name, sub_rule="---", field="ip/cidr",
                                    before_val="---", after_val=ip, status="ADDED"))
            for ip in sorted(b_set - a_set):
                changes.append(dict(rule=name, sub_rule="---", field="ip/cidr",
                                    before_val=ip, after_val="---", status="REMOVED"))
        all_subs = sorted(set(list(b["subrules"].keys()) + list(a["subrules"].keys())))
        for sub in all_subs:
            bv = b["subrules"].get(sub)
            av = a["subrules"].get(sub)
            if bv == av:
                continue
            st = "ADDED" if bv is None else ("REMOVED" if av is None else "CHANGED")
            changes.append(dict(rule=name, sub_rule=sub, field="action",
                                before_val=bv or "---", after_val=av or "---", status=st))
    return changes

# ─────────────────────────────────────────────────────────────
# PRINTERS
# ─────────────────────────────────────────────────────────────
def print_header(meta, plan_file):
    print("\n" + "=" * 80)
    print("  TERRAFORM WAF PLAN ANALYSIS")
    print("  File        : {}".format(os.path.basename(plan_file)))
    print("  Project     : {}".format(meta["project"]))
    print("  Environment : {}".format(meta["environment"]))
    print("  Region      : {}".format(meta["aws_region"]))
    print("  Default Act : {}".format(meta["default_action"]))
    print("  Create WAF  : {}".format(meta["create_waf"]))
    print("  Assoc WAF   : {}".format(meta["associate_waf"]))
    print("  TF Version  : {}".format(meta["tf_version"]))
    print("  Timestamp   : {}".format(meta["timestamp"]))
    print("  Applyable   : {}".format(meta["applyable"]))
    print("=" * 80)

def print_alb_section(albs, waf_arn):
    print(section("ALB ASSOCIATIONS & WAF ARN"))
    status = "NO CHANGE" if waf_arn["before"] == waf_arn["after"] else "CHANGED"
    print(make_table(["RESOURCE", "BEFORE", "AFTER", "STATUS"],
                     [["WAF ACL ARN", waf_arn["before"], waf_arn["after"], status]]))
    print(subsection("Associated ALB ARNs"))
    alb_before = set(albs["before"])
    alb_after  = set(albs["after"])
    all_albs   = sorted(alb_before | alb_after)
    if not all_albs:
        print("  (no ALBs associated in this plan)")
        return
    alb_rows = []
    for arn in all_albs:
        if   arn in alb_before and arn in alb_after: st = "NO CHANGE"
        elif arn in alb_after:                        st = "ADDED"
        else:                                         st = "REMOVED"
        alb_rows.append([arn, st])
    print(make_table(["ALB ARN", "STATUS"], alb_rows))

def print_rule_overview(before, after):
    print(section("WAF RULE OVERVIEW  (enabled rules only, sorted by priority)"))
    all_names = sorted(
        set(list(before.keys()) + list(after.keys())),
        key=lambda n: priority_sort_key(n, before, after)
    )
    rows = []
    for name in all_names:
        b = before.get(name, {})
        a = after.get(name, {})
        # Skip rules that are disabled in both before and after
        b_enabled = b.get("enabled", True)
        a_enabled = a.get("enabled", True)
        if (b_enabled is False or str(b_enabled).lower() == "false") and \
           (a_enabled is False or str(a_enabled).lower() == "false"):
            continue
        prio_b  = str(b.get("priority", "---"))
        prio_a  = str(a.get("priority", "---"))
        act_b   = str(b.get("effective_action", "---"))
        act_a   = str(a.get("effective_action", "---"))
        enabled = str(a_enabled)
        n_subs  = len(a.get("subrules", b.get("subrules", {})))
        wcu     = WCU_MAP.get(name, "?")
        if   name not in before:                              status = "ADDED"
        elif name not in after:                               status = "REMOVED"
        elif prio_b != prio_a or act_b != act_a:             status = "CHANGED"
        elif b.get("subrules", {}) != a.get("subrules", {}): status = "SUB-RULES CHANGED"
        elif b.get("geo_countries", []) != a.get("geo_countries", []): status = "GEO CHANGED"
        elif b.get("byte_strings", []) != a.get("byte_strings", []):   status = "IPs CHANGED"
        else:                                                 status = "NO CHANGE"
        prio_disp = prio_a if prio_a != "---" else prio_b
        act_disp  = act_a  if act_a  != "---" else act_b
        if prio_b != prio_a and prio_b != "---": prio_disp = "{} -> {}".format(prio_b, prio_a)
        if act_b  != act_a  and act_b  != "---": act_disp  = "{} -> {}".format(act_b,  act_a)
        rows.append([name, prio_disp, act_disp, n_subs, wcu, enabled, status])
    print(make_table(
        ["RULE NAME", "PRIORITY", "ACTION", "# SUB-RULES", "WCU", "ENABLED", "STATUS"],
        rows
    ))

def print_wcu_summary(after):
    print(section("WCU BUDGET SUMMARY  (enabled rules only)"))
    total = 0
    rows = []
    for name, info in sorted(after.items(), key=lambda x: priority_sort_key(x[0], {}, after)):
        enabled = info.get("enabled", True)
        if enabled is False or str(enabled).lower() == "false":
            continue
        # Skip duplicate legacy names
        if name in ("Allow-IPs",) and "keybank-frontend-prod-allowIP" in after:
            continue
        wcu = WCU_MAP.get(name, 0)
        if wcu == 0:
            continue
        total += wcu
        rows.append([name, wcu])
    rows.append(["TOTAL", total])
    over = " *** EXCEEDS LIMIT ***" if total > WCU_LIMIT else " (within limit)"
    print(make_table(["RULE", "WCU"], rows))
    print("\n  Hard limit: {}  |  Used: {}{}".format(WCU_LIMIT, total, over))

def print_custom_rules_detail(before, after):
    print(section("CUSTOM RULES DETAIL  (enabled rules only)"))
    custom_names = [r[1] for r in CUSTOM_RULES] + [
        "keybank-frontend-prod-allowIP", "VPN-AllowIp", "Allow-IPs", "Block-IP", "RateLimit"
    ]
    for name in custom_names:
        b_info = before.get(name, {})
        a_info = after.get(name, {})
        info   = a_info or b_info
        if not info:
            continue
        enabled = info.get("enabled", True)
        if enabled is False or str(enabled).lower() == "false":
            continue

        prio   = info.get("priority", "N/A")
        action = info.get("effective_action", "N/A")
        rate   = info.get("rate_limit", "N/A")

        print(subsection("{} [priority={}  action={}]".format(name, prio, action)))

        # Rate limit
        if rate and rate != "N/A":
            b_rate = b_info.get("rate_limit", "N/A")
            a_rate = a_info.get("rate_limit", "N/A")
            status = "CHANGED" if b_rate != a_rate and b_rate != "N/A" else "NO CHANGE"
            print(make_table(["FIELD", "BEFORE", "AFTER", "STATUS"],
                             [["rate_limit", b_rate, a_rate, status]]))

        # IP set info
        ip_set_name = info.get("ip_set_name", "")
        ip_set_arn  = info.get("ip_set_arn", "")
        if ip_set_name or ip_set_arn:
            print("\n  IP Set Name : {}".format(ip_set_name or "(auto-generated)"))
            if ip_set_arn:
                print("  IP Set ARN  : {}".format(ip_set_arn))

        # Geo countries diff
        b_geo = b_info.get("geo_countries", [])
        a_geo = a_info.get("geo_countries", [])
        if a_geo or b_geo:
            b_set = set(b_geo)
            a_set = set(a_geo)
            added   = sorted(a_set - b_set)
            removed = sorted(b_set - a_set)
            kept    = sorted(b_set & a_set)
            rows = []
            for c in added:   rows.append([c, "---", c,   "ADDED"])
            for c in removed: rows.append([c, c,   "---", "REMOVED"])
            for c in kept:    rows.append([c, c,   c,     "NO CHANGE"])
            rows.sort(key=lambda r: (r[3] != "ADDED", r[3] != "REMOVED", r[0]))
            print("\n  Country Codes ({} total):".format(len(a_geo) or len(b_geo)))
            print(make_table(["COUNTRY CODE", "BEFORE", "AFTER", "STATUS"], rows))

        # IP / byte-string diff
        b_ips = b_info.get("byte_strings", [])
        a_ips = a_info.get("byte_strings", [])
        if a_ips or b_ips:
            b_set = set(b_ips)
            a_set = set(a_ips)
            added   = sorted(a_set - b_set)
            removed = sorted(b_set - a_set)
            kept    = sorted(b_set & a_set)
            rows = []
            for ip in added:   rows.append([ip, "---", ip,  "ADDED"])
            for ip in removed: rows.append([ip, ip,  "---", "REMOVED"])
            for ip in kept:    rows.append([ip, ip,  ip,    "NO CHANGE"])
            rows.sort(key=lambda r: (r[3] != "ADDED", r[3] != "REMOVED", r[0]))
            label = "IPs / CIDRs" if any("/" in str(x) for x in a_ips + b_ips) else "Paths / Strings"
            print("\n  {} ({} total):".format(label, len(a_ips) or len(b_ips)))
            print(make_table([label, "BEFORE", "AFTER", "STATUS"], rows))

def print_subrules_full(before, after):
    print(section("AWS MANAGED RULE SUB-RULES  (enabled rules only)"))
    all_names = sorted(
        set(list(before.keys()) + list(after.keys())),
        key=lambda n: priority_sort_key(n, before, after)
    )
    for name in all_names:
        b = before.get(name, {})
        a = after.get(name, {})
        b_subs = b.get("subrules", {})
        a_subs = a.get("subrules", {})
        if not b_subs and not a_subs:
            continue
        # Skip disabled rules
        b_enabled = b.get("enabled", True)
        a_enabled = a.get("enabled", True)
        if (b_enabled is False or str(b_enabled).lower() == "false") and \
           (a_enabled is False or str(a_enabled).lower() == "false"):
            continue
        prio = a.get("priority", b.get("priority", "?"))
        bot_level = a.get("bot_inspect_level", "N/A")
        title = "{}  [priority={}]".format(name, prio)
        if bot_level and bot_level != "N/A":
            title += "  [inspection={}]".format(bot_level)
        print(subsection(title))
        all_subs = sorted(set(list(b_subs.keys()) + list(a_subs.keys())))
        rows = []
        for sub in all_subs:
            bv = b_subs.get(sub, "---")
            av = a_subs.get(sub, "---")
            if   bv == "---": status = "ADDED"
            elif av == "---": status = "REMOVED"
            elif bv != av:    status = "CHANGED  <<<"
            else:             status = "no change"
            rows.append([sub, bv, av, status])
        print(make_table(["SUB-RULE NAME", "BEFORE ACTION", "AFTER ACTION", "STATUS"], rows))

def print_diff_summary(changes):
    print(section("CHANGE SUMMARY"))
    if not changes:
        print("\n  NO CHANGES DETECTED - Infrastructure is up to date.\n")
        return
    counts = {}
    for c in changes:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    summary_rows = [[st, cnt] for st, cnt in sorted(counts.items())]
    summary_rows.append(["TOTAL", len(changes)])
    print(make_table(["STATUS", "COUNT"], summary_rows))
    print(subsection("All Changes Detail"))
    rows = [
        [c["rule"], c["sub_rule"], c["field"], c["before_val"], c["after_val"], c["status"]]
        for c in changes
    ]
    print(make_table(["RULE", "SUB-RULE", "FIELD", "BEFORE", "AFTER", "STATUS"], rows))

# ─────────────────────────────────────────────────────────────
# MAIN LOGIC
# ─────────────────────────────────────────────────────────────
def load(path):
    with open(path) as f:
        return json.load(f)

def get_best_rules(plan):
    b, a = rules_from_changes(plan)
    if b or a:
        return b, a
    prior_vals   = plan.get("prior_state",    {}).get("values", {})
    planned_vals = plan.get("planned_values", {})
    b = rules_from_state(prior_vals)
    a = rules_from_state(planned_vals)
    if b or a:
        return b, a
    # Terraform may report no changes due to `ignore_changes = [rule]` on the
    # WAF resource.  In that case resource_changes is empty and planned_values
    # has no rule data.  We still want to surface drift between what is live in
    # AWS (prior_state) and what the tfvars declare (variables).  Use the live
    # state as "before" and the variable-derived desired state as "after" so
    # that plan.py can detect sub-rule overrides that differ from the tfvars.
    desired = rules_from_variables(plan)
    live    = rules_from_state(prior_vals)   # may be empty on first deploy
    if live:
        # Merge: for each AWS-managed rule present in live state, copy its
        # subrules into the desired "before" so the diff is accurate.
        return live, desired
    return {}, desired

def _terraform_has_no_rule_changes(plan):
    """Return True when Terraform reported no-op for the WAF ACL (ignore_changes = [rule])."""
    for ch in plan.get("resource_changes", []):
        if ch.get("type") == "aws_wafv2_web_acl":
            return False   # there IS a change tracked by Terraform
    # No WAF ACL entry in resource_changes → Terraform sees no diff
    return bool(plan.get("prior_state"))  # only flag when we have live state

def analyze_single(plan_path):
    plan = load(plan_path)
    meta = extract_metadata(plan)
    print_header(meta, plan_path)

    before_rules, after_rules = get_best_rules(plan)
    if not before_rules and not after_rules:
        print("\n  WARNING: No WAF rules found in this plan file.\n")
        return

    ignore_changes_active = _terraform_has_no_rule_changes(plan)
    if ignore_changes_active:
        print("\n" + "!" * 80)
        print("  WARNING: ignore_changes = [rule] is active on the WAF resource.")
        print("  Terraform will NOT apply rule changes via 'terraform apply'.")
        print("  The diff below compares LIVE AWS state vs. your tfvars (desired config).")
        print("  Any CHANGED rows indicate drift that Terraform is silently ignoring.")
        print("!" * 80)

    mode = "DIFF MODE (live state vs tfvars)" if ignore_changes_active else \
           ("DIFF MODE" if before_rules else "PLANNED STATE (no before state)")
    print("\n  Mode   : {}".format(mode))
    print("  Before : {} rules".format(len(before_rules)))
    print("  After  : {} rules\n".format(len(after_rules)))

    albs    = extract_albs(plan)
    waf_arn = extract_waf_arn(plan)

    print_alb_section(albs, waf_arn)
    print_ip_set_changes(extract_ip_set_changes(plan))
    print_rule_overview(before_rules, after_rules)
    print_wcu_summary(after_rules)
    print_custom_rules_detail(before_rules, after_rules)
    print_subrules_full(before_rules, after_rules)

    changes = diff_rules(before_rules, after_rules)
    if before_rules:
        print_diff_summary(changes)
    else:
        print(section("CHANGE SUMMARY  (new deployment — no prior state)"))
        if not changes:
            print("\n  NO CHANGES DETECTED - Infrastructure is up to date.\n")
        else:
            rows = [
                [c["rule"], c["sub_rule"], c["field"], c["before_val"], c["after_val"], c["status"]]
                for c in changes
            ]
            print("\n  Note: No prior state — all entries below are planned additions.\n")
            print(make_table(["RULE", "SUB-RULE", "FIELD", "BEFORE", "AFTER", "STATUS"], rows))
        print("\n  To diff two states run:")
        print("    python3 plan.py old_plan.json new_plan.json\n")

def analyze_two(before_path, after_path):
    before_plan = load(before_path)
    after_plan  = load(after_path)

    meta = extract_metadata(after_plan)
    print("\n" + "=" * 80)
    print("  TERRAFORM WAF PLAN DIFF")
    print("  BEFORE      : {}".format(os.path.basename(before_path)))
    print("  AFTER       : {}".format(os.path.basename(after_path)))
    print("  Project     : {}".format(meta["project"]))
    print("  Environment : {}".format(meta["environment"]))
    print("  Region      : {}".format(meta["aws_region"]))
    print("=" * 80)

    _, before_rules = get_best_rules(before_plan)
    _, after_rules  = get_best_rules(after_plan)

    combined_albs = {
        "before": extract_albs(before_plan)["after"],
        "after":  extract_albs(after_plan)["after"],
    }
    waf_arn = {
        "before": extract_waf_arn(before_plan)["after"],
        "after":  extract_waf_arn(after_plan)["after"],
    }

    print_alb_section(combined_albs, waf_arn)
    print_ip_set_changes(extract_ip_set_changes(after_plan))
    print_rule_overview(before_rules, after_rules)
    print_wcu_summary(after_rules)
    print_custom_rules_detail(before_rules, after_rules)
    print_subrules_full(before_rules, after_rules)
    changes = diff_rules(before_rules, after_rules)
    print_diff_summary(changes)

# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────
def sanitize_argv(argv):
    cleaned = []
    for arg in argv:
        arg = arg.replace("\u200b", "").strip()
        if arg and arg[0] in ("\u2013", "\u2014", "\x96"):
            arg = "--" + arg.lstrip("\u2013\u2014\x96- ")
        cleaned.append(arg)
    return cleaned

def main():
    sys.argv[1:] = sanitize_argv(sys.argv[1:])
    parser = argparse.ArgumentParser(
        description="Terraform WAF Plan Analyzer — ASCII table output for Jenkins",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 plan.py plan.json
  python3 plan.py old_plan.json new_plan.json
        """
    )
    parser.add_argument("plan_file",       help="Terraform plan JSON")
    parser.add_argument("after_plan_file", nargs="?", default=None,
                        help="(Optional) second plan JSON to compare against")
    args, unknown = parser.parse_known_args()
    if unknown:
        print("\n  ERROR: Unrecognized argument(s): {}".format(" ".join(unknown)))
        sys.exit(1)
    for f in [args.plan_file, args.after_plan_file]:
        if f and not os.path.isfile(f):
            print("\n  ERROR: File not found: {}".format(f))
            sys.exit(1)
    if args.after_plan_file:
        analyze_two(args.plan_file, args.after_plan_file)
    else:
        analyze_single(args.plan_file)

if __name__ == "__main__":
    main()
