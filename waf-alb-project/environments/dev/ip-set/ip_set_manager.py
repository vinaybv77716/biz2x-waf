#!/usr/bin/env python3
"""
ip_set_manager.py — AWS WAFv2 IP Set Manager
=============================================
Reads ip-sets.tfvars, compares desired IPs against live AWS state,
and either shows a diff (plan) or applies the changes (apply).

Usage:
    python3 ip_set_manager.py plan   ip-sets.tfvars
    python3 ip_set_manager.py apply  ip-sets.tfvars
"""

import json
import re
import subprocess
import sys


# ---------------------------------------------------------------------------
# Parse ip-sets.tfvars  (HCL-like, not real HCL — we use regex)
# ---------------------------------------------------------------------------

def parse_tfvars(path):
    """
    Parse ip-sets.tfvars into a list of dicts:
      [{ name, arn, ips: [...] }, ...]
    """
    with open(path) as f:
        content = f.read()

    # Remove comment lines
    content = re.sub(r'#[^\n]*', '', content)

    # Extract region
    region_match = re.search(r'region\s*=\s*"([^"]+)"', content)
    region = region_match.group(1) if region_match else "us-east-1"

    # Extract each ip_set block: { name = "..." arn = "..." ips = [...] }
    ip_sets = []
    # Find all { ... } blocks inside ip_sets = [ ... ]
    outer = re.search(r'ip_sets\s*=\s*\[(.*)\]', content, re.DOTALL)
    if not outer:
        print("ERROR: Could not find ip_sets = [...] in tfvars", file=sys.stderr)
        sys.exit(1)

    blocks_text = outer.group(1)

    # Split into individual { } blocks
    depth = 0
    current = []
    for ch in blocks_text:
        if ch == '{':
            depth += 1
        if depth > 0:
            current.append(ch)
        if ch == '}':
            depth -= 1
            if depth == 0 and current:
                block = ''.join(current)
                current = []
                # Parse name
                name_m = re.search(r'name\s*=\s*"([^"]+)"', block)
                arn_m  = re.search(r'arn\s*=\s*"([^"]+)"',  block)
                ips_m  = re.search(r'ips\s*=\s*\[(.*?)\]',  block, re.DOTALL)
                if name_m and arn_m and ips_m:
                    ips = re.findall(r'"([^"]+)"', ips_m.group(1))
                    ip_sets.append({
                        "name": name_m.group(1),
                        "arn":  arn_m.group(1),
                        "ips":  sorted(ips),
                    })

    return region, ip_sets


# ---------------------------------------------------------------------------
# AWS CLI helpers
# ---------------------------------------------------------------------------

def aws(*args):
    cmd = ["aws"] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR: {' '.join(cmd)}\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)


def get_live_ips(name, region):
    """Fetch current IPs from AWS for a given IP set name (lookup by name)."""
    # List all IP sets and find by name
    result = aws("wafv2", "list-ip-sets",
                 "--scope", "REGIONAL",
                 "--region", region)

    ip_set_info = next(
        (s for s in result.get("IPSets", []) if s["Name"] == name),
        None
    )

    if not ip_set_info:
        raise ValueError(f"IP set '{name}' not found in region {region}")

    ip_set_id = ip_set_info["Id"]

    detail = aws("wafv2", "get-ip-set",
                 "--scope", "REGIONAL",
                 "--region", region,
                 "--name", name,
                 "--id", ip_set_id)

    addresses  = detail.get("IPSet", {}).get("Addresses", [])
    lock_token = detail.get("LockToken", "")
    live_arn   = ip_set_info["ARN"]
    return sorted(addresses), lock_token, ip_set_id, live_arn


def update_ip_set(name, ip_set_id, region, desired_ips, lock_token):
    """Update the IP set with the desired list."""
    cmd = [
        "aws", "wafv2", "update-ip-set",
        "--scope", "REGIONAL",
        "--region", region,
        "--name", name,
        "--id", ip_set_id,
        "--lock-token", lock_token,
        "--addresses"
    ] + desired_ips

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR updating {name}:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# Table printer
# ---------------------------------------------------------------------------

def print_table(headers, rows):
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    def fmt_row(r):
        return "|" + "|".join(f" {str(c):<{w}} " for c, w in zip(r, widths)) + "|"

    print(sep)
    print(fmt_row(headers))
    print(sep)
    for row in rows:
        print(fmt_row(row))
    print(sep)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 3:
        print("Usage: ip_set_manager.py <plan|apply> <path/to/ip-sets.tfvars>")
        sys.exit(1)

    action   = sys.argv[1].lower()
    tfvars   = sys.argv[2]

    if action not in ("plan", "apply"):
        print(f"ERROR: action must be 'plan' or 'apply', got '{action}'")
        sys.exit(1)

    region, ip_sets = parse_tfvars(tfvars)

    print(f"\n{'='*80}")
    print(f"  IP SET MANAGER — {'PLAN (dry run)' if action == 'plan' else 'APPLY (updating AWS)'}")
    print(f"  Region : {region}")
    print(f"  File   : {tfvars}")
    print(f"  Sets   : {len(ip_sets)}")
    print(f"{'='*80}\n")

    total_adds = 0
    total_removes = 0
    any_changes = False

    for entry in ip_sets:
        name    = entry["name"]
        arn     = entry["arn"]
        desired = set(entry["ips"])

        print(f"  Checking: {name}")
        print(f"  ARN     : {arn}")

        try:
            live_list, lock_token, ip_set_id, live_arn = get_live_ips(name, region)
        except ValueError as e:
            print(f"  ERROR: {e}\n")
            continue
        except SystemExit:
            print(f"  ERROR: Could not fetch live state for {name}\n")
            continue

        # Show live ARN if it differs from tfvars (stale ARN warning)
        if live_arn != arn:
            print(f"  NOTE: ARN in tfvars is stale. Live ARN: {live_arn}")

        live = set(live_list)

        to_add    = sorted(desired - live)
        to_remove = sorted(live - desired)
        unchanged = sorted(desired & live)

        total_adds    += len(to_add)
        total_removes += len(to_remove)

        if not to_add and not to_remove:
            print(f"  Status  : NO CHANGES ({len(live)} IPs)\n")
            continue

        any_changes = True
        print(f"  Status  : CHANGES DETECTED")

        # Build diff table
        rows = []
        for ip in to_add:
            rows.append([ip, "---",  ip,  "ADD"])
        for ip in to_remove:
            rows.append([ip, ip,  "---", "REMOVE"])
        for ip in unchanged:
            rows.append([ip, ip,   ip,  "no change"])

        rows.sort(key=lambda r: (r[3] != "ADD", r[3] != "REMOVE", r[0]))

        print()
        print_table(["IP / CIDR", "LIVE (current)", "DESIRED", "ACTION"], rows)
        print()

        if action == "apply":
            print(f"  Applying update to {name} ...")
            update_ip_set(name, ip_set_id, region, sorted(desired), lock_token)
            print(f"  SUCCESS: {name} updated (+{len(to_add)} / -{len(to_remove)})\n")
        else:
            print(f"  [PLAN] Would add {len(to_add)}, remove {len(to_remove)} IPs\n")

    # Summary
    print(f"{'='*80}")
    print(f"  SUMMARY")
    print(f"{'='*80}")
    if not any_changes:
        print("  All IP sets are up to date. No changes needed.\n")
    else:
        print_table(
            ["METRIC", "COUNT"],
            [
                ["Total IPs to ADD",    total_adds],
                ["Total IPs to REMOVE", total_removes],
                ["Status", "APPLIED" if action == "apply" else "PLAN ONLY — not applied"],
            ]
        )
        print()


if __name__ == "__main__":
    main()
