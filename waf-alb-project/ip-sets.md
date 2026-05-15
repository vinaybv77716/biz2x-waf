# IP Sets Management

## Overview

The WAF deployments in this project use shared IP sets that already exist in AWS WAFv2. Since these IP sets are pre-created and shared across multiple WAF Web ACLs, a dedicated Jenkins job is used to manage their contents — adding, removing, or updating IP addresses without touching any WAF configuration.

All code for this job lives in `environments/dev/ip-set/`.

---

## Shared IP Sets

The following IP sets are used across WAF deployments in this account (`892669526097`, `us-east-1`):

| IP Set Name | Type | Used By | IPs |
|---|---|---|---|
| `site-24and7-AllowIP` | VPN / Office Allowlist | All BSA WAFs | 27 |
| `keybank-frontend-PROD-AllowIP` | Frontend Allowlist | PROD-BSA-Frontend | 6 |
| `keybank-Backend-Prod-AllowIP` | Backend Allowlist | PROD-BSA-Backend | 26 |
| `Keybank-Prchestrator-Prod-BlockIP` | Blocklist | Orchestrator WAF | 5 |

These IP sets are referenced in WAF tfvars files using their ARNs:

```hcl
# Reference an existing IP set by ARN — no new IP set is created
vpn_allowlist_ips         = []
vpn_allowlist_ip_set_name = "site-24and7-AllowIP"
vpn_allowlist_ip_set_arn  = "arn:aws:wafv2:us-east-1:892669526097:regional/ipset/site-24and7-AllowIP/16c758f2-5b6d-4082-80fd-cd2d3afa6c7e"
vpn_allowlist_priority    = 0
```

---

## IP Set Manager Jenkins Job

### Purpose

To add, remove, or update IPs in the shared IP sets, use the **ip-sets** Jenkins job. This job reads the desired IP list from `ip-sets.tfvars`, compares it against the live state in AWS, and either shows a diff (plan) or applies the changes (apply).

### Location

```
environments/dev/ip-set/
├── Jenkinsfile          # Jenkins pipeline definition
├── ip-sets.tfvars       # Desired IP list for each IP set
└── ip_set_manager.py    # Diff and update logic
```

### How It Works

1. `ip-sets.tfvars` defines the **desired** full IP list for each managed IP set
2. The job fetches the **live** IP list from AWS for each set
3. It computes the diff — which IPs will be added, which will be removed
4. In **plan** mode: prints a formatted diff table, no changes made
5. In **apply** mode: shows the diff, waits for approval, then updates AWS

### Jenkinsfile Summary

The pipeline has three stages:

| Stage | Description |
|---|---|
| **Validate** | Checks the `ip-sets.tfvars` file exists and prints job parameters |
| **Plan — IP Set Diff** | Runs `ip_set_manager.py plan` — fetches live IPs, computes diff, prints table |
| **Approval** | Pauses for human approval (only when `ACTION = apply` and changes exist) |
| **Apply — Update IP Sets** | Runs `ip_set_manager.py apply` — updates each IP set in AWS |

### Parameters

| Parameter | Options | Description |
|---|---|---|
| `ACTION` | `plan` / `apply` | `plan` shows diff only; `apply` updates AWS after approval |
| `IP_SETS_FILE` | path string | Path to `ip-sets.tfvars` (default: `environments/dev/ip-set/ip-sets.tfvars`) |
| `AWS_REGION` | string | AWS region (default: `us-east-1`) |

### Plan Output Example

```
================================================================================
  IP SET MANAGER — PLAN (dry run)
  Region : us-east-1
  File   : environments/dev/ip-set/ip-sets.tfvars
  Sets   : 2
================================================================================

  Checking: site-24and7-AllowIP
  ARN     : arn:aws:wafv2:us-east-1:892669526097:regional/ipset/...
  Status  : CHANGES DETECTED

+------------------+------------------+------------------+-----------+
| IP / CIDR        | LIVE (current)   | DESIRED          | ACTION    |
+------------------+------------------+------------------+-----------+
| 44.44.44.44/32   | ---              | 44.44.44.44/32   | ADD       |
| 99.99.99.99/32   | 99.99.99.99/32   | ---              | REMOVE    |
| 45.33.65.221/32  | 45.33.65.221/32  | 45.33.65.221/32  | no change |
+------------------+------------------+------------------+-----------+

  [PLAN] Would add 1, remove 1 IPs
```

---

## How to Add or Remove an IP

### Step 1 — Edit `ip-sets.tfvars`

Open `environments/dev/ip-set/ip-sets.tfvars` and update the `ips` list for the relevant IP set:

```hcl
{
  name = "site-24and7-AllowIP"
  arn  = "arn:aws:wafv2:us-east-1:892669526097:regional/ipset/site-24and7-AllowIP/16c758f2-5b6d-4082-80fd-cd2d3afa6c7e"
  ips  = [
    "45.33.65.221/32",
    "139.64.132.20/32",
    # ... existing IPs ...
    "55.55.55.55/32",   # <-- add new IP here
  ]
},
```

To remove an IP, simply delete its line from the list.

### Step 2 — Run the Jenkins Job

1. Open Jenkins → **ip-sets** job
2. Click **Build with Parameters**
3. Set `ACTION = plan`
4. Review the diff table in the console output
5. Re-run with `ACTION = apply` to apply the changes

### Step 3 — Verify

After apply, the job prints a summary confirming how many IPs were added and removed per set.

---

## Notes

- The `ips` list in `ip-sets.tfvars` is the **complete desired state** — any IP not in the list will be removed from AWS
- IP lookup is done by **name**, not by ARN ID — so stale ARNs in the file are handled gracefully (the job will print the current live ARN if it differs)
- Changes to IP sets take effect immediately in AWS — no WAF redeployment needed
- This job does **not** modify any WAF Web ACL rules or associations
