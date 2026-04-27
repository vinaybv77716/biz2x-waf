# AWS WAF + ALB Terraform Project

A comprehensive Infrastructure as Code (IaC) solution for deploying and managing AWS Web Application Firewall (WAF) rules to protect Application Load Balancers (ALBs) from common web attacks.

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [Project Structure](#project-structure)
- [Technologies Used](#technologies-used)
- [Prerequisites](#prerequisites)
- [Quick Start Guide](#quick-start-guide)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Jenkins Pipeline](#jenkins-pipeline)
- [WAF Rules Reference](#waf-rules-reference)
- [Troubleshooting](#troubleshooting)
- [Security Best Practices](#security-best-practices)
- [Cost Considerations](#cost-considerations)
- [Contributing](#contributing)

---

## 🎯 Project Overview

This project provides a complete Terraform-based solution for securing AWS Application Load Balancers with Web Application Firewall rules. It automates the deployment of AWS Managed Rule Groups, custom IP allow/block lists, rate limiting, and logging configurations.

### What It Does

- **🛡️ Deploys WAF Web ACLs** with multiple AWS managed rule sets
- **🔗 Associates WAF rules** with Application Load Balancers
- **📊 Provides monitoring** through CloudWatch metrics and optional logging
- **🚀 Supports CI/CD** via Jenkins pipelines
- **🔧 Enables customization** through environment-specific configurations

### Simple Analogy

Imagine your ALB is the front door to your house. The WAF is a smart security guard that:
- Checks everyone entering (traffic inspection)
- Blocks suspicious visitors (attackers)
- Lets trusted people in without questions (IP allowlists)
- Monitors and reports unusual activity (logging/metrics)

---

## ✨ Key Features

- **Multi-Environment Support**: Dev, staging, and production configurations
- **Comprehensive Rule Coverage**: 10+ AWS managed rule groups
- **Flexible Actions**: Block, count, or allow per rule group
- **Per-Rule Overrides**: Fine-tune individual sub-rules
- **IP Management**: Allowlist and blocklist IP sets
- **Rate Limiting**: DDoS protection with configurable thresholds
- **Automated CI/CD**: Jenkins pipeline integration
- **Plan Analysis**: Python script for readable Terraform plan output
- **Cost Optimization**: WCU monitoring and rule enablement controls

---

## 📁 Project Structure

```
security/
├── Jenkinsfile                    # Main Jenkins CI/CD pipeline
├── waf-rules.md                   # Detailed WAF rules reference
├── waf-alb-project/              # Main Terraform project
│   ├── main.tf                   # Root module - calls WAF module
│   ├── variables.tf              # Root variable definitions
│   ├── outputs.tf                # Root outputs
│   ├── backend.tf                # S3 remote state configuration
│   ├── jenkinsfile               # Alternative Jenkins pipeline
│   ├── plan.py                   # Terraform plan analyzer script
│   ├── environments/             # Environment-specific configs
│   │   └── dev/
│   │       ├── terraform.tfvars  # Dev environment variables
│   │       └── new.tfvars        # Alternative dev config
│   └── modules/
│       └── waf/                  # WAF Terraform module
│           ├── main.tf           # WAF resource definitions
│           ├── variables.tf      # Module variables
│           └── outputs.tf        # Module outputs
```

### Key Components

| Component | Purpose |
|-----------|---------|
| `Jenkinsfile` | CI/CD pipeline for automated deployment |
| `waf-alb-project/` | Main Terraform codebase |
| `modules/waf/` | Reusable WAF module |
| `environments/` | Environment-specific configurations |
| `plan.py` | Plan analysis and reporting tool |

---

## 🛠️ Technologies Used

- **Infrastructure as Code**: Terraform 1.3+
- **Cloud Platform**: Amazon Web Services (AWS)
  - WAFv2 (Web Application Firewall)
  - ALB (Application Load Balancer)
  - S3 (remote state storage)
  - CloudWatch (monitoring & logging)
- **CI/CD**: Jenkins
- **Scripting**: Python 3 (plan analysis)
- **Version Control**: Git

---

## 📋 Prerequisites

### 1. AWS Account & Permissions

You need an AWS account with these IAM permissions:

```json
{
  "Effect": "Allow",
  "Action": [
    "wafv2:*",
    "elasticloadbalancing:DescribeLoadBalancers",
    "s3:GetObject",
    "s3:PutObject",
    "s3:ListBucket",
    "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

### 2. Required Tools

- **Terraform**: v1.3.0 or higher
- **AWS CLI**: Configured with credentials
- **Python 3**: For plan analysis (optional)
- **Jenkins**: For CI/CD (optional)

### 3. AWS Resources

- **S3 Bucket**: For Terraform state storage
- **Application Load Balancer**: Already created ALB to protect
- **IAM User/Role**: With appropriate permissions

---

## 🚀 Quick Start Guide

### Step 1: Clone and Navigate

```bash
cd waf-alb-project
```

### Step 2: Configure Environment

Edit `environments/dev/terraform.tfvars`:

```hcl
project     = "myproject"
environment = "dev"
aws_region  = "us-east-1"

# S3 backend
bucket = "my-terraform-state-bucket"
key    = "waf-alb/terraform.tfstate"

# WAF settings
create_waf    = true
associate_waf = true
alb_arns      = ["arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890123456"]

# Basic protection
enable_aws_managed_rules = true
aws_managed_rules_action = "count"  # Start with count for testing
```

### Step 3: Initialize Terraform

```bash
terraform init
```

### Step 4: Plan Changes

```bash
terraform plan -var-file="environments/dev/terraform.tfvars"
```

### Step 5: Apply Changes

```bash
terraform apply -var-file="environments/dev/terraform.tfvars"
```

### Step 6: Verify Deployment

```bash
terraform output
aws wafv2 list-web-acls --scope REGIONAL --region us-east-1
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TF_IN_AUTOMATION` | Enables Terraform automation mode | `true` |
| `AWS_REGION` | AWS region for deployment | `us-east-1` |
| `AWS_PROFILE` | AWS CLI profile (if using profiles) | - |

### Key Configuration Files

#### terraform.tfvars Structure

```hcl
# Project metadata
project     = "myapp"
environment = "dev"
aws_region  = "us-east-1"

# Backend configuration
bucket = "my-state-bucket"
key    = "waf-alb/dev/terraform.tfstate"

# WAF lifecycle
create_waf           = true
existing_web_acl_arn = ""   # set when create_waf = false

# ALB association
associate_waf = true
alb_arns      = ["arn:aws:elasticloadbalancing:us-east-1:123456789:loadbalancer/app/my-alb/abc123"]

# Default action for requests that match no rule
default_action = "allow"   # allow | block

# IP lists
allowlist_ips = ["203.0.113.0/24"]   # bypasses all WAF rules
blocklist_ips = ["192.168.1.100/32"] # always blocked

# Logging
enable_waf_logging  = false
log_destination_arn = ""   # CloudWatch Log Group or S3 ARN
```

### Rule Action Types

| Action | Behavior | Use Case |
|--------|----------|----------|
| `block` | Blocks matching requests | Production, trusted rules |
| `count` | Logs but allows requests | Testing, monitoring |
| `allow` | Disables rule entirely | Rule not needed |

---

## 🚀 Deployment

### Via Jenkins (Recommended)

1. Open Jenkins → Select `simple-jenkinsfile` pipeline
2. Click **"Build with Parameters"**
3. Configure:
   - `ENVIRONMENT`: dev/staging/prod
   - `ACTION`: plan/apply/destroy
   - `TF_STATE_BUCKET`: Your S3 bucket
4. Review plan output
5. Approve and apply


---

## Creating a New WAF for a New Project

To deploy a separate WAF Web ACL for a new project, you only need to create a new `.tfvars` file — no Terraform code changes required.

### Step 1 — Create the tfvars file

Copy an existing file as a starting point:

```
waf-alb-project/environments/dev/myproject.tfvars
```

Update the identity fields at the top:

```hcl
project     = "myproject"       # used in resource names: myproject-dev-web-acl
environment = "dev"
aws_region  = "us-east-1"

bucket = "bizx2-rapyder-jenkins-waf-2026"
key    = "waf-alb/dev/myproject.tfstate"   # unique state key per project
region = "us-east-1"

alb_arns = ["arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc123"]
```

Enable or disable rules as needed — set `enable_* = false` for anything not required.

### Step 2 — Run via Jenkins

1. Open Jenkins and select the WAF pipeline
2. Click **Build with Parameters**
3. Set:
   - `ACTION` = `plan`
   - `TERRAFORM_VARIABLE_FILE` = `myproject.tfvars`
4. Review the plan output
5. Re-run with `ACTION` = `apply` to deploy

The pipeline handles `terraform init` with the correct backend config automatically based on the `key` value in your tfvars.

### Step 3 — Verify

After apply, confirm in AWS Console:
**WAF & Shield → Web ACLs → US East (N. Virginia)** — you should see `myproject-dev-web-acl`.

### Rules to enable per use case

| Use case | Recommended rules |
|----------|------------------|
| Standard web app | Core, SQLi, Known Bad Inputs, IP Reputation, RateLimit |
| PHP / WordPress | + PHP Protection, WordPress Protection |
| Linux backend | + Linux Protection |
| Geo-restricted app | + AllowCountryUS or BlockSelectedCountries |
| High-security | All of the above in `block` mode |

---

The project includes a comprehensive Jenkins pipeline with these stages:

```
Validate Parameters → Terraform Init → Terraform Plan → Review Plan → Approval → Terraform Apply → Outputs
```

- Approval gate is skipped when `AUTO_APPROVE = true` or `ACTION = plan`
- Plan output is archived as a Jenkins artifact

### Pipeline Parameters

| Parameter | Options | Description |
|-----------|---------|-------------|
| `ENVIRONMENT` | dev/staging/prod | Target environment |
| `ACTION` | plan/apply/destroy | Operation to perform |
| `TF_STATE_BUCKET` | string | S3 bucket for state |
| `AWS_REGION` | string | AWS region |
| `TERRAFORM_VARIABLE_FILE` | string | .tfvars filename |

### Actions

| Action | What it does |
|--------|-------------|
| `plan` | Shows what Terraform will change — no changes applied |
| `apply` | Applies the plan — creates or updates WAF |
| `destroy` | Destroys all WAF resources for the environment |

### Terraform Backend

State is stored per environment in S3:

```
Bucket: bizx2-rapyder-jenkins-waf-2026
Key:    waf-alb/{environment}/terraform.tfstate
Region: us-east-1
```

The pipeline handles `-backend-config` automatically based on the `ENVIRONMENT` parameter.

### Plan Analysis

The pipeline uses `plan.py` to generate readable plan summaries:

```bash
python3 plan.py plan.json
```

This produces ASCII tables showing:
- ALB associations
- WAF rule changes
- Sub-rule modifications
- Change summaries

---

## 📚 WAF Rules Reference

For full WAF rule and sub-rule definitions, see [waf-rules.md](./waf-rules.md).

### Rule Groups Summary

| # | Rule Group | Variable Prefix | WCU | Priority |
|---|-----------|----------------|-----|----------|
| 1 | Core Rule Set (OWASP Top 10) | `aws_managed_rules` | 700 | 10 |
| 2 | Known Bad Inputs (Log4Shell, CVEs) | `known_bad_inputs` | 200 | 15 |
| 3 | SQL Injection | `sql_injection_protection` | 200 | 20 |
| 4 | IP Reputation List | `ip_reputation` | 25 | 25 |
| 5 | Anonymous IP (VPN/Tor/Proxy) | `anonymous_ip` | 50 | 35 |
| 6 | Linux Protection | `linux_protection` | 200 | 50 |
| 7 | Unix Protection | `unix_protection` | 100 | 55 |
| 8 | Windows Protection | `windows_protection` | 200 | 60 |
| 9 | PHP Protection | `php_protection` | 100 | 65 |
| 10 | WordPress Protection | `wordpress_protection` | 100 | 70 |
| — | Rate Limiting | `rate_limiting` | 2 | 40 |

### Rule Priorities

Rules are evaluated in priority order (lower numbers first):
- 5: IP Allowlist
- 10: Core Rules
- 15: Known Bad Inputs
- 20: SQL Injection
- 25: IP Reputation
- 30: IP Blocklist
- 40: Rate Limiting

### WCU Budget

**Hard limit: 1,500 WCU per Web ACL.**

Current dev configuration: ~1,327 WCU used.

### Dev Environment (Current)

| Rule | Enabled | Action | WCU |
|------|---------|--------|-----|
| Core Rule Set | yes | count | 700 |
| Known Bad Inputs | yes | count | 200 |
| SQL Injection | yes | count | 200 |
| IP Reputation | yes | count | 25 |
| Linux Protection | yes | count | 200 |
| Rate Limiting | yes | count | 2 |
| All others | no | — | 0 |
| **Total** | | | **1,327** |

### Per-Sub-Rule Overrides

Fine-tune individual rules regardless of the group-level action:

```hcl
aws_managed_rules_action = "count"

aws_managed_rules_rule_action_overrides = [
  { name = "NoUserAgent_HEADER", action = "block" },
  { name = "CrossSiteScripting_BODY", action = "allow" },
]
```

See `waf-rules.md` for the full list of sub-rules per group.

### Environment Progression

```
dev (count) → staging (block critical rules) → prod (all block)
```

1. Deploy dev — all rules in `count` mode
2. Monitor CloudWatch for 24–48 hours, identify false positives
3. Add sub-rule overrides for any false positives
4. Promote to staging — set `block` for Core, SQLi, Known Bad Inputs, IP Reputation
5. Validate with staging traffic
6. Deploy prod — all rules in `block` mode

---

## 🔧 Troubleshooting

### Common Issues

#### "Access Denied" Errors
- Verify AWS credentials: `aws sts get-caller-identity`
- Check IAM permissions
- Confirm S3 bucket access

#### WCU Limit Exceeded
Error: `web_acl_capacity` over 1,500. Disable unused rules:
```hcl
enable_windows_protection   = false   # saves 200 WCU
enable_linux_protection     = false   # saves 200 WCU
enable_unix_protection      = false   # saves 100 WCU
enable_php_protection       = false   # saves 100 WCU
enable_wordpress_protection = false   # saves 100 WCU
enable_anonymous_ip         = false   # saves 50 WCU
```

#### WAF Not Protecting ALB
- Verify `associate_waf = true`
- Check ALB ARN correctness
- Ensure same AWS region
- Wait 5-10 minutes post-deployment
- Make sure you are in the correct region in the AWS Console: **WAF & Shield → Web ACLs → US East (N. Virginia)**

#### Terraform State Issues
- State locked: `terraform force-unlock LOCK_ID`
- Stale state (WAF deleted manually in AWS): run `ACTION = sync-state` in Jenkins, then apply again, or via terminal:

```bash
terraform state rm 'module.waf.aws_wafv2_web_acl.this[0]'
terraform plan -var-file="environments/dev/terraform.tfvars" -out=tfplan.binary
terraform apply -auto-approve tfplan.binary
```

#### S3 Backend 403 Forbidden
The state key path is wrong. Re-init with the correct key:
```bash
terraform init \
  -backend-config="bucket=bizx2-rapyder-jenkins-waf-2026" \
  -backend-config="key=waf-alb/dev/terraform.tfstate" \
  -backend-config="region=us-east-1" \
  -reconfigure
```

#### Tag Value Error
AWS WAF does not allow commas in tag values. Use `+` as separator:
```hcl
# Wrong
Dependencies = "alb,s3,cloudwatch"

# Correct
Dependencies = "alb+s3+cloudwatch"
```

#### HCL Syntax Error — Missing Attribute Separator
Object attributes in `.tfvars` must be comma-separated:
```hcl
# Wrong
{ name = "SomeRule_BODY" action = "allow" }

# Correct
{ name = "SomeRule_BODY", action = "allow" }
```

### Debugging Commands

```bash
# Check WAF status
aws wafv2 list-web-acls --scope REGIONAL --region us-east-1

# View WAF details
aws wafv2 get-web-acl \
  --scope REGIONAL \
  --name myapp-dev-web-acl \
  --id <web-acl-id> \
  --region us-east-1

# Check ALB associations
aws wafv2 list-resources-for-web-acl \
  --web-acl-arn <web-acl-arn> \
  --region us-east-1

# View sampled requests (last 1 hour)
aws wafv2 get-sampled-requests \
  --web-acl-arn <web-acl-arn> \
  --rule-metric-name myapp-dev-sqli-rules \
  --scope REGIONAL \
  --time-window StartTime=$(date -u -d '1 hour ago' +%s),EndTime=$(date -u +%s) \
  --max-items 100 \
  --region us-east-1
```


## 🔒 Security Best Practices

1. **Start with Monitoring**: Use "count" action initially
2. **Test Thoroughly**: Validate application behavior
3. **Enable Logging**: Monitor for false positives
4. **Use Allowlists**: Whitelist known good IPs
5. **Regular Reviews**: Audit rules and logs monthly
6. **Least Privilege**: Grant minimal required permissions
7. **Backup State**: Enable S3 versioning
8. **Monitor Costs**: Set WCU usage alerts

### Production Checklist

- [ ] All rules in "block" mode
- [ ] Logging enabled
- [ ] CloudWatch alarms configured
- [ ] IP allowlists populated
- [ ] Rate limiting tuned
- [ ] Manual testing completed
- [ ] Rollback plan documented

---

*This project follows Infrastructure as Code best practices and AWS security guidelines. Always test changes in development before production deployment.*
