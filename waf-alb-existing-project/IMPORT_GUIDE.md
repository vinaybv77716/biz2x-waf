# Existing WAF Import & Management Guide

This guide explains how to use the code in `waf-alb-existing-project` to import an existing AWS WAF Web ACL and manage/modify it in the future.

---

## 📌 Architectural Overview

In a standard deployment (`waf-alb-project`), setting `create_waf = false` prevents Terraform from managing the WAF Web ACL resource; it only reads the ARN and links it to Application Load Balancers (ALBs).

In the **existing WAF management flow** (`waf-alb-existing-project`), we set `create_waf = true` and **import** the existing WAF Web ACL into Terraform. This brings the existing resource under Terraform control, storing its state in the remote S3 bucket, allowing future rule changes or load balancer associations to be applied directly via code.

---

## 🛠️ Step-by-Step Guide

### Step 1: Configure the `.tfvars` File

1. Locate the correct environment variable file under `environments/dev/...` (e.g. `environments/dev/POC/PROD-BSA-Backend.tfvars`).
2. Ensure the state key path has the `waf-alb-existing/` prefix to prevent collision with clean-build states:
   ```hcl
   bucket = "bizx2-rapyder-jenkins-waf-2026"
   key    = "waf-alb-existing/dev/PROD-BSA-Backend.tfstate"
   region = "us-east-1"
   ```
3. Set `create_waf = true` to instruct Terraform to manage the WAF resource:
   ```hcl
   create_waf = true
   ```
4. Match your local rules configuration (like enabling/disabling rules) with the *current live settings* of the WAF to prevent unwanted modifications during the first plan.

---

### Step 2: Initialize Terraform Backend

Initialize the remote backend so that Terraform associates your workspace with the state in the S3 bucket:

```bash
cd waf-alb-existing-project

terraform init \
  -backend-config="bucket=bizx2-rapyder-jenkins-waf-2026" \
  -backend-config="key=waf-alb-existing/dev/PROD-BSA-Backend.tfstate" \
  -backend-config="region=us-east-1" \
  -reconfigure
```

---

### Step 3: Run the Import Command

To import the existing WAF Web ACL into your state file, execute:

```bash
# Syntax: terraform import -var-file="<tfvars>" module.waf.aws_wafv2_web_acl.this[0] "<id>/<name>/<scope>"
# Scope is REGIONAL (for ALBs) or CLOUDFRONT

terraform import \
  -var-file="environments/dev/POC/PROD-BSA-Backend.tfvars" \
  module.waf.aws_wafv2_web_acl.this[0] \
  "eac59bc0-c105-48ef-84c3-8dd8eff7ce0d/PROD-BSA-Backend-web-acl/REGIONAL"
```

> [!NOTE]
> If your WAF uses IP sets that were created manually and you want Terraform to manage those IP sets moving forward, import them too:
> ```bash
> terraform import \
>   -var-file="environments/dev/POC/PROD-BSA-Backend.tfvars" \
>   module.waf.aws_wafv2_ip_set.allowlist[0] \
>   "dfb99752-b04e-44e4-bd3c-177310ec36ef/site-24and7-AllowIP/REGIONAL"
> ```

---

### Step 4: Verify the Imported State

Run a dry run `plan` to verify that Terraform has successfully linked the existing resource and is not planning to recreate or delete it:

```bash
terraform plan -var-file="environments/dev/POC/PROD-BSA-Backend.tfvars"
```

The output should show **no changes** or only minor adjustments (if there were discrepancies between the live settings and your local `.tfvars` file).

---

### Step 5: Make Changes in the Future

Once the resource is imported, you can modify it as follows:
* **Add/Remove IPs**: Edit `environments/dev/ip-set/ip-sets.tfvars` and run the IP Set Manager pipeline.
* **Modify WAF rules**: Edit your project's `.tfvars` file (e.g. change a rule action from `count` to `block`), then run a normal `terraform apply`.

---

## 🚀 Running via Jenkins Pipeline

A dedicated pipeline is provided inside this directory. To set up the Jenkins build:

1. Create a new Pipeline job in Jenkins.
2. Select **Pipeline script from SCM**.
3. Choose the repository and branch.
4. Set the script path to:
   ```text
   waf-alb-existing-project/Jenkinsfile
   ```
5. Run the build with parameters (`ENVIRONMENT`, `ACTION=plan`/`apply`, etc.). The pipeline dynamically initializes and manages the imported state on the S3 bucket using the updated `waf-alb-existing/` state key prefix.
