# WAF Multi-Account Management

Manage AWS WAF Web ACLs across multiple accounts and applications.

## Structure

```
waf-multi-account/
├── jenkinsfile                    # Single pipeline for all accounts
├── providers.tf                   # Provider configurations
├── tf_plan_analyzer.py            # Terraform plan analyzer (formatted table output)
├── Readme.md                      # Project documentation
└── accounts/
    ├── <account-name>/
    │   └── <webacl-name>/
    │       ├── import.tf          # Import blocks for existing resources
    │       ├── main.tf            # Calls WAF module
    │       ├── variables.tf       # Variables definition
    │       └── prod.tfvars        # Web ACL configuration (rules, priorities)
```

## Adding a New Web ACL

1. Create folder: `accounts/<account>/<webacl>/`
2. Add `import.tf` with existing resource IDs
3. Add `variables.tf` (copy from existing folder)
4. Add `main.tf` (copy from existing folder)
5. Configure `prod.tfvars` with Web ACL rules

## Jenkins Pipeline

**Parameters**:
- `ACCOUNT_FOLDER`: Account folder name (e.g., `devops/biz2x-dev`)
- `ACTION`: Terraform action (`plan`, `apply`, `destroy`)

**Example**:
- Folder: `accounts/devops/biz2x-dev/`
- Parameter: `ACCOUNT_FOLDER=devops/biz2x-dev`
- Action: `apply`

## Provider Configuration

Edit `providers.tf` to add account IDs and role ARNs:

```hcl
provider "aws" {
  alias  = "<account-name>"
  region = "us-east-1"

  assume_role {
    role_arn = "arn:aws:iam::<account-id>:role/TerraformRole"
  }
}
```

## State Management

Terraform state is stored locally by default. Configure remote state in `main.tf`:

```hcl
terraform {
  backend "s3" {
    bucket = "waf-multi-account-state"
    key    = "<account>/<webacl>/terraform.tfstate"
    region = "us-east-1"
  }
}
```

## Terraform Plan Analyzer (`tf_plan_analyzer.py`)

A Python script that parses Terraform plan output and displays changes in a clean, formatted table. Automatically runs in Jenkins after every `plan` and `apply` to provide visibility into infrastructure changes.

### Features:
- 📊 Summary table showing adds, modifications, and destructions
- 🔍 Detailed table of all resources being changed
- ✅ Confirms successful state alignment after apply
- 📦 Works with all WAF account configurations

### Manual Usage:
```bash
# Install dependencies
pip install tabulate

# Run against any WAF directory
python tf_plan_analyzer.py accounts/SBA-Client1/NonPROD-BFP-Tenancy
python tf_plan_analyzer.py accounts/SBA-Client1/SBA-client-waf-np
python tf_plan_analyzer.py accounts/SBA-Client1/dummy
python tf_plan_analyzer.py accounts/SBA-Client1/Biz2credit-Stage-cpaBussinessloans-WAF-eu-north-1
```

### Jenkins Integration:
The script automatically runs in the pipeline after every Terraform plan/apply, displaying the formatted table directly in Jenkins build logs. No additional configuration needed - it uses the same `ACCOUNT_FOLDER` and `WAF_NAME` parameters as the rest of the pipeline.

### Example Output:
```
+------------------+-------+
| ➕ To Add         | 0     |
| ✏️  To Modify      | 2     |
| 🗑️  To Destroy     | 0     |
| ✅ No Changes     | 15    |
+------------------+-------+
```

## Adding/Updating WAF Rules

### How to Add or Modify Rules:
1. **Locate the environment's `prod.tfvars`** in its account directory:
   ```
   accounts/<account-name>/<webacl-name>/prod.tfvars
   ```

2. **Add your new rule to the `rules` array** (maintain correct priority order - lower numbers execute first):
   ```hcl
   # Example: Add a new geo-restriction rule
   {
     name     = "Block-New-Region"
     priority = 4  # Must be unique and correctly ordered
     action   = "block"
     statement = {
       geo_match_statement = {
         country_codes = ["RU", "CN"]
       }
     }
     visibility_config = {
       sampled_requests_enabled   = true
       cloudwatch_metrics_enabled = true
       metric_name                = "Block-New-Region"
     }
   },
   ```

3. **Supported rule types** (already implemented in `main.tf`):
   - `ip_set_reference_statement`: Allow/block specific IP sets
   - `geo_match_statement`: Geo-location restrictions
   - `managed_rule_group_statement`: AWS managed rules (Bot Control, Anti-DDoS, SQLi, etc.)
   - `rule_group_reference_statement`: AWS Shield mitigation rule groups
   - `rate_based_statement`: Rate-limiting rules
   - `or_statement`: Combine multiple conditions for complex logic

### Verify Changes Before Applying:
After updating `prod.tfvars`, always run the plan analyzer to verify your changes:
```bash
python tf_plan_analyzer.py accounts/<your-waf-directory>
```
This will show you exactly what resources are being modified and confirm your rule additions are correctly configured.

### Run the Jenkins Pipeline:
Trigger a Jenkins build with:
- `ACCOUNT_FOLDER`: Your account folder (e.g., `SBA-Client1`)
- `WAF_NAME`: Your WAF directory name (e.g., `NonPROD-BFP-Tenancy`)
- `ACTION`: First run `plan` to verify, then `apply` to deploy

### Example Workflow for Rule Updates:
```bash
# 1. Edit prod.tfvars and add your new rule
code accounts/SBA-Client1/NonPROD-BFP-Tenancy/prod.tfvars

# 2. Verify changes locally
python tf_plan_analyzer.py accounts/SBA-Client1/NonPROD-BFP-Tenancy

# 3. Run in Jenkins to deploy (pipeline will auto-run analyzer again)
# Trigger Jenkins with ACTION=plan first, then ACTION=apply
```

This ensures all rule changes are validated before they reach production!
  ```
