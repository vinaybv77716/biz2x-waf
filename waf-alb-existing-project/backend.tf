# =============================================================================
# REMOTE STATE BACKEND
# Update bucket/key/region before use
# =============================================================================

terraform {
  backend "s3" {
    # bucket, key, and region are injected at runtime by Jenkins via -backend-config
    # key pattern: waf-alb-existing/<env>/<tfvars-file>.tfstate
    bucket = "vina-terraform-waf-bucket"
    key    = "waf-alb-existing/placeholder.tfstate"
    region = "us-east-1"
  }
}
