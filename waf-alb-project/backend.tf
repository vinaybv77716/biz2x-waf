# =============================================================================
# REMOTE STATE BACKEND
# Update bucket/key/region before use
# =============================================================================

terraform {
  backend "s3" {
    bucket         = "bizx2-rapyder-jenkins-waf-2026"
    key            = "wafalb/"
    region         = "us-east-1"
  }
}
