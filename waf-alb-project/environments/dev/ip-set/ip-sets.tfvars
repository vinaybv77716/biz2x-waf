# =============================================================================
# ip-sets.tfvars — AWS CLI-managed IP Set definitions
# =============================================================================
# This file is used by the ip-set-manager Jenkinsfile (NOT by Terraform).
# The Jenkinsfile reads this file, compares against live AWS state,
# and uses aws wafv2 update-ip-set to add/remove IPs.
#
# Format per IP set:
#   name = "<IP set name in AWS>"
#   arn  = "<full ARN of the IP set>"
#   ips  = ["cidr1", "cidr2", ...]   # DESIRED full list
#
# The Jenkinsfile will:
#   PLAN  — show a diff table (what will be ADDED / REMOVED)
#   APPLY — call aws wafv2 update-ip-set with the desired list
# =============================================================================

region = "us-east-1"

ip_sets = [

  # =============================================================================
  # IP Set 1 — site-24and7-AllowIP
  # =============================================================================
  {
    name = "site-24and7-AllowIP"
    arn  = "arn:aws:wafv2:us-east-1:892669526097:regional/ipset/site-24and7-AllowIP/eac59bc0-c105-48ef-84c3-8dd8eff7ce0d"
    ips  = [
      "45.33.65.221/32",
      "139.64.132.20/32",
      "123.63.212.74/32",
      "149.28.63.4/32",
      "156.77.0.0/16",
      "8.12.17.175/32",
      "50.116.57.114/32",
      "93.177.110.3/32",
      "111.93.242.74/32",
      "182.74.72.50/32",
      "162.210.173.104/32",
      "184.74.226.42/32",
      "162.210.173.201/32",
      "125.20.89.56/29",
      "23.92.18.184/32",
      "66.135.10.99/32",
      "198.74.62.39/32",
      "38.122.225.178/32",
      "45.56.110.193/32",
      "208.249.47.2/32",
      "45.76.0.57/32",
      "198.74.56.175/32",
      "125.20.89.58/32",
      "104.192.216.226/32",
      "172.104.208.130/32",
      "22.22.22.22/32"
    ]
  },

  # =============================================================================
  # IP Set 2 — keybank-frontend-PROD-AllowIP
  # =============================================================================
  {
    name = "keybank-frontend-PROD-AllowIP"
    arn  = "arn:aws:wafv2:us-east-1:892669526097:regional/ipset/keybank-frontend-PROD-AllowIP/921df34f-c70c-4e0f-81d1-fcc8c24b5e94"
    ips  = [
      "125.20.89.58/32",
      "111.93.242.74/32",
      "182.74.72.50/32",
      "123.63.212.74/32",
      "125.20.89.56/29",
      "144.121.234.242/32",
      "11.11.11.11/32"

    ]
  },

]
