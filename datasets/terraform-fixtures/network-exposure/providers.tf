terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.80.0"
    }
  }
}

# Offline planning: credentials are mock values supplied by the Aegis runner
# through environment variables. No AWS API is called.
provider "aws" {
  region                      = "ap-south-1"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true

  default_tags {
    tags = {
      owner       = "payments-team"
      environment = "production"
      cost_center = "payments"
    }
  }
}
