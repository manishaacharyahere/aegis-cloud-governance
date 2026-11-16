# DELIBERATELY INSECURE TEST FIXTURE - do not apply.
# No provider default_tags, so ownership and cost tags are missing.

resource "aws_s3_bucket" "trail_logs" {
  bucket = "aegis-fixture-trail-logs"
  tags = {
    environment = "staging"
  }
}

resource "aws_s3_bucket_public_access_block" "trail_logs" {
  bucket                  = aws_s3_bucket.trail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_cloudtrail" "disabled" {
  name                       = "disabled"
  s3_bucket_name             = aws_s3_bucket.trail_logs.id
  enable_logging             = false
  enable_log_file_validation = false
}
