# Secure baseline: Aegis policies must report no findings here.

resource "aws_kms_key" "data" {
  description             = "Customer data encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_s3_bucket" "customer_data" {
  bucket = "aegis-fixture-secure-customer-data"
}

resource "aws_s3_bucket_public_access_block" "customer_data" {
  bucket                  = aws_s3_bucket.customer_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
  }
}

resource "aws_s3_bucket_versioning" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_security_group" "app" {
  name        = "app"
  description = "Application tier"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from inside the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_iam_policy" "app_read" {
  name = "app-read-customer-data"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["arn:aws:s3:::aegis-fixture-secure-customer-data/*"]
    }]
  })
}

resource "aws_db_instance" "orders" {
  identifier                  = "orders"
  engine                      = "postgres"
  instance_class              = "db.t3.medium"
  allocated_storage           = 20
  username                    = "orders_admin"
  manage_master_user_password = true
  storage_encrypted           = true
  publicly_accessible         = false
  skip_final_snapshot         = false
  final_snapshot_identifier   = "orders-final"
}

resource "aws_cloudtrail" "main" {
  name                       = "main"
  s3_bucket_name             = aws_s3_bucket.customer_data.id
  is_multi_region_trail      = true
  enable_log_file_validation = true
  enable_logging             = true
}
