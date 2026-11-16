# DELIBERATELY INSECURE TEST FIXTURE - do not apply.

# Public access explicitly allowed.
resource "aws_s3_bucket" "public_assets" {
  bucket = "aegis-fixture-public-assets"
}

resource "aws_s3_bucket_public_access_block" "public_assets" {
  bucket                  = aws_s3_bucket.public_assets.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# No public access block, no encryption, no versioning.
resource "aws_s3_bucket" "exports" {
  bucket = "aegis-fixture-exports"
}

resource "aws_db_instance" "legacy" {
  identifier                  = "legacy"
  engine                      = "mysql"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "legacy_admin"
  manage_master_user_password = true
  storage_encrypted           = false
  publicly_accessible         = true
  skip_final_snapshot         = true
}
