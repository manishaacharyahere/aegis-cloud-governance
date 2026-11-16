# DELIBERATELY INSECURE TEST FIXTURE - do not apply.

resource "aws_iam_role" "ci" {
  name = "ci-deployer"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_policy" "admin_everything" {
  name = "admin-everything"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ci_admin" {
  role       = aws_iam_role.ci.name
  policy_arn = aws_iam_policy.admin_everything.arn
}

# Wildcard action on a scoped resource: broad, but not full admin.
resource "aws_iam_policy" "s3_all_actions" {
  name = "s3-all-actions"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*"]
      Resource = ["arn:aws:s3:::aegis-fixture-exports/*"]
    }]
  })
}
