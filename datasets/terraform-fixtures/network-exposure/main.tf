# DELIBERATELY INSECURE TEST FIXTURE - do not apply.

resource "aws_vpc" "main" {
  cidr_block = "10.10.0.0/16"
}

resource "aws_security_group" "bastion" {
  name        = "bastion"
  description = "SSH open to the internet"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "windows" {
  name        = "windows"
  description = "RDP open to the IPv6 internet"
  vpc_id      = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "rdp_any" {
  security_group_id = aws_security_group.windows.id
  description       = "RDP from anywhere (IPv6)"
  ip_protocol       = "tcp"
  from_port         = 3389
  to_port           = 3389
  cidr_ipv6         = "::/0"
}

# Public HTTPS is acceptable and must not be flagged.
resource "aws_security_group" "web" {
  name        = "web"
  description = "Public HTTPS"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
