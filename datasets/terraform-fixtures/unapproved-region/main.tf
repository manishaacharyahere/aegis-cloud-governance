# TEST FIXTURE - a resource in a region outside the approved list.

resource "aws_vpc" "shadow" {
  cidr_block = "10.99.0.0/16"
}
