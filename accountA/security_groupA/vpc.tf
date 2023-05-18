resource "alicloud_vpc" "vpc" {
  vpc_name    = "hangzhou-vpc"
  cidr_block  = "10.10.0.0/16"
  description = "vpc desc"
}
