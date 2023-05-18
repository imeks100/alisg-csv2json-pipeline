locals {
  data = jsondecode(file("security_group_rules.json"))
}

variable "region" {
  default = "cn-hangzhou"
}
