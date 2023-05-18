locals {
  data = jsondecode(file("sgrs.json"))
}

variable "region" {
  default = "cn-hangzhou"
}
