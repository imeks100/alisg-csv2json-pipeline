resource "alicloud_security_group" "this" {
  name        = "security_group_demo"
  vpc_id      = alicloud_vpc.vpc.id
  description = "securitygroupdesc"
}

resource "alicloud_security_group_rule" "security_group_rules" {
  count = length(local.data.security_group_rules) > 0 ? length(local.data.security_group_rules) : 0

  security_group_id = alicloud_security_group.this.id

  # required parameter from json
  type        = local.data.security_group_rules[count.index].security_rule_type
  ip_protocol = local.data.security_group_rules[count.index].ip_protocol
  nic_type    = local.data.security_group_rules[count.index].nic_type
  policy      = local.data.security_group_rules[count.index].policy
  port_range  = local.data.security_group_rules[count.index].port_range
  priority    = local.data.security_group_rules[count.index].priority

  # cidr or security group id, only use one of them
  cidr_ip                  = length(local.data.security_group_rules[count.index].cidr_ip) > 0 ? local.data.security_group_rules[count.index].cidr_ip : null
  source_security_group_id = length(local.data.security_group_rules[count.index].source_security_group_id) > 0 ? local.data.security_group_rules[count.index].source_security_group_id : null

  description = length(local.data.security_group_rules[count.index].description) > 0 ? local.data.security_group_rules[count.index].description : null
}
