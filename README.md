# alisg-csv2json-pipeline
Convert csv file to json for alibaba cloud security group rule, terraform load data from json file, then apply.

# repository hierarchy
```
├── accountA
│   ├── security_groupA/(terraform files, csv file)
│   └── security_groupA1/(terraform files, csv file)
├── accountB
│   ├── security_groupB/(terraform files, csv file)
│   └── security_groupB1/(terraform files, csv file)
│ ...
```

## csv file format example
```
# 8 fields, index from 0 to 7. separated by commas and use # for comment.
nic_type,security_rule_type,policy,ip_protocol,port_range,priority,authorization_object,description
intranet,ingress,accept,tcp,80/80,1,192.168.1.0/24,http
#intranet,ingress,accept,tcp,22/22,1,sg-abcdefgxxxx,ssh
```
> **note**: If insert a security group rule to csv file, for example line 3, terraform will destroy security group rule from line 3 to the last line, then recreate. Append is better.

## converted json file format example
```
{
  "security_group_rules": [
    {
      "security_rule_type": "ingress",
      "priority": 1,
      "ip_protocol": "tcp",
      "port_range": "80/80",
      "policy": "accept",
      "cidr_ip": "192.168.1.0/24",
      "source_security_group_id": "",
      "description": "http"
    }
  ]
}
```

## terraform example code
```
locals {
  data = jsondecode(file("security_group_rules.json"))
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
  cidr_ip = (length(local.data.security_group_rules[count.index].cidr_ip) > 0
    ? local.data.security_group_rules[count.index].cidr_ip : null)

  source_security_group_id = (length(local.data.security_group_rules[count.index].source_security_group_id) > 0
    ? local.data.security_group_rules[count.index].source_security_group_id : null)

  description = (length(local.data.security_group_rules[count.index].description) > 0 
    ? local.data.security_group_rules[count.index].description : null)
}
```

# build binary
```
cd alisg-csv2json
go mod init alisg-csv2json && go mod tidy
go build
sudo cp alisg-csv2json /usr/local/bin
```
The default csv file is security_group_rules.csv, or use `-rule-file` to specify a csv file. alisg-csv2json convert this csv file to security_group_rules.json

# simple pipeline steps
1. find out the latest added/modified tf/csv file, then output the uniq path to a file
```bash
git log -1 --name-status | grep -E '^[AM]\b.*(tf|csv)$' | awk '{print $NF}' | tee diff_files
for n in `cat diff_files`;do echo ${n%/*}; done | sort | uniq | tee diff_paths
```

2. walk to the modified paths, convert csv to json, then apply
```bash
workdir=$PWD
for p in `cat diff_paths`;do
  cd $p && alisg-csv2json
  terraform init && terraform plan && terraform apply -auto-approve
  cd $workdir
done
```
